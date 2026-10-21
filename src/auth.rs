use std::{
    collections::HashMap,
    io::Cursor,
    marker::PhantomData,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aes::{cipher::consts::U16, Aes128};
use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
use cloudkit_proto::{
    octagon_pairing_message::{self, Step5},
    CuttlefishPeer, OctagonPairingMessage, OctagonWrapper, SignedInfo,
};
use deku::{DekuContainerWrite, DekuUpdate};
use deku::{DekuRead, DekuWrite};
use hkdf::Hkdf;
use icloud_auth::{AppleAccount, CircleSendMessage, GenerateVerificationTokenRequest, LoginState};
use keystore::{
    KeystoreAccessRules, KeystoreDigest, KeystorePadding, KeystorePublicKey, KeystoreSignKey,
    RsaKey,
};
use log::{debug, info, warn};
use omnisette::{AnisetteClient, AnisetteProvider};
use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
    sha::sha1,
    sign::Signer,
    x509::{X509Name, X509Req},
};
use plist::{Data, Dictionary, Value};
use rand::Rng;
use rasn::{AsnType, Decode, Encode};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method, Request, RequestBuilder, Response, Url,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use srp::{
    client::{SrpClient, SrpClientVerifier},
    groups::G_3072,
    server::SrpServer,
};
use tokio::sync::watch;
use uuid::Uuid;
use x509_cert::{
    attr::AttributeTypeAndValue,
    der::{
        asn1::{BitString, Null, SetOfVec, Utf8StringRef},
        pem::LineEnding,
        EncodePem,
    },
    name::{Name, RdnSequence, RelativeDistinguishedName},
    request::{CertReq, CertReqInfo},
    spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo},
};
use xml::{
    reader::{self, ParserConfig2},
    EventReader,
};

use crate::{
    aps::{get_message, APSInterestToken},
    cloudkit_operation_gate::with_cloudkit_writer_operation,
    ids::user::{IDSUser, IDSUserIdentity, IDSUserType},
    keychain::{EncodedPeer, KeychainClient, PrivateUserIdentity},
    util::{
        base64_decode, base64_encode, decode_hex, duration_since_epoch, encode_hex, get_bag, gzip,
        gzip_normal, plist_to_bin, plist_to_buf, plist_to_string, ungzip, DebugMutex, KeyPair,
        KeyPairNew, PhoneNumberResponse, IDS_BAG, REQWEST,
    },
    APSConnection, APSConnectionResource, APSMessage, APSState, OSConfig, PushError,
};

#[path = "auth_response.rs"]
pub(crate) mod auth_response;
use auth_response::AuthResponse;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthRequest {
    apple_id: String,
    client_id: String,
    delegates: Value,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V2AuthRequest {
    delegates: Value,
    protocol_version: String,
    user_info: V2AuthUserInfo,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct V2AuthUserInfo {
    client_id: String,
    language: String,
    timezone: String,
}

#[derive(Clone, Copy)]
pub enum LoginDelegate {
    IDS,
    MobileMe,
}

impl LoginDelegate {
    fn delegate(&self) -> (&'static str, Value) {
        match self {
            Self::IDS => (
                "com.apple.private.ids",
                Value::Dictionary(Dictionary::from_iter(
                    [("protocol-version", Value::String("4".to_string()))].into_iter(),
                )),
            ),
            Self::MobileMe => ("com.apple.mobileme", Value::Dictionary(Dictionary::new())),
        }
    }
}

struct CloudKitReadAuthenticationGeneration {
    gate: Arc<tokio::sync::RwLock<()>>,
    revoked: AtomicBool,
}

type CloudKitReadAuthenticationInvalidator = Arc<dyn Fn() -> Result<(), PushError> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct CloudKitReadAuthenticationLease {
    mme_auth_token: Arc<str>,
    cloudkit_token: Arc<str>,
    generation: Arc<CloudKitReadAuthenticationGeneration>,
}

impl CloudKitReadAuthenticationLease {
    fn new(mme_auth_token: String, cloudkit_token: String) -> Self {
        Self {
            mme_auth_token: mme_auth_token.into(),
            cloudkit_token: cloudkit_token.into(),
            generation: Arc::new(CloudKitReadAuthenticationGeneration {
                gate: Arc::new(tokio::sync::RwLock::new(())),
                revoked: AtomicBool::new(false),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(mme_auth_token: &str, cloudkit_token: &str) -> Self {
        Self::new(mme_auth_token.to_owned(), cloudkit_token.to_owned())
    }

    pub(crate) fn mme_auth_token(&self) -> &str {
        &self.mme_auth_token
    }

    pub(crate) fn cloudkit_token(&self) -> &str {
        &self.cloudkit_token
    }

    fn is_revoked(&self) -> bool {
        self.generation.revoked.load(Ordering::Acquire)
    }

    pub(crate) async fn admit(&self) -> Result<CloudKitReadAuthenticationAdmission, PushError> {
        let guard = self.generation.gate.clone().read_owned().await;
        if self.generation.revoked.load(Ordering::Acquire) {
            drop(guard);
            return Err(PushError::CloudKitWarmAuthenticationRequired);
        }
        Ok(CloudKitReadAuthenticationAdmission { _guard: guard })
    }

    pub(crate) fn revoker(&self) -> CloudKitReadAuthenticationRevoker {
        CloudKitReadAuthenticationRevoker {
            generation: self.generation.clone(),
        }
    }
}

pub(crate) struct CloudKitReadAuthenticationAdmission {
    _guard: tokio::sync::OwnedRwLockReadGuard<()>,
}

#[derive(Clone)]
pub struct CloudKitReadAuthenticationRevoker {
    generation: Arc<CloudKitReadAuthenticationGeneration>,
}

impl CloudKitReadAuthenticationRevoker {
    fn matches(&self, lease: &CloudKitReadAuthenticationLease) -> bool {
        Arc::ptr_eq(&self.generation, &lease.generation)
    }

    pub fn is_same_generation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.generation, &other.generation)
    }

    pub async fn revoke(&self) {
        let _guard = self.generation.gate.clone().write_owned().await;
        self.generation.revoked.store(true, Ordering::Release);
    }
}

struct CloudKitReadAuthenticationCache {
    lease: CloudKitReadAuthenticationLease,
    refreshed: SystemTime,
    invalidator: CloudKitReadAuthenticationInvalidator,
}

pub struct TokenProvider<T: AnisetteProvider> {
    account: Arc<DebugMutex<AppleAccount<T>>>,
    mme_delegate: DebugMutex<Option<MobileMeDelegateResponse>>,
    mme_refreshed: DebugMutex<SystemTime>,
    cloudkit_read_authentication: DebugMutex<Option<CloudKitReadAuthenticationCache>>,
    cloudkit_read_authentication_mutation: DebugMutex<()>,
    os_config: Arc<dyn OSConfig>,
}

const MME_DELEGATE_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 7);

fn mme_delegate_is_warm(delegate_present: bool, refreshed: SystemTime, now: SystemTime) -> bool {
    delegate_present
        && now
            .duration_since(refreshed)
            .map(|age| age <= MME_DELEGATE_MAX_AGE)
            .unwrap_or(false)
}

fn storage_quota_url(delegate: Option<&MobileMeDelegateResponse>) -> Result<String, PushError> {
    let delegate = delegate.ok_or(PushError::TokenMissing)?;
    let url = delegate
        .config
        .get("com.apple.Dataclass.Quota")
        .and_then(|value| value.as_dictionary())
        .and_then(|quota| quota.get("storageInfoURL"))
        .and_then(|value| value.as_string())
        .filter(|url| !url.trim().is_empty())
        .ok_or(PushError::BagKeyNotFound)?;
    Ok(url.trim().to_string())
}

fn storage_account_identifiers(spd: Option<&Dictionary>) -> Result<(String, String), PushError> {
    let spd = spd.ok_or(PushError::TokenMissing)?;
    let dsid = spd
        .get("DsPrsId")
        .and_then(|value| {
            value.as_unsigned_integer().or_else(|| {
                value
                    .as_signed_integer()
                    .and_then(|value| u64::try_from(value).ok())
            })
        })
        .filter(|value| *value != 0)
        .ok_or(PushError::BagKeyNotFound)?;
    let adsid = spd
        .get("adsid")
        .and_then(|value| value.as_string())
        .filter(|value| !value.trim().is_empty())
        .ok_or(PushError::BagKeyNotFound)?;
    Ok((dsid.to_string(), adsid.trim().to_owned()))
}

fn storage_anisette_headers(headers: &HashMap<String, String>) -> Result<HeaderMap, PushError> {
    headers
        .iter()
        .map(|(name, value)| {
            let name = HeaderName::from_str(name.as_str()).map_err(|_| {
                PushError::KeyedArchiveError("invalid anisette header name".to_string())
            })?;
            let value: HeaderValue = value.parse().map_err(|_| {
                PushError::KeyedArchiveError("invalid anisette header value".to_string())
            })?;
            Ok((name, value))
        })
        .collect()
}

#[derive(Deserialize, Debug)]
pub struct StorageInfoBytes {
    pub total_storage: u64,
    pub used_storage: u64,
    pub commerce_storage_in_bytes: u64,
}

#[derive(Deserialize, Debug)]
pub struct QuotaInfoBytes {
    pub total_quota: u64,
    pub total_used: u64,
    pub total_available: u64,
}

#[derive(Deserialize, Debug)]
pub struct StorageData {
    pub storage_info_in_bytes: StorageInfoBytes,
    pub quota_info_in_bytes: QuotaInfoBytes,
}

#[derive(Deserialize, Debug)]
pub struct StorageUsageByMedia {
    #[serde(default)]
    pub display_label: String,
    #[serde(default)]
    pub display_color: String,
    pub usage_in_bytes: u64,
    pub media_key: String,
    #[serde(default)]
    pub display_color_dark: String,
    #[serde(default)]
    pub text_color: String,
    #[serde(default)]
    pub text_color_dark: String,
}

#[derive(Deserialize, Debug)]
pub struct QuotaData {
    pub storage_data: StorageData,
    pub storage_usage_by_media: Vec<StorageUsageByMedia>,
}

impl<T: AnisetteProvider> TokenProvider<T> {
    pub fn new(
        account: Arc<DebugMutex<AppleAccount<T>>>,
        os_config: Arc<dyn OSConfig>,
    ) -> Arc<Self> {
        Arc::new(Self {
            account,
            os_config,
            mme_delegate: DebugMutex::new(None),
            mme_refreshed: DebugMutex::new(SystemTime::UNIX_EPOCH),
            cloudkit_read_authentication: DebugMutex::new(None),
            cloudkit_read_authentication_mutation: DebugMutex::new(()),
        })
    }

    /// Restores only the two bearer tokens required by the admitted semantic
    /// CloudKit read path. The cache is deliberately separate from the live
    /// MobileMe delegate used by refreshable and write-capable operations.
    pub async fn restore_cloudkit_read_authentication<F>(
        &self,
        mme_auth_token: String,
        cloudkit_token: String,
        refreshed: SystemTime,
        invalidator: F,
    ) -> Option<CloudKitReadAuthenticationRevoker>
    where
        F: Fn() -> Result<(), PushError> + Send + Sync + 'static,
    {
        if mme_auth_token.is_empty()
            || cloudkit_token.is_empty()
            || !mme_delegate_is_warm(true, refreshed, SystemTime::now())
        {
            return None;
        }

        let _mutation = self.cloudkit_read_authentication_mutation.lock().await;
        let existing = {
            let mut cache = self.cloudkit_read_authentication.lock().await;
            if let Some(existing) = cache.as_ref() {
                if existing.refreshed >= refreshed && !existing.lease.is_revoked() {
                    return Some(existing.lease.revoker());
                }
            }
            cache.take()
        };
        if let Some(existing) = existing {
            existing.lease.revoker().revoke().await;
        }
        let lease = CloudKitReadAuthenticationLease::new(mme_auth_token, cloudkit_token);
        let revoker = lease.revoker();
        *self.cloudkit_read_authentication.lock().await = Some(CloudKitReadAuthenticationCache {
            lease,
            refreshed,
            invalidator: Arc::new(invalidator),
        });
        Some(revoker)
    }

    pub async fn invalidate_cloudkit_read_authentication(&self) -> Result<bool, PushError> {
        let _mutation = self.cloudkit_read_authentication_mutation.lock().await;
        let cached = self.cloudkit_read_authentication.lock().await.take();
        if let Some(cached) = cached {
            cached.lease.revoker().revoke().await;
            (cached.invalidator)()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Invalidates only the exact generation that authenticated a failed
    /// request. The request's read admission must be dropped before calling
    /// this method so revocation can wait for every admitted use to finish.
    pub(crate) async fn invalidate_cloudkit_read_authentication_generation(
        &self,
        failed_generation: &CloudKitReadAuthenticationRevoker,
    ) -> Result<bool, PushError> {
        let _mutation = self.cloudkit_read_authentication_mutation.lock().await;
        let cached = {
            let mut cache = self.cloudkit_read_authentication.lock().await;
            if !cache
                .as_ref()
                .is_some_and(|cached| failed_generation.matches(&cached.lease))
            {
                return Ok(false);
            }
            cache.take().expect("matched CloudKit read authentication")
        };
        cached.lease.revoker().revoke().await;
        (cached.invalidator)()?;
        Ok(true)
    }

    pub async fn get_storage_info(&self) -> Result<QuotaData, PushError> {
        let token = self.get_mme_token("mmeAuthToken").await?;

        let quota_url = {
            let delegate = self.mme_delegate.lock().await;
            storage_quota_url(delegate.as_ref())?
        };

        let (dsid, adsid, anisette) = {
            let account = self.account.lock().await;
            let (dsid, adsid) = storage_account_identifiers(account.spd.as_ref())?;
            (dsid, adsid, account.anisette.clone())
        };

        let anisette_headers = {
            let headers = anisette.lock().await.get_headers().await?.clone();
            storage_anisette_headers(&headers)?
        };

        let data = REQWEST
            .get(quota_url)
            .basic_auth(&format!("{}", dsid), Some(token))
            .header("X-Client-UDID", self.os_config.get_udid().to_lowercase())
            .header("X-MMe-Country", "US")
            .header(
                "X-MMe-Client-Info",
                self.os_config.get_mme_clientinfo(
                    "com.apple.AppleAccount/1.0 (com.apple.Preferences/1112.96)",
                ),
            )
            .header("X-MMe-Language", "en")
            .header("X-Apple-ADSID", adsid)
            .headers(anisette_headers)
            .send()
            .await?
            .bytes()
            .await?;

        Ok(plist::from_bytes(&data)?)
    }

    pub async fn generate_verification_token(
        &self,
        request: GenerateVerificationTokenRequest,
    ) -> Result<String, PushError> {
        Ok(self
            .account
            .lock()
            .await
            .generate_verification_token(request)
            .await?)
    }

    pub async fn get_gsa_token(&self, token: &str) -> Option<String> {
        self.account.lock().await.get_token(token).await
    }

    pub async fn get_gsa_email(&self) -> Option<String> {
        self.account.lock().await.username.clone()
    }

    /// Returns the account identifiers already present in the authenticated
    /// AppleAccount SPD. This is deliberately a cached-only accessor: it only
    /// takes the account lock and never refreshes authentication, generates
    /// Anisette data, or performs network I/O.
    ///
    /// The identifiers are native-boundary data and must not be logged or
    /// exposed through FFI. Malformed or incomplete SPD data fails closed.
    pub(crate) async fn get_gsa_account_identifiers_cached(
        &self,
    ) -> Result<(String, String), PushError> {
        let account = self.account.lock().await;
        let Some(spd) = account.spd.as_ref() else {
            return Err(PushError::UnauthorizedAccountError);
        };

        let Some(dsid) = spd
            .get("DsPrsId")
            .and_then(Value::as_unsigned_integer)
            .filter(|value| *value != 0)
        else {
            return Err(PushError::UnauthorizedAccountError);
        };

        let Some(adsid) = spd
            .get("adsid")
            .and_then(Value::as_string)
            .filter(|value| !value.trim().is_empty())
        else {
            return Err(PushError::UnauthorizedAccountError);
        };

        Ok((dsid.to_string(), adsid.to_owned()))
    }

    pub async fn refresh_mme(&self) -> Result<(), PushError> {
        let mut mme = self.mme_delegate.lock().await;

        self.get_gsa_token("com.apple.gs.idms.pet")
            .await
            .ok_or(PushError::TokenMissing)?;
        let delegates = login_apple_delegates(
            &mut *self.account.lock().await,
            None,
            &*self.os_config,
            &[LoginDelegate::MobileMe],
        )
        .await?;

        *mme = delegates.mobileme;
        *self.mme_refreshed.lock().await = SystemTime::now();

        Ok(())
    }

    /// Refreshes MobileMe explicitly and returns only the two tokens required
    /// to seed the isolated CloudKit semantic-read authentication cache.
    ///
    /// This method performs authentication network I/O, but it does not open a
    /// CloudKit container or issue record, zone, subscription, save, or delete
    /// operations. Callers must persist and install the returned material under
    /// their account-lifecycle lock before admitting semantic reads.
    pub async fn refresh_cloudkit_read_authentication_material(
        &self,
    ) -> Result<(String, String, SystemTime), PushError> {
        self.refresh_mme().await?;
        let delegate = self.mme_delegate.lock().await;
        let refreshed = *self.mme_refreshed.lock().await;
        cloudkit_read_authentication_material(delegate.as_ref(), refreshed, SystemTime::now())
    }

    pub async fn get_mme_token(&self, token: &str) -> Result<String, PushError> {
        // refresh every week
        if !mme_delegate_is_warm(
            self.mme_delegate.lock().await.is_some(),
            *self.mme_refreshed.lock().await,
            SystemTime::now(),
        ) {
            self.refresh_mme().await?;
        }
        self.mme_delegate
            .lock()
            .await
            .as_ref()
            .expect("no MME?")
            .tokens
            .get(token)
            .ok_or(PushError::TokenMissing)
            .cloned()
    }

    /// Returns a token only when explicit prior authentication left a current
    /// MobileMe delegate in memory. This accessor never logs in or refreshes.
    pub async fn get_mme_token_cached(&self, token: &str) -> Result<String, PushError> {
        let delegate = self.mme_delegate.lock().await;
        if !mme_delegate_is_warm(
            delegate.is_some(),
            *self.mme_refreshed.lock().await,
            SystemTime::now(),
        ) {
            return Err(PushError::CloudKitWarmAuthenticationRequired);
        }
        delegate
            .as_ref()
            .and_then(|delegate| delegate.tokens.get(token))
            .cloned()
            .ok_or(PushError::CloudKitWarmAuthenticationRequired)
    }

    /// Returns an already-authenticated token only for the admitted semantic
    /// CloudKit read path. It never logs in, refreshes MobileMe, or exposes the
    /// restored cache through the general token accessor.
    pub async fn cloudkit_read_authentication_is_warm(&self) -> bool {
        self.cloudkit_read_authentication_lease().await.is_ok()
    }

    pub(crate) async fn cloudkit_read_authentication_lease(
        &self,
    ) -> Result<CloudKitReadAuthenticationLease, PushError> {
        {
            let cache = self.cloudkit_read_authentication.lock().await;
            let refreshed = cache
                .as_ref()
                .map_or(SystemTime::UNIX_EPOCH, |cache| cache.refreshed);
            if mme_delegate_is_warm(cache.is_some(), refreshed, SystemTime::now())
                && cache
                    .as_ref()
                    .is_some_and(|cache| !cache.lease.is_revoked())
            {
                return Ok(cache.as_ref().expect("validated cache").lease.clone());
            }
        }

        let _mutation = self.cloudkit_read_authentication_mutation.lock().await;
        let stale = {
            let mut cache = self.cloudkit_read_authentication.lock().await;
            let refreshed = cache
                .as_ref()
                .map_or(SystemTime::UNIX_EPOCH, |cache| cache.refreshed);
            if mme_delegate_is_warm(cache.is_some(), refreshed, SystemTime::now())
                && cache
                    .as_ref()
                    .is_some_and(|cache| !cache.lease.is_revoked())
            {
                return Ok(cache.as_ref().expect("validated cache").lease.clone());
            }
            cache.take()
        };
        if let Some(stale) = stale {
            stale.lease.revoker().revoke().await;
            (stale.invalidator)()?;
        }
        Err(PushError::CloudKitWarmAuthenticationRequired)
    }
}

fn cloudkit_read_authentication_material(
    delegate: Option<&MobileMeDelegateResponse>,
    refreshed: SystemTime,
    now: SystemTime,
) -> Result<(String, String, SystemTime), PushError> {
    if !mme_delegate_is_warm(delegate.is_some(), refreshed, now) {
        return Err(PushError::CloudKitWarmAuthenticationRequired);
    }
    let delegate = delegate.ok_or(PushError::CloudKitWarmAuthenticationRequired)?;
    let mme_auth_token = delegate
        .tokens
        .get("mmeAuthToken")
        .filter(|token| !token.is_empty())
        .cloned()
        .ok_or(PushError::CloudKitWarmAuthenticationRequired)?;
    let cloudkit_token = delegate
        .tokens
        .get("cloudKitToken")
        .filter(|token| !token.is_empty())
        .cloned()
        .ok_or(PushError::CloudKitWarmAuthenticationRequired)?;
    Ok((mme_auth_token, cloudkit_token, refreshed))
}

#[cfg(test)]
mod token_provider_tests {
    use super::{
        cloudkit_read_authentication_material, mme_delegate_is_warm, storage_account_identifiers,
        storage_anisette_headers, storage_quota_url, CloudKitReadAuthenticationLease,
        MobileMeDelegateResponse, PushError, MME_DELEGATE_MAX_AGE,
    };
    use plist::{Dictionary, Value};
    use std::{
        collections::HashMap,
        time::{Duration, SystemTime},
    };

    #[test]
    fn semantic_auth_preflight_requires_a_current_existing_delegate() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        assert!(!mme_delegate_is_warm(false, now, now));
        assert!(mme_delegate_is_warm(true, now - MME_DELEGATE_MAX_AGE, now));
        assert!(!mme_delegate_is_warm(
            true,
            now - MME_DELEGATE_MAX_AGE - Duration::from_secs(1),
            now
        ));
        assert!(!mme_delegate_is_warm(
            true,
            now + Duration::from_secs(1),
            now
        ));
    }

    #[tokio::test]
    async fn read_authentication_revocation_waits_for_active_request_and_blocks_future_use() {
        let lease = CloudKitReadAuthenticationLease::new_for_test("mme-token", "cloudkit-token");
        let admission = lease.admit().await.expect("initial admission");
        let revoker = lease.revoker();
        let mut revoke = tokio::spawn(async move {
            revoker.revoke().await;
        });

        assert!(tokio::time::timeout(Duration::from_millis(20), &mut revoke)
            .await
            .is_err());
        drop(admission);
        tokio::time::timeout(Duration::from_secs(1), revoke)
            .await
            .expect("revocation should finish after the active request exits")
            .expect("revocation task");
        assert!(matches!(
            lease.admit().await,
            Err(PushError::CloudKitWarmAuthenticationRequired)
        ));
    }

    #[test]
    fn revokers_identify_only_their_exact_authentication_generation() {
        let first = CloudKitReadAuthenticationLease::new_for_test("mme-one", "cloudkit-one");
        let second = CloudKitReadAuthenticationLease::new_for_test("mme-two", "cloudkit-two");

        assert!(first.revoker().is_same_generation(&first.revoker()));
        assert!(!first.revoker().is_same_generation(&second.revoker()));
    }

    #[test]
    fn refreshed_semantic_material_requires_both_current_nonempty_tokens() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let mut tokens = HashMap::from([
            ("mmeAuthToken".to_owned(), "mme-token".to_owned()),
            ("cloudKitToken".to_owned(), "cloudkit-token".to_owned()),
        ]);
        let delegate = MobileMeDelegateResponse {
            tokens: tokens.clone(),
            config: Default::default(),
        };
        let material = cloudkit_read_authentication_material(Some(&delegate), now, now)
            .expect("current complete delegate");
        assert_eq!(material.0, "mme-token");
        assert_eq!(material.1, "cloudkit-token");
        assert_eq!(material.2, now);

        tokens.remove("cloudKitToken");
        let incomplete = MobileMeDelegateResponse {
            tokens,
            config: Default::default(),
        };
        assert!(matches!(
            cloudkit_read_authentication_material(Some(&incomplete), now, now),
            Err(PushError::CloudKitWarmAuthenticationRequired)
        ));
        assert!(matches!(
            cloudkit_read_authentication_material(
                Some(&delegate),
                now - MME_DELEGATE_MAX_AGE - Duration::from_secs(1),
                now,
            ),
            Err(PushError::CloudKitWarmAuthenticationRequired)
        ));
    }

    fn quota_delegate_with_url(url: Option<Value>) -> MobileMeDelegateResponse {
        let mut quota = Dictionary::new();
        if let Some(url) = url {
            quota.insert("storageInfoURL".to_string(), url);
        }
        let mut config = Dictionary::new();
        config.insert(
            "com.apple.Dataclass.Quota".to_string(),
            Value::Dictionary(quota),
        );
        MobileMeDelegateResponse {
            tokens: HashMap::new(),
            config,
        }
    }

    #[test]
    fn storage_quota_url_accepts_only_a_nonempty_string_url() {
        assert!(matches!(
            storage_quota_url(None),
            Err(PushError::TokenMissing)
        ));
        assert!(matches!(
            storage_quota_url(Some(&MobileMeDelegateResponse {
                tokens: HashMap::new(),
                config: Dictionary::new(),
            })),
            Err(PushError::BagKeyNotFound)
        ));
        assert!(matches!(
            storage_quota_url(Some(&quota_delegate_with_url(None))),
            Err(PushError::BagKeyNotFound)
        ));
        assert!(matches!(
            storage_quota_url(Some(&quota_delegate_with_url(Some(Value::from(123u64))))),
            Err(PushError::BagKeyNotFound)
        ));
        assert!(matches!(
            storage_quota_url(Some(&quota_delegate_with_url(Some(Value::String(
                "   ".to_string()
            ))))),
            Err(PushError::BagKeyNotFound)
        ));
        let delegate =
            quota_delegate_with_url(Some(Value::String("https://example.com/quota".to_string())));
        assert_eq!(
            storage_quota_url(Some(&delegate)).expect("valid quota url"),
            "https://example.com/quota"
        );
        let padded = quota_delegate_with_url(Some(Value::String(
            "  https://example.com/quota  ".to_string(),
        )));
        assert_eq!(
            storage_quota_url(Some(&padded)).expect("trimmed quota url"),
            "https://example.com/quota"
        );
    }

    #[test]
    fn storage_account_identifiers_rejects_missing_or_malformed_spd() {
        assert!(matches!(
            storage_account_identifiers(None),
            Err(PushError::TokenMissing)
        ));
        let empty = Dictionary::new();
        assert!(matches!(
            storage_account_identifiers(Some(&empty)),
            Err(PushError::BagKeyNotFound)
        ));
        let zero_dsid = Dictionary::from_iter(
            [
                ("DsPrsId".to_string(), Value::from(0u64)),
                ("adsid".to_string(), Value::String("a".to_string())),
            ]
            .into_iter(),
        );
        assert!(matches!(
            storage_account_identifiers(Some(&zero_dsid)),
            Err(PushError::BagKeyNotFound)
        ));
        let wrong_dsid_type = Dictionary::from_iter(
            [
                ("DsPrsId".to_string(), Value::String("123".to_string())),
                ("adsid".to_string(), Value::String("a".to_string())),
            ]
            .into_iter(),
        );
        assert!(matches!(
            storage_account_identifiers(Some(&wrong_dsid_type)),
            Err(PushError::BagKeyNotFound)
        ));
        let blank_adsid = Dictionary::from_iter(
            [
                ("DsPrsId".to_string(), Value::from(12345u64)),
                ("adsid".to_string(), Value::String("   ".to_string())),
            ]
            .into_iter(),
        );
        assert!(matches!(
            storage_account_identifiers(Some(&blank_adsid)),
            Err(PushError::BagKeyNotFound)
        ));
        let signed_dsid = Dictionary::from_iter(
            [
                ("DsPrsId".to_string(), Value::Integer(12345i64.into())),
                ("adsid".to_string(), Value::String(" abc ".to_string())),
            ]
            .into_iter(),
        );
        assert_eq!(
            storage_account_identifiers(Some(&signed_dsid)).expect("signed positive dsid"),
            ("12345".to_string(), "abc".to_string())
        );
        let valid = Dictionary::from_iter(
            [
                ("DsPrsId".to_string(), Value::from(12345u64)),
                ("adsid".to_string(), Value::String("abc".to_string())),
            ]
            .into_iter(),
        );
        assert_eq!(
            storage_account_identifiers(Some(&valid)).expect("valid identifiers"),
            ("12345".to_string(), "abc".to_string())
        );
    }

    #[test]
    fn storage_anisette_headers_rejects_invalid_names_and_values() {
        let valid = HashMap::from([("X-Apple-Test".to_string(), "ok".to_string())]);
        let headers = storage_anisette_headers(&valid).expect("valid headers");
        assert_eq!(
            headers
                .get("X-Apple-Test")
                .expect("header present")
                .to_str()
                .expect("header value is visible ASCII"),
            "ok"
        );
        let bad_name = HashMap::from([("not a valid header name".to_string(), "ok".to_string())]);
        assert!(matches!(
            storage_anisette_headers(&bad_name),
            Err(PushError::KeyedArchiveError(_))
        ));
        let bad_value = HashMap::from([("X-Apple-Test".to_string(), "bad\nvalue".to_string())]);
        assert!(matches!(
            storage_anisette_headers(&bad_value),
            Err(PushError::KeyedArchiveError(_))
        ));

        let bad_name_error = storage_anisette_headers(&bad_name)
            .expect_err("invalid header name must fail")
            .to_string();
        assert!(!bad_name_error.contains("not a valid header name"));
        let bad_value_error = storage_anisette_headers(&bad_value)
            .expect_err("invalid header value must fail")
            .to_string();
        assert!(!bad_value_error.contains("bad"));
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct IDSDelegateResponse {
    pub auth_token: String,
    pub profile_id: String,
}

#[derive(Deserialize)]
pub struct MobileMeDelegateResponse {
    pub tokens: HashMap<String, String>,
    #[serde(default)]
    pub config: Dictionary,
}

pub struct DelegateResponses {
    pub ids: Option<IDSDelegateResponse>,
    pub mobileme: Option<MobileMeDelegateResponse>,
}

pub enum UpdateAccountFinish {
    MacOS,
    IOS { url: String },
}

impl UpdateAccountFinish {
    pub async fn accept_terms<T: AnisetteProvider>(
        &self,
        delegates: &[LoginDelegate],
        account: &AppleAccount<T>,
        os_config: &dyn OSConfig,
    ) -> Result<DelegateResponses, PushError> {
        match self {
            Self::MacOS => {
                login_apple_delegates(account, Some("termsAccepted=true"), os_config, delegates)
                    .await
            }
            Self::IOS { url } => {
                let header_map = build_setup_headers(account, os_config).await?;

                let text = REQWEST
                    .post(url)
                    .header("Accept", "*/*")
                    .header("Accept-Encoding", "gzip, deflate, br")
                    .header("Accept-Language", "en-US,en")
                    .header("Content-Type", "application/xml")
                    .headers(header_map)
                    .send()
                    .await?;

                if !text.status().is_success() {
                    return Err(PushError::FailedToAcceptTOS(text.text().await?));
                }

                text.bytes().await?;

                login_apple_delegates(account, None, os_config, delegates).await
            }
        }
    }
}

async fn build_setup_headers<T: AnisetteProvider>(
    account: &AppleAccount<T>,
    os_config: &dyn OSConfig,
) -> Result<HeaderMap, PushError> {
    let mut map = HashMap::new();
    let base_headers = account.anisette.lock().await.get_headers().await?.clone();
    map.extend(base_headers);

    map.extend(
        [
            (
                "Authorization",
                format!(
                    "Basic {}",
                    base64::encode(format!(
                        "{}:{}",
                        account.username.as_ref().unwrap().trim(),
                        account.get_pet().expect("No pet b?")
                    ))
                ),
            ),
            (
                "User-Agent",
                format!(
                    "iOS iPhone {} iPhone Setup Assistant",
                    os_config.get_register_meta().software_version
                ),
            ),
            ("Cookie", "repairSteps=".to_string()),
            ("X-MMe-Country", "US".to_string()),
            ("X-MMe-Language", "en,en-US".to_string()),
            (
                "X-MMe-Client-Info",
                os_config.get_mme_clientinfo(
                    "com.apple.AppleAccount/1.0 (com.apple.Preferences/1112.96)",
                ),
            ),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b)),
    );

    Ok(HeaderMap::from_iter(map.into_iter().map(|(a, b)| {
        (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())
    })))
}

pub async fn request_update_account<T: AnisetteProvider>(
    account: &AppleAccount<T>,
    os_config: &dyn OSConfig,
) -> Result<(String, UpdateAccountFinish), PushError> {
    let data = os_config.get_version_ua();
    if data.contains("macOS") {
        let result = account.request_update_account().await?;
        Ok((result, UpdateAccountFinish::MacOS))
    } else {
        let header_map = build_setup_headers(account, os_config).await?;

        #[derive(Serialize)]
        struct RequestedTerms {
            name: &'static str,
        }

        #[derive(Serialize)]
        struct TermsUIRequest {
            format: &'static str,
            terms: Vec<RequestedTerms>,
        }

        let buffer = plist_to_string(&TermsUIRequest {
            format: "plist/buddyml",
            terms: vec![RequestedTerms { name: "iCloud" }],
        })?;

        let text = REQWEST
            .post("https://setup.icloud.com/setup/iosbuddy/ui/genericTermsUI")
            .header("Accept", "application/x-buddyml")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Accept-Language", "en-US,en")
            .header("Content-Type", "text/plist")
            .header("X-Apple-I-Appearance", "1")
            .headers(header_map)
            .body(buffer)
            .send()
            .await?
            .bytes()
            .await?;

        let reader: EventReader<Cursor<_>> = EventReader::new_with_config(
            Cursor::new(&text),
            ParserConfig2::new().cdata_to_characters(true),
        );
        let mut agree_url: Option<String> = None;
        let mut current_page: Option<String> = None;
        let mut current_page_html: Option<String> = None;

        let mut pages: HashMap<String, String> = HashMap::new();

        for e in reader {
            match e {
                Ok(reader::XmlEvent::StartElement {
                    name,
                    attributes,
                    namespace: _,
                }) => {
                    let get_attr = |name: &str, def: Option<&str>| {
                        attributes
                            .iter()
                            .find(|attr| attr.name.to_string() == name)
                            .map_or_else(
                                || {
                                    def.expect(&format!("attribute {} doesn't exist!", name))
                                        .to_string()
                                },
                                |data| data.value.to_string(),
                            )
                    };
                    match name.local_name.as_str() {
                        "clientInfo" => {
                            agree_url = Some(get_attr("agreeUrl", None));
                        }
                        "page" => current_page = Some(get_attr("id", Some("default"))),
                        "html" => {
                            current_page_html = current_page.clone();
                        }
                        _ => {}
                    }
                }
                Ok(reader::XmlEvent::EndElement { name }) => match name.local_name.as_str() {
                    "page" => {
                        current_page = None;
                    }
                    "html" => {
                        current_page_html = None;
                    }
                    _ => {}
                },
                Ok(reader::XmlEvent::Characters(data)) => {
                    if let Some(page) = &current_page_html {
                        pages.entry(page.clone()).or_default().push_str(&data);
                    }
                }
                _ => {}
            }
        }

        Ok((
            pages.remove("iCloud").unwrap_or_default(),
            UpdateAccountFinish::IOS {
                url: agree_url.expect("No agree url???"),
            },
        ))
    }
}

pub async fn login_apple_delegates<T: AnisetteProvider>(
    account: &AppleAccount<T>,
    cookie: Option<&str>,
    os_config: &dyn OSConfig,
    delegates: &[LoginDelegate],
) -> Result<DelegateResponses, PushError> {
    let started = Instant::now();
    let Some(pet) = account.get_pet() else {
        panic!("No pet!")
    };
    let Some(spd) = &account.spd else {
        panic!("No spd!")
    };

    debug!(
        "Parsed SPD metadata (keys={}, has_adsid={})",
        spd.len(),
        spd.contains_key("adsid")
    );
    let adsid = spd.get("adsid").expect("No adsid!").as_string().unwrap();

    let username = account.username.as_ref().unwrap();

    // let request = AuthRequest {
    //     apple_id: username.to_string(),
    //     client_id: Uuid::new_v4().to_string(),
    //     delegates: Value::Dictionary(Dictionary::from_iter(delegates.iter().map(|d| d.delegate()))),
    //     password: pet.to_string()
    // };

    let mut request = V2AuthRequest {
        delegates: Value::Dictionary(Dictionary::from_iter(
            delegates.iter().map(|d| d.delegate()),
        )),
        protocol_version: "1.0".to_string(),
        user_info: V2AuthUserInfo {
            client_id: Uuid::new_v4().to_string().to_uppercase(),
            language: "en-US".to_string(),
            timezone: "America/New_York".to_string(),
        },
    };

    // Account signing is separate from IDS/device NAC. Generate the account
    // qualifier first so the fresh authentication headers do not age while it runs.
    let validation_data = account_delegate_validation(&account.anisette, os_config.generate_validation_data()).await?;

    // Request fresh proof for this service-authorization exchange, keeping the
    // same provider and identity used by password authentication.
    let (base_headers, provider_client_info, provider_client_id, omit_validation) = {
        let mut anisette = account.anisette.lock().await;
        let headers = anisette.get_fresh_headers().await?.clone();
        let context = anisette.provider.delegate_client_info(&os_config.get_aoskit_version());
        let client_id = anisette.provider.delegate_client_id();
        let omit_validation = anisette.provider.omit_delegate_validation();
        (headers, context, client_id, omit_validation)
    };
    apply_delegate_client_id(&mut request, provider_client_id);
    let body = plist_to_string(&request)?;
    let client_info = delegate_client_info(
        provider_client_info, os_config.get_mme_clientinfo(&os_config.get_aoskit_version()));
    let mut anisette_headers = delegate_anisette_headers(base_headers);

    if let Some(cookie) = cookie {
        anisette_headers.insert("Cookie", HeaderValue::from_str(cookie).unwrap());
    }

    // Fixed metadata only. Never log credentials, headers, identity, or body.
    info!(target: "rustpush::auth::delegate_diagnostic",
        "delegate_request pet_remaining_s={} validation_bytes={} preparation_ms={}",
        account.pet_remaining_lifetime().map(|value| value.as_secs()).unwrap_or(0),
        validation_data.len(), started.elapsed().as_millis());

    let mut request_builder = REQWEST
        .post(os_config.get_login_url())
        .header("Accept-Encoding", "gzip")
        .header(
            "User-Agent",
            os_config.get_normal_ua("com.apple.iCloudHelper/282"),
        )
        .header(
            "X-Mme-Client-Info",
            client_info,
        );
    if !omit_validation {
        request_builder = request_builder
            .header("X-Mme-Nas-Qualify", base64_encode(&validation_data));
    }
    let request_builder = request_builder
        .header("X-Apple-ADSID", adsid)
        .headers(anisette_headers.clone())
        .basic_auth(username, Some(pet));
    let resp = delegate_serialized_plist_body(request_builder, body)
        .send()
        .await?;
    info!(target: "rustpush::auth::delegate_diagnostic",
        "delegate_response status={} origin={} elapsed_ms={}",
        resp.status().as_u16(), delegate_response_origin(resp.url()), started.elapsed().as_millis());
    let response = AuthResponse::read("icloud-delegates", resp).await?;
    parse_apple_delegates(&response)
}

async fn account_delegate_validation<T: AnisetteProvider>(
    anisette: &omnisette::ArcAnisetteClient<T>,
    legacy_nac: impl std::future::Future<Output = Result<Vec<u8>, PushError>>,
) -> Result<Vec<u8>, PushError> {
    let native = anisette.lock().await.provider.native_account_validation_data().await?;
    match native {
        Some(proof) if !proof.is_empty() && proof.len() <= 4096 => Ok(proof),
        Some(_) => Err(omnisette::AnisetteError::NativeRelayUnavailable("invalid-account-qualifier").into()),
        None => legacy_nac.await,
    }
}

fn delegate_client_info(provider: Option<String>, activation: String) -> String {
    provider.unwrap_or(activation)
}

fn apply_delegate_client_id(request: &mut V2AuthRequest, provider: Option<String>) {
    if let Some(client_id) = provider {
        request.user_info.client_id = client_id;
    }
}

#[cfg(test)]
fn delegate_plist_body(builder: RequestBuilder, request: &V2AuthRequest) -> Result<RequestBuilder, PushError> {
    Ok(delegate_serialized_plist_body(builder, plist_to_string(request)?))
}

fn delegate_serialized_plist_body(builder: RequestBuilder, body: String) -> RequestBuilder {
    builder
        .header("Content-Type", "text/plist")
        .header("Accept", "application/x-plist")
        .body(body)
}

fn delegate_anisette_headers(base_headers: HashMap<String, String>) -> HeaderMap {
    base_headers.into_iter()
        // The service owns its AOSKit context. Generic AuthKit/ADI metadata must
        // not replace it when reqwest merges headers; retain every proof field.
        .filter(|(name, _)| !name.eq_ignore_ascii_case("X-Mme-Client-Info"))
        .map(|(name, value)| (HeaderName::from_str(&name).unwrap(), value.parse().unwrap()))
        .collect()
}

fn delegate_response_origin(url: &reqwest::Url) -> &'static str {
    if url.scheme() == "https" && url.host_str() == Some("setup.icloud.com")
        && url.port_or_known_default() == Some(443) {
        "expected"
    } else {
        "changed"
    }
}

#[cfg(test)]
mod delegate_diagnostic_tests {
    use super::*;
    use tokio::sync::Mutex;

    struct NativeValidationProvider { result: u8 }
    impl AnisetteProvider for NativeValidationProvider {
        async fn get_anisette_headers(&mut self) -> Result<HashMap<String,String>,omnisette::AnisetteError> {
            panic!("This selection test must not generate headers or contact a device")
        }
        async fn native_account_validation_data(&mut self) -> Result<Option<Vec<u8>>,omnisette::AnisetteError> {
            match self.result {
                0 => Ok(None), 1 => Ok(Some(vec![7;261])), 2 => Ok(Some(Vec::new())),
                _ => Err(omnisette::AnisetteError::NativeRelayUnavailable("synthetic-failure")),
            }
        }
    }
    #[tokio::test]
    async fn native_account_qualifier_never_polls_nac_fallback() {
        let anisette=Arc::new(Mutex::new(omnisette::AnisetteClient::new(NativeValidationProvider {result:1})));
        let proof=account_delegate_validation(&anisette,async {panic!("NAC must remain separate")}).await.unwrap();
        assert_eq!(proof.len(),261);
    }
    #[tokio::test]
    async fn legacy_provider_keeps_the_original_nac_path() {
        let anisette=Arc::new(Mutex::new(omnisette::AnisetteClient::new(NativeValidationProvider {result:0})));
        assert_eq!(account_delegate_validation(&anisette,async {Ok(vec![9;4])}).await.unwrap(),vec![9;4]);
    }
    #[tokio::test]
    async fn native_failure_or_empty_proof_cannot_fall_back_to_nac() {
        for result in [2,3] {
            let anisette=Arc::new(Mutex::new(omnisette::AnisetteClient::new(NativeValidationProvider {result})));
            assert!(account_delegate_validation(&anisette,async {panic!("Must not change proof source after failure")}).await.is_err());
        }
    }

    #[test]
    fn provider_client_id_changes_only_the_explicit_request_body_field() {
        let mut request = V2AuthRequest {
            delegates: Value::Dictionary(Dictionary::from_iter(
                [LoginDelegate::IDS, LoginDelegate::MobileMe].iter().map(|d| d.delegate()))),
            protocol_version: "1.0".into(),
            user_info: V2AuthUserInfo {
                client_id: "SYNTHETIC-PER-REQUEST".into(),
                language: "en-US".into(), timezone: "America/New_York".into(),
            },
        };
        let original = plist_to_string(&request).unwrap();
        apply_delegate_client_id(&mut request, None);
        assert_eq!(plist_to_string(&request).unwrap(), original);
        let id = "C71605D9-4E49-401A-8B9F-AD8BE80F766C";
        apply_delegate_client_id(&mut request, Some(id.into()));
        let mut expected: Value = plist::from_bytes(original.as_bytes()).unwrap();
        expected.as_dictionary_mut().unwrap().get_mut("userInfo").unwrap()
            .as_dictionary_mut().unwrap().insert("client-id".into(), Value::String(id.into()));
        let actual: Value = plist::from_bytes(plist_to_string(&request).unwrap().as_bytes()).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn explicit_provider_delegate_context_preserves_default_and_proof_headers() {
        assert_eq!(delegate_client_info(None, "synthetic-activation".into()), "synthetic-activation");
        let context = delegate_client_info(Some("synthetic-provider-service".into()), "synthetic-activation".into());
        let base = HashMap::from_iter([
            ("X-Mme-Client-Info".into(), "synthetic-generic-context".into()),
            ("X-Apple-I-MD".into(), "synthetic-proof".into()),
            ("X-Mme-Device-Id".into(), "synthetic-existing-identity".into()),
        ]);
        let request = Client::new().post("https://example.invalid/setup/signin/v2/login")
            .header("X-Mme-Client-Info", context)
            .header("X-Mme-Nas-Qualify", "synthetic-validation")
            .header("X-Apple-ADSID", "synthetic-account")
            .headers(delegate_anisette_headers(base))
            .basic_auth("fixture@example.invalid", Some("synthetic-pet"))
            .build().unwrap();
        assert_eq!(request.headers()["X-Mme-Client-Info"], "synthetic-provider-service");
        assert_eq!(request.headers().get_all("X-Mme-Client-Info").iter().count(), 1);
        assert_eq!(request.headers()["X-Apple-I-MD"], "synthetic-proof");
        assert_eq!(request.headers()["X-Mme-Device-Id"], "synthetic-existing-identity");
        assert_eq!(request.headers()["X-Mme-Nas-Qualify"], "synthetic-validation");
        assert_eq!(request.headers()["X-Apple-ADSID"], "synthetic-account");
        assert!(request.headers().contains_key("Authorization"));
    }

    #[test]
    fn delegate_request_declares_plist_without_changing_auth_or_payload() {
        let payload = V2AuthRequest {
            delegates: Value::Dictionary(Dictionary::from_iter(
                [LoginDelegate::IDS, LoginDelegate::MobileMe].iter().map(|d| d.delegate()))),
            protocol_version: "1.0".into(),
            user_info: V2AuthUserInfo {
                client_id: "SYNTHETIC-CLIENT".into(),
                language: "en-US".into(),
                timezone: "America/New_York".into(),
            },
        };
        let request = delegate_plist_body(Client::new()
            .post("https://example.invalid/setup/signin/v2/login")
            .header("X-Mme-Nas-Qualify", "synthetic-validation")
            .header("X-Apple-ADSID", "synthetic-account")
            .basic_auth("fixture@example.invalid", Some("synthetic-pet")), &payload)
            .unwrap().build().unwrap();
        assert_eq!(request.headers().get("Content-Type").and_then(|v| v.to_str().ok()), Some("text/plist"));
        assert_eq!(request.headers().get("Accept").and_then(|v| v.to_str().ok()), Some("application/x-plist"));
        assert_eq!(request.headers()["X-Mme-Nas-Qualify"], "synthetic-validation");
        assert_eq!(request.headers()["X-Apple-ADSID"], "synthetic-account");
        assert!(request.headers().contains_key("Authorization"));
        let body = request.body().unwrap().as_bytes().unwrap();
        assert_eq!(body, plist_to_string(&payload).unwrap().as_bytes());
        let parsed: Value = plist::from_bytes(body).unwrap();
        let delegates = parsed.as_dictionary().unwrap()["delegates"].as_dictionary().unwrap();
        assert!(delegates.contains_key("com.apple.private.ids"));
        assert!(delegates.contains_key("com.apple.mobileme"));
    }

    #[test]
    fn delegate_headers_preserve_explicit_service_context_and_proofs() {
        for name in ["X-Mme-Client-Info", "x-mme-client-info", "X-MME-CLIENT-INFO"] {
            let base = HashMap::from_iter([
                (name.into(), "synthetic-authkit-context".into()),
                ("X-Apple-I-MD".into(), "synthetic-onetime-proof".into()),
                ("X-Apple-I-MD-M".into(), "synthetic-machine-proof".into()),
                ("X-Apple-I-MD-LU".into(), "synthetic-local-id".into()),
                ("X-Apple-I-MD-RINFO".into(), "synthetic-routing".into()),
                ("X-Mme-Device-Id".into(), "synthetic-device-id".into()),
            ]);
            let headers = delegate_anisette_headers(base.clone());
            let request = Client::new().post("https://example.invalid")
                .header("X-Mme-Client-Info", "synthetic-aoskit-context")
                .header("X-Mme-Nas-Qualify", "synthetic-validation")
                .headers(headers)
                .basic_auth("fixture@example.invalid", Some("synthetic-pet"))
                .build().unwrap();
            assert_eq!(request.headers()["X-Mme-Client-Info"], "synthetic-aoskit-context");
            assert_eq!(request.headers().get_all("X-Mme-Client-Info").iter().count(), 1);
            for (name, value) in base {
                if !name.eq_ignore_ascii_case("X-Mme-Client-Info") {
                    assert_eq!(request.headers()[name], value);
                }
            }
            assert_eq!(request.headers()["X-Mme-Nas-Qualify"], "synthetic-validation");
            assert!(request.headers().contains_key("Authorization"));
        }
    }

    #[test]
    fn origin_is_classified_without_logging_any_url_data() {
        for url in ["https://setup.icloud.com/setup/signin/v2/login", "https://setup.icloud.com:443/private?secret=do-not-log"] {
            assert_eq!(delegate_response_origin(&url.parse().unwrap()), "expected");
        }
        for url in ["http://setup.icloud.com", "https://setup.icloud.com:444", "https://example.com/?account=private", "https://setup.icloud.com.example.com"] {
            assert_eq!(delegate_response_origin(&url.parse().unwrap()), "changed");
        }
    }
}

fn parse_apple_delegates(response: &AuthResponse) -> Result<DelegateResponses, PushError> {
    let parsed_dict = &response.dictionary;

    // Fixed numeric metadata only. The localized error text and description
    // are server-controlled strings and stay out of diagnostic logs.
    info!(target: "rustpush::auth::delegate_diagnostic",
        "delegate_body status={} localized_error_present={} description_present={}",
        parsed_dict.get("status").and_then(Value::as_signed_integer)
            .map(|status| status.to_string()).unwrap_or_else(|| "absent".to_string()),
        parsed_dict.contains_key("localizedError"),
        parsed_dict.contains_key("description"));

    if let Some(error) = parsed_dict.get("localizedError") {
        let error = error.as_string().ok_or_else(|| response.failure("invalid-localized-error"))?;
        if error == "UNAUTHORIZED" {
            return Err(PushError::UnauthorizedAccountError);
        }
        return Err(PushError::MobileMeError(
            error.to_string(),
            parsed_dict
                .get("description")
                .and_then(|d| d.as_string().map(|s| s.to_string())),
        ));
    }

    let status = parsed_dict.get("status").and_then(Value::as_signed_integer)
        .ok_or_else(|| response.failure("invalid-status"))?;
    if status != 0 {
        return Err(PushError::AuthError(Value::Dictionary(parsed_dict.clone())));
    }
    response.require_http_success()?;

    fn get_delegate<T: DeserializeOwned>(
        delegates: &Dictionary,
        delegate: &str,
        auth_response: &AuthResponse,
    ) -> Result<Option<T>, PushError> {
        let Some(value) = delegates.get(delegate) else {
            return Ok(None);
        };

        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct DelegateResponse {
            service_data: Option<Value>,
            status: i64,
            status_message: Option<String>,
        }

        let response: DelegateResponse = plist::from_value(&value)
            .map_err(|_| auth_response.failure("invalid-delegate-response"))?;

        if response.status != 0 {
            return Err(PushError::DelegateLoginFailed(
                delegate.to_string(), response.status,
                response.status_message.unwrap_or("No msg".to_string()),
            ));
        }

        let data = response.service_data.ok_or(PushError::DelegateLoginFailed(
            delegate.to_string(),
            response.status,
            response.status_message.unwrap_or("No msg".to_string()),
        ))?;
        Ok(Some(plist::from_value(&data)
            .map_err(|_| auth_response.failure("invalid-delegate-data"))?))
    }

    let delegates = parsed_dict
        .get("delegates")
        .and_then(Value::as_dictionary)
        .ok_or_else(|| response.failure("invalid-delegates"))?;

    let mut mme: Option<MobileMeDelegateResponse> = get_delegate(delegates, "com.apple.mobileme", response)?;

    if let Some(mme) = &mut mme {
        mme.config = get_delegate(delegates, "com.apple.mobileme", response)?.expect("No MME??");
    }

    Ok(DelegateResponses {
        ids: get_delegate(delegates, "com.apple.private.ids", response)?,
        mobileme: mme,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthCertRequest {
    authentication_data: Value,
    csr: Data,
    realm_user_id: String,
}

#[derive(Deserialize)]
struct AuthCertResponse {
    status: i64,
    cert: Option<Data>,
}

fn parse_auth_certificate(response: &AuthResponse) -> Result<Vec<u8>, PushError> {
    let parsed: AuthCertResponse = plist::from_value(&Value::Dictionary(response.dictionary.clone()))
        .map_err(|_| response.failure("invalid-certificate-response"))?;
    if parsed.status != 0 {
        return Err(PushError::CertError(response.dictionary.clone()));
    }
    response.require_http_success()?;
    if response.dictionary.contains_key("localizedError") {
        return Err(response.failure("unexpected-certificate-error"));
    }
    let cert: Vec<u8> = parsed.cert.ok_or_else(|| response.failure("missing-certificate"))?.into();
    if cert.is_empty() {
        return Err(response.failure("empty-certificate"));
    }
    Ok(cert)
}

fn generate_auth_csr(user_id: &str) -> Result<(RsaKey, Vec<u8>), PushError> {
    use x509_cert::der::{Decode as X509Decode, Encode as X509Encode};
    let key = RsaKey::overwrite(
        &format!("ids:{user_id}"),
        2048,
        KeystoreAccessRules {
            signature_padding: vec![KeystorePadding::PKCS1],
            digests: vec![KeystoreDigest::Sha1],
            can_sign: true,
            ..Default::default()
        },
    )?;

    let public_key = SubjectPublicKeyInfo::from_der(&key.get_public_key()?).unwrap();
    let common_name = encode_hex(&sha1(user_id.as_bytes())).to_uppercase();
    let request = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: RdnSequence(vec![RelativeDistinguishedName(
            SetOfVec::from_iter([AttributeTypeAndValue {
                oid: ObjectIdentifier::new("2.5.4.3").unwrap(), // commonname
                value: Utf8StringRef::new(&common_name).unwrap().into(),
            }])
            .unwrap(),
        )]),
        public_key,
        attributes: SetOfVec::new(),
    };

    let req_info = request.to_der().unwrap();

    let sign = key.sign(KeystoreDigest::Sha1, KeystorePadding::PKCS1, &req_info)?;

    let result = CertReq {
        info: request,
        algorithm: AlgorithmIdentifier {
            oid: ObjectIdentifier::new("1.2.840.113549.1.1.5").unwrap(),
            parameters: Some(Null.into()),
        },
        signature: BitString::from_bytes(&sign).unwrap(),
    };

    Ok((key, result.to_der().unwrap()))
}

async fn authenticate(
    os_config: &dyn OSConfig,
    user_id: &str,
    request: Value,
    user_type: IDSUserType,
) -> Result<IDSUser, PushError> {
    let (key, csr) = generate_auth_csr(user_id)?;

    let auth_cert = AuthCertRequest {
        authentication_data: request,
        csr: csr.into(),
        realm_user_id: user_id.to_string(),
    };

    let url = get_bag(IDS_BAG, user_type.auth_endpoint())
        .await?
        .into_string()
        .unwrap();

    let resp = REQWEST
        .post(url)
        .header(
            "user-agent",
            format!(
                "com.apple.invitation-registration {}",
                os_config.get_version_ua()
            ),
        )
        .header("x-protocol-version", os_config.get_protocol_version())
        .header("content-encoding", "gzip")
        .body(gzip_normal(&plist_to_buf(&auth_cert)?)?)
        .send()
        .await?;

    let response = AuthResponse::read("ids-auth-certificate", resp).await?;
    let cert = parse_auth_certificate(&response)?;

    let keypair = KeyPairNew {
        cert,
        private: key,
    };

    Ok(IDSUser {
        auth_keypair: keypair,
        user_id: user_id.to_string(),
        registration: HashMap::new(),
        user_type,
        protocol_version: os_config.get_protocol_version(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthApple {
    auth_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuthPhone {
    pub push_token: Data,
    pub sigs: Vec<Data>,
}

pub async fn authenticate_apple(
    ids_delegate: IDSDelegateResponse,
    os_config: &dyn OSConfig,
) -> Result<IDSUser, PushError> {
    authenticate(
        os_config,
        &ids_delegate.profile_id,
        plist::to_value(&AuthApple {
            auth_token: ids_delegate.auth_token,
        })?,
        IDSUserType::Apple,
    )
    .await
}

pub async fn authenticate_phone(
    number: &str,
    phone: AuthPhone,
    os_config: &dyn OSConfig,
) -> Result<IDSUser, PushError> {
    authenticate(
        os_config,
        &format!("P:{number}"),
        plist::to_value(&phone)?,
        IDSUserType::Phone,
    )
    .await
}

pub async fn authenticate_smsless(
    auth: &PhoneNumberResponse,
    host: &str,
    os_config: &dyn OSConfig,
    aps: &APSConnection,
) -> Result<IDSUser, PushError> {
    #[derive(DekuWrite, Clone, Debug)]
    #[deku(endian = "big")]
    struct SMSLessSig {
        header: u16,
        domain_len: u8,
        domain: Vec<u8>,
        carrier_len: u16,
        carrier: Vec<u8>,
    }

    let stripped_host = Url::parse(host)
        .expect("Failed to parse host")
        .domain()
        .expect("No domain name?")
        .to_string();
    let sig_data = base64_decode(&auth.signature);
    let sig = SMSLessSig {
        header: 0x0200,
        domain_len: stripped_host.len() as u8,
        domain: stripped_host.as_bytes().to_vec(),
        carrier_len: sig_data.len() as u16,
        carrier: sig_data,
    };

    let user_id = format!("P:{}", auth.phone_number);

    #[derive(Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct SmslessAuthRequest {
        csr: Data,
        sig: Data,
        tag: String,
        user_id: String,
    }

    let (key, csr) = generate_auth_csr(&user_id)?;

    let request = SmslessAuthRequest {
        csr: csr.into(),
        sig: sig.to_bytes()?.into(),
        tag: "SIM1".to_string(),
        user_id: user_id.clone(),
    };

    #[derive(Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct AuthMultipleUsers {
        push_token: Data,
        authentication_requests: Vec<SmslessAuthRequest>,
    }

    let users = AuthMultipleUsers {
        push_token: aps.try_get_token().await.ok_or(PushError::NotConnected)?.to_vec().into(),
        authentication_requests: vec![request],
    };

    let url = get_bag(IDS_BAG, "id-authenticate-multiple-users")
        .await?
        .into_string()
        .unwrap();

    let resp = REQWEST
        .post(url)
        .header(
            "user-agent",
            format!(
                "com.apple.invitation-registration {}",
                os_config.get_version_ua()
            ),
        )
        .header("x-protocol-version", os_config.get_protocol_version())
        .header("content-encoding", "gzip")
        .body(gzip_normal(&plist_to_buf(&users)?)?)
        .send()
        .await?
        .bytes()
        .await?;

    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct ResponseMultipleUsers {
        authentication_responses: Vec<SmslessAuthResponse>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct SmslessAuthResponse {
        cert: Data,
        user_id: String,
        status: u32,
    }

    let mut result: ResponseMultipleUsers = plist::from_bytes(&resp)?;

    let response = result.authentication_responses.remove(0);

    if response.status != 0 {
        return Err(PushError::CertError(plist::from_bytes(&resp)?));
    }

    let keypair = KeyPairNew {
        cert: response.cert.into(),
        private: key,
    };

    Ok(IDSUser {
        auth_keypair: keypair,
        user_id: user_id.to_string(),
        registration: HashMap::new(),
        user_type: IDSUserType::Phone,
        protocol_version: os_config.get_protocol_version(),
    })
}

pub enum NonceType {
    HTTP,
    APNS,
}

impl NonceType {
    fn get_header(&self) -> u8 {
        match self {
            Self::APNS => 0x00,
            Self::HTTP => 0x01,
        }
    }
}

pub fn generate_nonce(typ: NonceType) -> Vec<u8> {
    [
        vec![typ.get_header()],
        (duration_since_epoch().as_secs() * 1000)
            .to_be_bytes()
            .to_vec(),
        rand::thread_rng().gen::<[u8; 8]>().to_vec(),
    ]
    .concat()
}

pub fn build_payload(nonce: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut items = fields
        .iter()
        .map(|i| [(i.len() as u32).to_be_bytes().to_vec(), i.to_vec()].concat())
        .collect::<Vec<_>>();

    items.insert(0, nonce.to_vec());
    items.concat()
}

pub fn do_ids_signature(key: &RsaKey, payload: &[u8]) -> Result<Vec<u8>, PushError> {
    let signer = key.sign(KeystoreDigest::Sha1, KeystorePadding::PKCS1, &payload)?;

    Ok([vec![1, 1], signer].concat())
}

pub enum KeyType {
    Push,
    Auth,
    Id,
}

impl KeyType {
    fn name(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Push => "push",
            Self::Id => "id",
        }
    }
}

pub enum Signed {}
pub enum Unsigned {}

pub trait RequestState {}
impl RequestState for Signed {}
impl RequestState for Unsigned {}

pub struct SignedRequest<S: RequestState = Unsigned> {
    headers: HeaderMap,
    method: Method,
    body: Vec<u8>,
    bag: &'static str,
    marker: PhantomData<S>,
}

impl SignedRequest<Unsigned> {
    pub fn new(bag: &'static str, method: Method) -> Self {
        Self {
            headers: Default::default(),
            method,
            body: vec![],
            bag,
            marker: PhantomData,
        }
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

impl<S: RequestState> SignedRequest<S> {
    pub fn header(mut self, name: &str, val: &str) -> Self {
        self.headers
            .append::<HeaderName>(name.try_into().unwrap(), val.parse().unwrap());
        self
    }

    pub fn sign(
        mut self,
        pair: &KeyPairNew<RsaKey>,
        key_type: KeyType,
        aps: &APSState,
        item: Option<usize>,
    ) -> Result<SignedRequest<Signed>, PushError> {
        let name = key_type.name();
        let nonce = generate_nonce(NonceType::HTTP);
        let postfix = item.map(|i| format!("-{i}")).unwrap_or_default();
        self.headers.append::<HeaderName>(
            format!("x-{name}-nonce{postfix}").try_into().unwrap(),
            base64_encode(&nonce).parse().unwrap(),
        );

        let payload = build_payload(
            &nonce,
            &[
                self.bag.as_bytes(),
                "".as_bytes(), // query str
                &self.body,
                aps.token.as_ref().ok_or(PushError::APSNotReady("token"))?,
            ],
        );
        self.headers.append::<HeaderName>(
            format!("x-{name}-sig{postfix}").try_into().unwrap(),
            base64_encode(&do_ids_signature(&pair.private, &payload)?)
                .parse()
                .unwrap(),
        );
        self.headers.append::<HeaderName>(
            format!("x-{name}-cert{postfix}").try_into().unwrap(),
            base64_encode(&pair.cert).parse().unwrap(),
        );
        Ok(SignedRequest {
            headers: self.headers,
            method: self.method,
            body: self.body,
            bag: self.bag,
            marker: PhantomData,
        })
    }

    /// Push signatures may require asynchronous native signing. Auth and ID
    /// signatures deliberately keep the existing local-keystore path.
    pub async fn sign_push(mut self, aps:&APSState) -> Result<SignedRequest<Signed>,PushError> {
        let token=aps.token.as_ref().ok_or(PushError::APSNotReady("token"))?;
        let nonce=generate_nonce(NonceType::HTTP);
        let payload=build_payload(&nonce,&[self.bag.as_bytes(),b"",&self.body,token]);
        let (certificate,signature)=aps.sign_push_http(&nonce,self.bag,&payload).await?;
        for (name,value) in [("x-push-nonce",base64_encode(&nonce)),
            ("x-push-sig",base64_encode(&signature)),("x-push-cert",base64_encode(&certificate))] {
            self.headers.append::<HeaderName>(name.try_into().map_err(|_| PushError::BadMsg)?,
                value.parse().map_err(|_| PushError::BadMsg)?);
        }
        Ok(SignedRequest { headers:self.headers,method:self.method,body:self.body,bag:self.bag,marker:PhantomData })
    }

    pub async fn send(self, client: &Client) -> Result<Response, PushError> {
        let url = get_bag(IDS_BAG, self.bag).await?;
        Ok(client
            .request(self.method, url.as_string().unwrap())
            .headers(self.headers)
            .body(self.body)
            .send()
            .await?)
    }

    pub async fn send_apns(
        self,
        aps: &APSConnectionResource,
        topic: &'static str,
    ) -> Result<Vec<u8>, PushError> {
        let url = get_bag(IDS_BAG, self.bag).await?;

        let msg_id = rand::thread_rng().gen::<[u8; 16]>();

        let request =
            Value::Dictionary(Dictionary::from_iter(
                [
                    ("cT", Value::String("application/x-apple-plist".to_string())),
                    ("U", Value::Data(msg_id.to_vec())),
                    ("c", 96.into()),
                    ("u", url.as_string().unwrap().into()),
                    (
                        "h",
                        Value::Dictionary(Dictionary::from_iter(self.headers.into_iter().map(
                            |(a, b)| (a.unwrap().to_string(), b.to_str().unwrap().to_string()),
                        ))),
                    ),
                    ("v", 2.into()),
                    ("b", Value::Data(self.body)),
                ]
                .into_iter(),
            ));

        debug!("Sending APNS authentication query");

        let receiver = aps.subscribe().await;
        aps.send_message(topic, request, None).await?;

        let response = aps
            .wait_for_timeout(
                receiver,
                get_message(
                    |payload| {
                        let Some(recv_id) = payload.as_dictionary().unwrap().get("U") else {
                            return None;
                        };
                        if recv_id.as_data().unwrap() == msg_id {
                            Some(payload)
                        } else {
                            None
                        }
                    },
                    &[topic],
                ),
            )
            .await?;

        let response = response.as_dictionary().unwrap();
        if let Some(b) = response.get("b") {
            Ok(ungzip(b.as_data().unwrap())?)
        } else {
            Err(PushError::WebTunnelError(
                response["s"].as_unsigned_integer().unwrap() as u16,
            ))
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct ApsAlert {
    pub title: String,
    pub body: String,
    pub sbdy: String,
    pub defbtn: String,
    pub albtn: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct ApsData {
    pub alert: ApsAlert,
}

#[derive(Clone, Copy, Deserialize, Debug)]
pub struct AkData {
    pub lat: f32,
    pub lng: f32,
}

#[derive(Clone, Deserialize, Debug)]
pub struct IdmsRequestedSignIn {
    pub aps: ApsData,
    pub txnid: String,
    pub akdata: AkData,
    pub adsid: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct IdmsCircleMessage {
    pub step: u32,
    pub atxnid: String,
    pub pake: Option<String>,
    pub ec: Option<i32>,
    pub idmsdata: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct TeardownSignIn {
    pub prevtxnid: String,
}

#[derive(Clone, Debug)]
pub enum IdmsMessage {
    RequestedSignIn(IdmsRequestedSignIn),
    TeardownSignIn(TeardownSignIn),
    CircleRequest(IdmsCircleMessage, Option<IdmsRequestedSignIn>),
}

pub struct IdmsAuthListener {
    _interest_token: APSInterestToken,
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep0 {
    circle_step: rasn::types::Integer,
    public_ephermeral: rasn::types::OctetString,
    unk3: rasn::types::Integer, // set to 1
    req_uuid: rasn::types::OctetString,
    tag: rasn::types::OctetString, // ASCII 'o'
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep1Body {
    salt: rasn::types::OctetString,
    public_ephermeral: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep1 {
    circle_step: rasn::types::Integer,
    body: rasn::types::OctetString,
    octagon: Option<rasn::types::OctetString>,
}

#[derive(AsnType, Encode, Decode)]
struct CircleError {
    extra_code: rasn::types::Integer,
    meta: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep2 {
    circle_step: rasn::types::Integer,
    proof: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
struct CircleEncryptedPayload {
    iv: rasn::types::OctetString,
    ciphertext: rasn::types::OctetString,
    tag: rasn::types::OctetString,
}

type Aes128Gcm16ByteNonce = aes_gcm::AesGcm<Aes128, U16>;

struct CircleEncryptedChannel {
    recv_send: [u8; 16],
    send_recv: [u8; 16],
}

impl CircleEncryptedChannel {
    fn new(key: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, key);
        let mut recv_send = [0u8; 16];
        hk.expand("recv->send".as_bytes(), &mut recv_send)
            .expect("Failed to expand key!");
        let mut send_recv = [0u8; 16];
        hk.expand("send->recv".as_bytes(), &mut send_recv)
            .expect("Failed to expand key!");
        Self {
            recv_send,
            send_recv,
        }
    }

    fn encrypt(data: &[u8], key: [u8; 16]) -> Vec<u8> {
        let nonce: [u8; 16] = rand::random();
        let cipher = Aes128Gcm16ByteNonce::new(&key.into());
        let mut encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), data)
            .expect("AES GCM failed?");

        let tag = encrypted.split_off(encrypted.len() - 16);

        rasn::der::encode(&CircleEncryptedPayload {
            iv: nonce.to_vec().into(),
            ciphertext: encrypted.into(),
            tag: tag.into(),
        })
        .unwrap()
    }

    fn decrypt(payload: &[u8], key: [u8; 16]) -> Option<Vec<u8>> {
        let _self: CircleEncryptedPayload = rasn::der::decode(payload).ok()?;
        let cipher = Aes128Gcm16ByteNonce::new(&key.into());
        cipher
            .decrypt(
                Nonce::from_slice(&_self.iv),
                &*[&_self.ciphertext[..], &_self.tag[..]].concat(),
            )
            .ok()
    }

    fn encrypt_to_client(&self, data: &[u8]) -> Vec<u8> {
        Self::encrypt(data, self.recv_send)
    }

    fn decrypt_from_server(&self, data: &[u8]) -> Vec<u8> {
        Self::decrypt(data, self.recv_send).expect("Circle Decrypt Failed")
    }

    fn encrypt_to_server(&self, data: &[u8]) -> Vec<u8> {
        Self::encrypt(data, self.send_recv)
    }

    fn decrypt_from_client(&self, data: &[u8]) -> Option<Vec<u8>> {
        Self::decrypt(data, self.send_recv)
    }
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep3 {
    circle_step: rasn::types::Integer,
    proof: rasn::types::OctetString,
    payload: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep4 {
    circle_step: rasn::types::Integer,
    welcome: rasn::types::OctetString, // either SOS (legacy) or Octagon, since we say we don't support SOS it is always Octagon
    // if SOS and Octagon are enabled, this is Octagon, top is SOS
    unk2: Option<rasn::types::OctetString>,
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep5 {
    circle_step: rasn::types::Integer,
    // at least with Octagon
    voucher: rasn::types::OctetString,
}

pub struct CircleClientSession<P: AnisetteProvider> {
    account: Arc<DebugMutex<AppleAccount<P>>>,
    push_token: [u8; 32],
    srp_client: SrpClient<'static, Sha256>,
    a: [u8; 32],
    dsid: u64,
    verifier: Option<SrpClientVerifier<Sha256>>,
    saved_step: Option<IdmsCircleMessage>,
    trusted_peers: Option<Arc<KeychainClient<P>>>,
    channel: Option<CircleEncryptedChannel>,
    saved_password: Option<String>,
    saved_device_password: Option<Vec<u8>>,
    pub session_id: Option<String>,
    atxid: String,
    private_identity: Option<PrivateUserIdentity>,
}

impl<P: AnisetteProvider> CircleClientSession<P> {
    // WARN: you, the caller, are responsible for advertising a BLE GATT service with the uuid of session_id
    // modern OSes may refuse to add you to the circle if you are not in physical proximity
    pub async fn new(
        dsid: u64,
        account: Arc<DebugMutex<AppleAccount<P>>>,
        push_token: [u8; 32],
    ) -> Result<Self, PushError> {
        // note, -0 is the attempt number. Each time there is another attempt (send new code) the -0 increments by 1
        let atxid = format!("{}-0", rand::random::<u32>() / 2);

        let srp_client = SrpClient::<Sha256>::new(&G_3072);

        let a: [u8; 32] = rand::random();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let response = account
            .lock()
            .await
            .circle(
                &CircleSendMessage {
                    atxid: atxid.clone(),
                    circlestep: 0,
                    idmsdata: None,
                    pakedata: Some(base64_encode(
                        &rasn::der::encode(&CircleStep0 {
                            circle_step: 0.into(),
                            public_ephermeral: a_pub.into(),
                            unk3: 1.into(),
                            req_uuid: Uuid::new_v4().into_bytes().to_vec().into(),
                            tag: "o".as_bytes().into(),
                        })
                        .unwrap(),
                    )),
                    ptkn: encode_hex(&push_token).to_uppercase(),
                    ec: None,
                },
                true,
            )
            .await?;
        Ok(Self {
            account,
            push_token,
            srp_client,
            a,
            dsid,
            verifier: None,
            saved_step: None,
            saved_password: None,
            trusted_peers: None,
            channel: None,
            saved_device_password: None,
            session_id: response.sid,
            atxid,
            private_identity: None,
        })
    }

    pub async fn send_code(&mut self, password: &str) -> Result<(), PushError> {
        let Some(request) = &self.saved_step else {
            self.saved_password = Some(password.to_string());
            return Ok(());
        };

        if request.step != 2 {
            return Err(PushError::WrongStep(request.step));
        }

        let step2: CircleStep1 =
            rasn::der::decode(&base64_decode(request.pake.as_ref().expect("No Pake!")))
                .expect("failed to decode circlestep1");
        let body: CircleStep1Body =
            rasn::der::decode(step2.body.as_ref()).expect("failed to decode circlestep1body");

        let verifier: SrpClientVerifier<Sha256> = self
            .srp_client
            .process_reply(
                &self.a,
                format!("{}", self.dsid).as_bytes(),
                password.as_ref(),
                &body.salt,
                &body.public_ephermeral,
                false,
            )
            .unwrap();

        let step2 = rasn::der::encode(&CircleStep2 {
            circle_step: 2.into(),
            proof: verifier.proof().to_vec().into(),
        })
        .unwrap();

        self.verifier = Some(verifier);

        self.account
            .lock()
            .await
            .circle(
                &CircleSendMessage {
                    atxid: request.atxnid.clone(),
                    circlestep: 2,
                    idmsdata: Some(request.idmsdata.clone()),
                    pakedata: Some(base64_encode(&step2)),
                    ptkn: encode_hex(&self.push_token).to_uppercase(),
                    ec: None,
                },
                true,
            )
            .await?;

        Ok(())
    }

    pub async fn cancel(&self) -> Result<(), PushError> {
        self.account
            .lock()
            .await
            .circle(
                &CircleSendMessage {
                    atxid: self.atxid.clone(),
                    circlestep: 0,
                    ptkn: encode_hex(&self.push_token).to_uppercase(),
                    ec: Some(-9004),
                    idmsdata: None,
                    pakedata: None,
                },
                true,
            )
            .await?;
        return Ok(());
    }

    pub async fn handle_circle_request(
        &mut self,
        request: &IdmsCircleMessage,
    ) -> Result<Option<LoginState>, PushError> {
        if let Some(ec) = &request.ec {
            if *ec != -9005 {
                if *ec == -9003 {
                    // bad password
                    return Err(PushError::Bad2FaCode);
                }
                return Err(PushError::IdmsCircleError(*ec));
            }
            // 9005 is proximity check failed which is expected since we don't support proximity checks.
            // We can continue anyways, it is a soft error.
        }
        let Some(pake) = &request.pake else {
            return Err(PushError::IdmsCircleError(50));
        };
        match request.step {
            2 => {
                self.saved_step = Some(request.clone());
                if let Some(password) = &self.saved_password {
                    self.send_code(&password.clone()).await?;
                }
            }
            4 => {
                let step3: CircleStep3 =
                    rasn::der::decode(&base64_decode(pake)).expect("failed to decode circlestep1");
                self.verifier
                    .as_ref()
                    .unwrap()
                    .verify_server(&step3.proof)
                    .unwrap();

                self.channel = Some(CircleEncryptedChannel::new(
                    self.verifier.as_ref().unwrap().key(),
                ));
                let channel = self.channel.as_ref().unwrap();

                let decoded: String =
                    rasn::der::decode(&channel.decrypt_from_server(&step3.payload))
                        .expect("Failed to encode der?");
                info!("Received encrypted-channel verification code");

                self.saved_step = Some(request.clone());

                return Ok(Some(self.account.lock().await.verify_2fa(decoded).await?));
            }
            6 => {
                let step5: CircleStep5 =
                    rasn::der::decode(&base64_decode(pake)).expect("failed to decode circlestep1");
                if step5.voucher.is_empty() {
                    warn!("Not joining clique because peer did not send voucher!");
                    return Ok(Some(LoginState::LoggedIn));
                }
                use prost::Message;
                let message = OctagonPairingMessage::decode(Cursor::new(&step5.voucher))?;
                let info = SignedInfo {
                    info: message.step5.as_ref().unwrap().voucher.clone(),
                    signature: message.step5.as_ref().unwrap().voucher_sig.clone(),
                };
                with_cloudkit_writer_operation(async {
                    self.trusted_peers
                        .as_ref()
                        .unwrap()
                        .join_clique(
                            self.saved_device_password.as_ref().unwrap(),
                            self.private_identity
                                .as_ref()
                                .expect("no private identity??"),
                            Some(info),
                            &[],
                            vec![],
                        )
                        .await
                })
                .await?;
                return Ok(Some(LoginState::LoggedIn));
            }
            _circlestep => {
                warn!("Ignoring unknown circle step {_circlestep}");
            }
        }
        Ok(None)
    }

    pub async fn setup_trusted_peers(
        &mut self,
        peers: Arc<KeychainClient<P>>,
        device_password: &[u8],
    ) -> Result<(), PushError> {
        self.private_identity = Some(peers.new_user_identity(false).await?);

        with_cloudkit_writer_operation(peers.sync_trust()).await?;

        let Some(request) = &self.saved_step else {
            return Ok(());
        };
        if request.step != 4 {
            return Err(PushError::WrongStep(request.step));
        }

        if request.ec.is_some() {
            // we failed the proximity check
            return Err(PushError::CircleOver);
        }

        let state = peers.state.read().await;
        let identity = state.user_identity.as_ref().unwrap();
        let stable_info =
            identity.sign_payload(peers.generate_stable_info(&state), "TPPB.PeerStableInfo")?;

        use prost::Message;

        let pairing = OctagonWrapper {
            inner: Some(OctagonPairingMessage {
                step1: None,
                step4: Some(octagon_pairing_message::Step4 {
                    peer_id: Some(identity.identifier.clone()),
                    permanent_info: identity.info.info.clone(),
                    permanent_info_sig: identity.info.signature.clone(),
                    stable_info: stable_info.info.clone(),
                    stable_info_sig: stable_info.signature.clone(),
                }),
                step5: None,
                supports_octagon: Some(octagon_pairing_message::SupportsOctagon {
                    supports_octagon: Some(true),
                }),
                supports_sos: Some(octagon_pairing_message::SupportsSos {
                    supports_sos: Some(false),
                }),
            }),
        }
        .encode_to_vec();

        let message = rasn::der::encode(&CircleStep4 {
            circle_step: 4.into(),
            welcome: self
                .channel
                .as_ref()
                .unwrap()
                .encrypt_to_server(&pairing)
                .into(),
            unk2: None,
        })
        .expect("outer encoding failed");

        self.account
            .lock()
            .await
            .circle(
                &CircleSendMessage {
                    atxid: request.atxnid.clone(),
                    circlestep: 4,
                    idmsdata: Some(request.idmsdata.clone()),
                    pakedata: Some(base64_encode(&message)),
                    ptkn: encode_hex(&self.push_token).to_uppercase(),
                    ec: None,
                },
                true,
            )
            .await?;

        drop(state);

        self.trusted_peers = Some(peers);

        self.saved_device_password = Some(device_password.to_vec());

        Ok(())
    }
}

pub struct CircleServerSession<P: AnisetteProvider> {
    salt: [u8; 16],
    dsid: u64,
    verifier: Vec<u8>,
    server: SrpServer<'static, Sha256>,
    account: Arc<DebugMutex<AppleAccount<P>>>,
    b: [u8; 32],
    client_public: Option<Vec<u8>>,
    push_token: [u8; 32],
    channel: Option<CircleEncryptedChannel>,
    trusted_peers: Option<Arc<KeychainClient<P>>>,
}

impl<P: AnisetteProvider> CircleServerSession<P> {
    pub fn new(
        dsid: u64,
        otp: u32,
        account: Arc<DebugMutex<AppleAccount<P>>>,
        push_token: [u8; 32],
        trusted_peers: Option<Arc<KeychainClient<P>>>,
    ) -> Self {
        let salt: [u8; 16] = rand::random();
        let client = SrpClient::<Sha256>::new(&G_3072);
        // check password, was guess
        let verifier = client.compute_verifier(
            format!("{dsid}").as_bytes(),
            format!("{:0>6}", otp).as_bytes(),
            &salt,
        );

        Self {
            salt,
            dsid,
            verifier,
            server: SrpServer::<Sha256>::new(&G_3072),
            account,
            b: rand::random(),
            client_public: None,
            push_token,
            channel: None,
            trusted_peers,
        }
    }

    pub async fn handle_circle_request(
        &mut self,
        request: &IdmsCircleMessage,
    ) -> Result<bool, PushError> {
        if let Some(ec) = &request.ec {
            return Err(PushError::IdmsCircleError(*ec));
        }
        let Some(pake) = &request.pake else {
            return Err(PushError::IdmsCircleError(50));
        };
        match request.step {
            1 => {
                let step0: CircleStep0 =
                    rasn::der::decode(&base64_decode(pake)).expect("failed to decode circlestep0");
                self.client_public = Some(step0.public_ephermeral.into());
                let b_pub = self
                    .server
                    .compute_public_ephemeral(&self.b, &self.verifier);

                use prost::Message;

                let is_in_clique = if let Some(tp) = &self.trusted_peers {
                    with_cloudkit_writer_operation(async {
                        Ok::<bool, PushError>(tp.is_in_clique().await)
                    })
                    .await?
                } else {
                    false
                };

                let step1 = rasn::der::encode(&CircleStep1 {
                    circle_step: 1.into(),
                    body: rasn::der::encode(&CircleStep1Body {
                        salt: self.salt.to_vec().into(),
                        public_ephermeral: b_pub.into(),
                    })
                    .unwrap()
                    .into(),
                    octagon: if is_in_clique {
                        Some(
                            OctagonPairingMessage {
                                step1: Some(octagon_pairing_message::Step1 { epoch: Some(1) }),
                                step4: None,
                                step5: None,
                                supports_octagon: Some(octagon_pairing_message::SupportsOctagon {
                                    supports_octagon: Some(true),
                                }),
                                supports_sos: Some(octagon_pairing_message::SupportsSos {
                                    supports_sos: Some(false),
                                }),
                            }
                            .encode_to_vec()
                            .into(),
                        )
                    } else {
                        None
                    },
                })
                .unwrap();

                debug!("Created initial circle pairing message");

                self.account
                    .lock()
                    .await
                    .circle(
                        &CircleSendMessage {
                            atxid: request.atxnid.clone(),
                            circlestep: 1,
                            idmsdata: Some(request.idmsdata.clone()),
                            pakedata: Some(base64_encode(&step1)),
                            ptkn: encode_hex(&self.push_token).to_uppercase(),
                            ec: None,
                        },
                        false,
                    )
                    .await?;
            }
            3 => {
                let step2: CircleStep2 =
                    rasn::der::decode(&base64_decode(pake)).expect("failed to decode circlestep0");
                let verifier = self
                    .server
                    .process_reply(
                        &self.b,
                        &self.verifier,
                        self.client_public.as_ref().unwrap(),
                        format!("{}", self.dsid).as_bytes(),
                        &self.salt,
                    )
                    .expect("Srp failure");
                if let Err(e) = verifier.verify_client(&step2.proof) {
                    warn!("SRP auth error {e}");
                    self.account
                        .lock()
                        .await
                        .circle(
                            &CircleSendMessage {
                                atxid: request.atxnid.clone(),
                                circlestep: 3,
                                idmsdata: Some(request.idmsdata.clone()),
                                pakedata: Some(base64_encode(
                                    &rasn::der::encode(&CircleError {
                                        extra_code: 0.into(),
                                        meta: vec![].into(),
                                    })
                                    .unwrap(),
                                )),
                                ptkn: encode_hex(&self.push_token).to_uppercase(),
                                ec: Some(-9003),
                            },
                            false,
                        )
                        .await?;
                    return Ok(false);
                }
                let receipt = verifier.proof();

                let channel = CircleEncryptedChannel::new(verifier.key());

                let twofa_code = self
                    .account
                    .lock()
                    .await
                    .anisette
                    .lock()
                    .await
                    .provider
                    .get_2fa_code()
                    .await?;
                let twofa_str = format!("{:0>6}", twofa_code);

                let message = rasn::der::encode(&CircleStep3 {
                    circle_step: 3.into(),
                    proof: receipt.to_vec().into(),
                    payload: channel
                        .encrypt_to_client(
                            &rasn::der::encode(&twofa_str).expect("Failed to encode der?"),
                        )
                        .into(),
                })
                .expect("outer encoding failed");

                self.account
                    .lock()
                    .await
                    .circle(
                        &CircleSendMessage {
                            atxid: request.atxnid.clone(),
                            circlestep: 3,
                            idmsdata: Some(request.idmsdata.clone()),
                            pakedata: Some(base64_encode(&message)),
                            ptkn: encode_hex(&self.push_token).to_uppercase(),
                            ec: None,
                        },
                        false,
                    )
                    .await?;

                self.channel = Some(channel);
            }
            5 => {
                let step4: CircleStep4 =
                    rasn::der::decode(&base64_decode(pake)).expect("failed to decode circlestep0");

                let channel = self.channel.as_ref().unwrap();

                let is_in_clique = if let Some(tp) = &self.trusted_peers {
                    with_cloudkit_writer_operation(async {
                        Ok::<bool, PushError>(tp.is_in_clique().await)
                    })
                    .await?
                } else {
                    false
                };
                use prost::Message;

                let wrapper = if let Some(wrapper) = channel.decrypt_from_client(&step4.welcome) {
                    OctagonWrapper::decode(Cursor::new(&wrapper)).map(|i| i.inner.unwrap())
                } else {
                    OctagonPairingMessage::decode(Cursor::new(&step4.welcome))
                };

                if !is_in_clique || wrapper.is_err() {
                    // Let's just say "I don't have them", because, well, I don't
                    self.account
                        .lock()
                        .await
                        .circle(
                            &CircleSendMessage {
                                atxid: request.atxnid.clone(),
                                circlestep: 5,
                                idmsdata: Some(request.idmsdata.clone()),
                                pakedata: Some(base64_encode(
                                    &rasn::der::encode(&CircleStep5 {
                                        circle_step: 5.into(),
                                        voucher: vec![].into(),
                                    })
                                    .expect("outer encoding failed"),
                                )),
                                ptkn: encode_hex(&self.push_token).to_uppercase(),
                                ec: None,
                            },
                            false,
                        )
                        .await?;
                    return Ok(true);
                }

                let wrapper = wrapper.unwrap().step4.unwrap();
                let cuttlefish_peer = EncodedPeer(CuttlefishPeer {
                    hash: wrapper.peer_id,
                    permanent_info: Some(SignedInfo {
                        info: wrapper.permanent_info,
                        signature: wrapper.permanent_info_sig,
                    }),
                    stable_info: Some(SignedInfo {
                        info: wrapper.stable_info,
                        signature: wrapper.stable_info_sig,
                    }),
                    dynamic_info: None,
                    voucher: None,
                });

                let peers = self.trusted_peers.as_ref().unwrap();
                let tlks = peers.get_share_tlks().await?;
                with_cloudkit_writer_operation(peers.share_tlks_to_peer(&cuttlefish_peer, &tlks))
                    .await?;

                let voucher = peers
                    .state
                    .read()
                    .await
                    .user_identity
                    .as_ref()
                    .unwrap()
                    .vouch_for(cuttlefish_peer.0.hash().to_string())?;

                self.account
                    .lock()
                    .await
                    .circle(
                        &CircleSendMessage {
                            atxid: request.atxnid.clone(),
                            circlestep: 5,
                            idmsdata: Some(request.idmsdata.clone()),
                            pakedata: Some(base64_encode(
                                &rasn::der::encode(&CircleStep5 {
                                    circle_step: 5.into(),
                                    voucher: OctagonPairingMessage {
                                        step1: None,
                                        step4: None,
                                        step5: Some(Step5 {
                                            voucher: voucher.info,
                                            voucher_sig: voucher.signature,
                                        }),
                                        supports_octagon: Some(Default::default()),
                                        supports_sos: Some(Default::default()),
                                    }
                                    .encode_to_vec()
                                    .into(),
                                })
                                .expect("outer encoding failed"),
                            )),
                            ptkn: encode_hex(&self.push_token).to_uppercase(),
                            ec: None,
                        },
                        false,
                    )
                    .await?;
            }
            _circlestep => {
                warn!("Ignoring unknown circle step {_circlestep}");
            }
        }
        Ok(true)
    }
}

impl IdmsAuthListener {
    pub async fn new(conn: APSConnection) -> Self {
        Self {
            _interest_token: conn.request_topics(&["com.apple.idmsauth"]).await,
        }
    }

    pub fn handle(&self, message: APSMessage) -> Result<Option<IdmsMessage>, PushError> {
        let APSMessage::Notification {
            topic,
            payload: Value::Data(payload),
            ..
        } = message
        else {
            return Ok(None);
        };
        if &topic != &sha1("com.apple.idmsauth".as_bytes()) {
            return Ok(None);
        }

        let data: serde_json::value::Map<String, serde_json::Value> =
            serde_json::from_slice(&payload)?;

        debug!(
            "Received IDMS message (command_present={})",
            data.contains_key("cmd")
        );

        Ok(match data["cmd"].as_u64().unwrap() {
            100 => Some(IdmsMessage::RequestedSignIn(serde_json::from_slice(
                &payload,
            )?)),
            400 => Some(IdmsMessage::TeardownSignIn(serde_json::from_slice(
                &payload,
            )?)),
            700 => Some(IdmsMessage::CircleRequest(
                serde_json::from_slice(&payload)?,
                serde_json::from_slice(&payload).ok(),
            )),
            _cmd => {
                debug!("Ignoring unknown IDMS message");
                None
            }
        })
    }
}
