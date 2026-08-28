use std::{borrow::Borrow, collections::BTreeSet, io::Cursor, time::SystemTime};

use crate::{
    keychain::{KeychainClient, KeychainClientState, PCSMeta, SavedKeychainZone},
    util::{
        base64_decode, base64_encode, decode_hex, encode_hex, kdf_ctr_hmac, rfc6637_unwrap_key,
        rfc6637_wrap_key, CompactECKey,
    },
    OSConfig, PushError,
};
use aes::{cipher::consts::U12, Aes128};
use aes_gcm::AeadInPlace;
use aes_gcm::KeyInit;
use aes_gcm::{AesGcm, Nonce, Tag};
use chrono::Utc;
use cloudkit_proto::{CloudKitEncryptor, ProtectionInfo, RecordIdentifier};
use log::{info, warn};
use omnisette::AnisetteProvider;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkcs5::pbkdf2_hmac,
    pkey::{HasPublic, PKey, Private, Public},
    sha::{sha1, sha256},
    sign::{Signer, Verifier},
};
use plist::{Dictionary, Value};
use prost::bytes::Bytes;
use rasn::{
    types::{Any, GeneralizedTime, SequenceOf, SetOf},
    AsnType, Decode, Encode,
};
use rustls::internal::msgs;
use uuid::Uuid;

pub struct PCSService<'t> {
    pub name: &'t str,
    pub view_hint: &'t str,
    pub zone: &'t str,
    pub r#type: i64,
    pub keychain_type: i32,
    pub v2: bool,
    // use zone-level record protection, as opposed to record protection on each record
    pub global_record: bool,
}

const MASTER_SERVICE: PCSService = PCSService {
    name: "MasterKey",
    view_hint: "PCS-MasterKey",
    zone: "ProtectedCloudStorage",
    r#type: 1,
    keychain_type: 65537,
    v2: false,
    global_record: true, // should be unused
};

fn require_existing_service_key_dict<'a>(
    zone: Option<&'a SavedKeychainZone>,
    service: &PCSService<'_>,
    missing: PushError,
) -> Result<&'a Dictionary, PushError> {
    zone.and_then(|zone| {
        zone.get_current_key(&format!("com.apple.ProtectedCloudStorage-{}", service.name))
    })
    .ok_or(missing)
}

const PCS_SHARE_KEY_UNAVAILABLE: &str = "unavailable";

fn share_key_not_found() -> PushError {
    PushError::ShareKeyNotFound(PCS_SHARE_KEY_UNAVAILABLE.to_string())
}

fn decode_compact_public_key(key: &[u8]) -> Result<CompactECKey<Public>, PushError> {
    let key: [u8; 32] = key.try_into().map_err(|_| PushError::BadMsg)?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut context = BigNumContext::new()?;
    let mut encoded = [0u8; 33];
    encoded[0] = 0x03;
    encoded[1..].copy_from_slice(&key);
    let point = EcPoint::from_bytes(&group, &encoded, &mut context)?;
    CompactECKey::try_from(EcKey::from_public_key(&group, &point)?)
}

fn decode_compact_private_key(key: &[u8]) -> Result<CompactECKey<Private>, PushError> {
    let key: [u8; 64] = key.try_into().map_err(|_| PushError::BadMsg)?;
    let public = decode_compact_public_key(&key[..32])?;
    let private = BigNum::from_slice(&key[32..])?;
    CompactECKey::try_from(EcKey::from_private_components(
        public.group(),
        &private,
        public.public_key(),
    )?)
}

// _add_PCSAttributes see references for types
#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PCSAttribute {
    key: u32,
    value: rasn::types::OctetString,
}

// key 3
#[derive(AsnType, Encode, Decode)]
pub struct PCSManateeFlags {
    flags: u32,
}

#[derive(AsnType, Encode, Decode)]
pub struct PCSBuildAndTime {
    #[rasn(tag(explicit(context, 0)))]
    build: String,
    #[rasn(tag(explicit(context, 1)))]
    time: GeneralizedTime,
}

#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
pub struct PCSSignature {
    keyid: rasn::types::OctetString,
    digest: u32, // 1 is sha256, 2 is sha512 (check?)
    signature: rasn::types::OctetString,
}

// signature is this struct with signature set to none
// the ID is found in ProtectedCloudStorage Keychain store.
// this is known as a "service key"
#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[rasn(tag(explicit(application, 1)))]
pub struct PCSPublicKey {
    pcsservice: i64,
    unk1: u64,
    pub_key: rasn::types::OctetString,
    #[rasn(tag(explicit(context, 0)))]
    attributes: Option<SequenceOf<PCSAttribute>>,
    #[rasn(tag(explicit(context, 1)))]
    signature: Option<PCSSignature>,
}

impl PCSPublicKey {
    pub fn data_for_signing(&self) -> Vec<u8> {
        let mut item = self.clone();
        item.signature = None;
        rasn::der::encode(&item).unwrap()
    }

    pub fn verify<T: HasPublic>(&self, key: &EcKey<T>) -> Result<bool, PushError> {
        let key = PKey::from_ec_key(key.clone())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        let data =
            rasn::der::encode(&self.clone_without_signature()).map_err(|_| PushError::BadMsg)?;
        verifier.update(&data)?;

        let signature = self.signature.as_ref().ok_or(PushError::BadMsg)?;
        Ok(verifier.verify(&signature.signature)?)
    }

    fn clone_without_signature(&self) -> Self {
        let mut item = self.clone();
        item.signature = None;
        item
    }

    pub fn sign(&mut self, key: &CompactECKey<Private>) -> Result<(), PushError> {
        let pkey = key.get_pkey();
        let mut verifier = Signer::new(MessageDigest::sha256(), &pkey)?;
        verifier.update(&self.data_for_signing())?;

        self.signature = Some(PCSSignature {
            keyid: sha256(&key.compress())[..20].to_vec().into(),
            digest: 1,
            signature: verifier.sign_to_vec().unwrap().into(),
        });
        Ok(())
    }
}

pub async fn get_boundary_key(
    service: &PCSService<'_>,
    keychain: &KeychainClient<impl AnisetteProvider>,
) -> Result<Vec<u8>, PushError> {
    let state = keychain.state.read().await;
    let existing = state.items.get(service.zone).and_then(|items| {
        items.keys.values().find(|v| {
            v.get("acct") == Some(&Value::String("PCSBoundaryKey".to_string()))
                && v.get("srvr") == Some(&Value::String(state.dsid.clone()))
        })
    });
    if let Some(existing) = existing {
        Ok(state.get_data(existing)?.unwrap())
    } else {
        let key: [u8; 32] = rand::random();

        // create new boundary key
        let keychain_dict = Dictionary::from_iter([
            ("class", Value::String("inet".to_string())),
            ("tomb", Value::Integer(0.into())),
            ("acct", Value::String("PCSBoundaryKey".to_string())),
            ("v_Data", Value::Data(key.to_vec())),
            ("atyp", Value::Data(vec![])),
            ("sha1", Value::Data(rand::random::<[u8; 20]>().to_vec())), // don't ask, don't check lmao
            ("path", Value::String("".to_string())),
            ("musr", Value::Data(vec![])),
            ("sdmn", Value::String(base64_encode(&sha256(&key)))), // security domain
            ("cdat", Value::Date(SystemTime::now().into())),
            ("srvr", Value::String(state.dsid.to_string())),
            ("mdat", Value::Date(SystemTime::now().into())),
            ("pdmn", Value::String("ck".to_string())),
            ("ptcl", Value::Integer(0.into())),
            (
                "agrp",
                Value::String("com.apple.ProtectedCloudStorage".to_string()),
            ),
            ("vwht", Value::String(service.view_hint.to_string())),
            ("port", Value::Integer(0.into())),
        ]);

        drop(state);

        keychain
            .insert_keychain(
                &Uuid::new_v4().to_string().to_uppercase(),
                service.zone,
                "classC",
                keychain_dict,
                None,
                None,
            )
            .await?;

        Ok(key.to_vec())
    }
}

#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[rasn(choice)]
pub enum PCSPrivateKey {
    V1 {
        key: rasn::types::OctetString,
        public: Option<PCSPublicKey>,
    },
    #[rasn(tag(application, 5))]
    V2 { data: rasn::types::OctetString },
}

impl PCSPrivateKey {
    pub fn new(
        signature_key: Option<&PCSPrivateKey>,
        service: i64,
        v2: bool,
        attributes: Vec<PCSAttribute>,
    ) -> Result<Self, PushError> {
        let key = CompactECKey::new()?;
        let signing_key = CompactECKey::new()?;

        let mut public = PCSPublicKey {
            pcsservice: service,
            unk1: 1,
            pub_key: key.compress().to_vec().into(),
            attributes: if attributes.is_empty() {
                None
            } else {
                Some(attributes)
            },
            signature: None,
        };

        let signature_key = if let Some(signature_key) = &signature_key {
            signature_key.signing_key()
        } else {
            signing_key.clone()
        };

        public.sign(&signature_key)?;

        use prost::Message;

        Ok(if v2 {
            Self::V2 {
                data: cloudkit_proto::ProtoPcsKey {
                    encryption_key: cloudkit_proto::ProtoPcsPrivateKey {
                        key: key.compress_private().to_vec(),
                        public: Some(rasn::der::encode(&public).unwrap()),
                    },
                    signing_key: Some(cloudkit_proto::ProtoPcsPrivateKey {
                        key: signature_key.compress_private().to_vec(),
                        public: None,
                    }),
                }
                .encode_to_vec()
                .into(),
            }
        } else {
            Self::V1 {
                key: key.compress_private().to_vec().into(),
                public: Some(public),
            }
        })
    }

    // does not sync keys, make sure to sync beforehand
    pub async fn get_master_key(
        keychain: &KeychainClient<impl AnisetteProvider>,
    ) -> Result<Self, PushError> {
        let state = keychain.state.read().await;
        let existing = state.items.get(MASTER_SERVICE.zone).and_then(|zone| {
            zone.get_current_key(&format!(
                "com.apple.ProtectedCloudStorage-{}",
                MASTER_SERVICE.name
            ))
        });
        if let Some(existing) = existing {
            return Ok(Self::from_dict(existing, &state));
        }
        drop(state);
        let master_key = PCSPrivateKey::new_master_key()?;
        master_key
            .save_key(
                &Uuid::new_v4().to_string().to_uppercase(),
                &keychain,
                &MASTER_SERVICE,
            )
            .await?;
        Ok(master_key)
    }

    /// Returns the existing PCS master key without creating or saving one.
    pub async fn require_existing_master_key(
        keychain: &KeychainClient<impl AnisetteProvider>,
    ) -> Result<Self, PushError> {
        let state = keychain.state.read().await;
        let existing = require_existing_service_key_dict(
            state.items.get(MASTER_SERVICE.zone),
            &MASTER_SERVICE,
            PushError::MasterKeyNotFound,
        )?;
        Self::try_from_dict(existing, &state)
    }

    // use a service struct
    pub async fn get_service_key(
        keychain: &KeychainClient<impl AnisetteProvider>,
        service: &PCSService<'_>,
        config: &dyn OSConfig,
    ) -> Result<Self, PushError> {
        let state = keychain.state.read().await;
        let existing = state.items.get(service.zone).and_then(|zone| {
            zone.get_current_key(&format!("com.apple.ProtectedCloudStorage-{}", service.name))
        });
        if let Some(existing) = existing {
            return Ok(PCSPrivateKey::from_dict(existing, &state));
        }
        drop(state);
        let master_key = Self::get_master_key(keychain).await?;

        let service_key =
            PCSPrivateKey::new_service_key(&master_key, service.r#type, service.v2, config)?;
        service_key
            .save_key(
                &Uuid::new_v4().to_string().to_uppercase(),
                &keychain,
                service,
            )
            .await?;
        Ok(service_key)
    }

    /// Returns an existing service key and its existing master-key dependency.
    ///
    /// This method intentionally has no creation fallback. It is the only PCS
    /// service-key lookup allowed by semantic decode, where missing keychain
    /// state must be reported instead of repaired with a remote insert.
    pub async fn require_existing_service_key(
        keychain: &KeychainClient<impl AnisetteProvider>,
        service: &PCSService<'_>,
    ) -> Result<Self, PushError> {
        Self::require_existing_master_key(keychain).await?;

        let state = keychain.state.read().await;
        let existing = require_existing_service_key_dict(
            state.items.get(service.zone),
            service,
            share_key_not_found(),
        )?;
        Self::try_from_dict(existing, &state)
    }

    pub fn new_service_key(
        master_key: &PCSPrivateKey,
        service: i64,
        v2: bool,
        config: &dyn OSConfig,
    ) -> Result<Self, PushError> {
        // one day i will fix the config mess, i swear...
        let data = config.get_register_meta();
        let meta = format!(
            "{};{}",
            data.os_version.split_once(",").unwrap().0,
            data.software_version
        );

        let attributes = vec![
            PCSAttribute {
                key: 3,
                value: rasn::der::encode(&PCSManateeFlags { flags: 0 })
                    .unwrap()
                    .into(),
            },
            PCSAttribute {
                key: 1,
                value: rasn::der::encode(&PCSBuildAndTime {
                    build: meta,
                    time: Utc::now().into(),
                })
                .unwrap()
                .into(),
            },
        ];
        Self::new(Some(master_key), service, v2, attributes)
    }

    pub fn new_master_key() -> Result<Self, PushError> {
        Self::new(None, 1, false, vec![])
    }

    pub fn public(&self) -> Result<PCSPublicKey, PushError> {
        use prost::Message;
        Ok(match self {
            Self::V1 { key: _, public } => public.clone().ok_or(PushError::BadMsg)?,
            Self::V2 { data } => {
                let decoded = cloudkit_proto::ProtoPcsKey::decode(Cursor::new(data))?;
                let public = decoded
                    .encryption_key
                    .public
                    .as_ref()
                    .ok_or(PushError::BadMsg)?;
                rasn::der::decode(public).map_err(|_| PushError::BadMsg)?
            }
        })
    }

    pub async fn save_key(
        &self,
        uuid: &str,
        keychain: &KeychainClient<impl AnisetteProvider>,
        service: &PCSService<'_>,
    ) -> Result<(), PushError> {
        let dsid = keychain.state.read().await.dsid.clone();
        let public = self.public()?;
        if service.r#type != public.pcsservice {
            panic!("mismatched service type!")
        }
        let id = sha256(&public.pub_key);
        let keychain_dict = Dictionary::from_iter([
            ("invi", Value::Integer(1.into())), // invisible
            ("sdmn", Value::String("ProtectedCloudStorage".to_string())), // security domain
            ("class", Value::String("inet".to_string())),
            ("srvr", Value::String(dsid.to_string())),
            ("path", Value::String("".to_string())),
            (
                "labl",
                Value::String(format!(
                    "PCS {} - {}",
                    service.name,
                    base64_encode(&public.pub_key[..6])
                )),
            ),
            (
                "agrp",
                Value::String("com.apple.ProtectedCloudStorage".to_string()),
            ),
            ("pdmn", Value::String("ck".to_string())),
            ("type", Value::Integer(service.keychain_type.into())),
            ("atyp", Value::Data(id[..20].to_vec())),
            ("port", Value::Integer(0.into())),
            ("vwht", Value::String(service.view_hint.to_string())),
            ("sha1", Value::Data(rand::random::<[u8; 20]>().to_vec())), // don't ask, don't check lmao
            ("musr", Value::Data(vec![])),
            ("cdat", Value::Date(SystemTime::now().into())),
            ("mdat", Value::Date(SystemTime::now().into())),
            ("ptcl", Value::Integer(0.into())),
            ("tomb", Value::Integer(0.into())),
            ("v_Data", Value::Data(rasn::der::encode(self).unwrap())),
            ("acct", Value::String(base64_encode(&public.pub_key))),
        ]);

        keychain
            .insert_keychain(
                uuid,
                service.zone,
                "classC",
                keychain_dict,
                Some(&PCSMeta {
                    pcsservice: public.pcsservice,
                    pcspublickey: public.pub_key.to_vec(),
                    pcspublicidentity: rasn::der::encode(&public).unwrap(),
                }),
                Some(&format!("com.apple.ProtectedCloudStorage-{}", service.name)),
            )
            .await?;

        Ok(())
    }

    fn try_from_dict(dict: &Dictionary, keychain: &KeychainClientState) -> Result<Self, PushError> {
        let key = keychain.get_data(dict)?.ok_or(PushError::BadMsg)?;
        let decoded: PCSPrivateKey = rasn::der::decode(&key).map_err(|_| PushError::BadMsg)?;
        let key_id = dict
            .get("atyp")
            .and_then(Value::as_data)
            .ok_or(PushError::BadMsg)?;

        if !decoded.verify_with_keychain(keychain, key_id)? {
            return Err(PushError::VerificationFailed);
        }

        Ok(decoded)
    }

    pub fn from_dict(dict: &Dictionary, keychain: &KeychainClientState) -> Self {
        let key = keychain
            .get_data(dict)
            .expect("Failed to get data")
            .expect("No dataa");

        let decoded: PCSPrivateKey =
            rasn::der::decode(&key).expect("Failed to decode private key!");

        match decoded.verify_with_keychain(
            keychain,
            dict.get("atyp")
                .expect("No dat?")
                .as_data()
                .expect("Not data"),
        ) {
            Ok(true) => {}
            Ok(false) => {
                panic!("PCS Master key verification failed!");
            }
            Err(e) => {
                warn!("PCS master key verification failed {e}");
            }
        }

        decoded
    }

    pub fn key(&self) -> CompactECKey<Private> {
        use prost::Message;
        let key = match self {
            Self::V1 { key, public: _ } => key.to_vec(),
            Self::V2 { data } => {
                let decoded = cloudkit_proto::ProtoPcsKey::decode(Cursor::new(data)).unwrap();
                decoded.encryption_key.key
            }
        };
        CompactECKey::decompress_private(key[..].try_into().unwrap())
    }

    fn try_key(&self) -> Result<CompactECKey<Private>, PushError> {
        use prost::Message;
        let key = match self {
            Self::V1 { key, public: _ } => key.to_vec(),
            Self::V2 { data } => {
                cloudkit_proto::ProtoPcsKey::decode(Cursor::new(data))?
                    .encryption_key
                    .key
            }
        };
        decode_compact_private_key(&key)
    }

    pub fn signing_key(&self) -> CompactECKey<Private> {
        use prost::Message;
        let key = match self {
            Self::V1 { key, public: _ } => key.to_vec(),
            Self::V2 { data } => {
                let decoded = cloudkit_proto::ProtoPcsKey::decode(Cursor::new(data)).unwrap();
                decoded.signing_key.unwrap_or(decoded.encryption_key).key
            }
        };
        CompactECKey::decompress_private(key[..].try_into().unwrap())
    }

    fn try_signing_key(&self) -> Result<CompactECKey<Private>, PushError> {
        use prost::Message;
        let key = match self {
            Self::V1 { key, public: _ } => key.to_vec(),
            Self::V2 { data } => {
                let decoded = cloudkit_proto::ProtoPcsKey::decode(Cursor::new(data))?;
                decoded.signing_key.unwrap_or(decoded.encryption_key).key
            }
        };
        decode_compact_private_key(&key)
    }

    pub fn verify_with_keychain(
        &self,
        keychain: &KeychainClientState,
        keyid: &[u8],
    ) -> Result<bool, PushError> {
        let public = self.public()?;
        let signature = public.signature.as_ref().ok_or(PushError::BadMsg)?;

        if keyid == &signature.keyid[..] {
            // self signed
            let signing_key = self.try_signing_key()?;
            public.verify(&signing_key)
        } else {
            let account = Value::Data(signature.keyid.to_vec());
            let item = keychain
                .items
                .get("ProtectedCloudStorage")
                .ok_or(PushError::MasterKeyNotFound)?
                .keys
                .values()
                .find(|x| x.get("atyp") == Some(&account))
                .ok_or(PushError::MasterKeyNotFound)?;
            let key = keychain.get_data(item)?.ok_or(PushError::BadMsg)?;

            let decoded: PCSPrivateKey = rasn::der::decode(&key).map_err(|_| PushError::BadMsg)?;

            if !decoded.verify_with_keychain(keychain, &signature.keyid)? {
                return Err(PushError::VerificationFailed);
            }

            let key = decoded.try_signing_key()?;

            public.verify(&key)
        }
    }
}

fn get_ciphertext_key(ciphertext: &[u8]) -> Result<(Vec<u8>, usize), PushError> {
    let encryption_version = *ciphertext
        .first()
        .ok_or(PushError::PCSCiphertextMalformed)?;
    if encryption_version != 3 {
        return Err(PushError::PCSCiphertextMalformed);
    }

    let second_keyid_part_len =
        usize::from(*ciphertext.get(3).ok_or(PushError::PCSCiphertextMalformed)?);
    let first_key_part = ciphertext
        .get(1..3)
        .ok_or(PushError::PCSCiphertextMalformed)?;
    let second_key_part = ciphertext
        .get(4..4 + second_keyid_part_len)
        .ok_or(PushError::PCSCiphertextMalformed)?;
    let total_tag = [first_key_part, second_key_part].concat();

    Ok((total_tag, 4 + second_keyid_part_len))
}

#[derive(AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PCSKeyRef {
    pub keytype: u32,
    pub pub_key: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PCSShareKey {
    decryption_key: PCSKeyRef,
    ciphertext: rasn::types::OctetString,
    flags: Option<u32>,
}

#[derive(AsnType, Encode, Decode, Debug)]
pub struct PCSKeySet {
    unk1: u32, // 0
    keyset: SetOf<PCSShareKey>,
    #[rasn(tag(explicit(context, 0)))]
    attributes: Option<SequenceOf<PCSAttribute>>,
}

#[derive(Clone)]
pub struct PCSKey(Vec<u8>);
impl PCSKey {
    fn new(eckey: &CompactECKey<Private>, wrapped: &[u8]) -> Result<Self, PushError> {
        Ok(Self(rfc6637_unwrap_key(
            eckey,
            &wrapped,
            "fingerprint".as_bytes(),
        )?))
    }

    fn wrap<T: HasPublic>(&self, key: &CompactECKey<T>) -> Result<Vec<u8>, PushError> {
        rfc6637_wrap_key(key, &self.0, "fingerprint".as_bytes())
    }

    pub fn random() -> Self {
        Self(rand::random::<[u8; 16]>().to_vec())
    }

    // AKA object key
    fn master_ec_key(&self) -> Result<EcKey<Private>, PushError> {
        let mut ctx = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut output = [0u8; 128];
        pbkdf2_hmac(
            &self.0,
            "full master key".as_bytes(),
            10,
            MessageDigest::sha256(),
            &mut output,
        )?;

        // we need big endian for OpenSSL, yes the output is used as little endian
        output.reverse();

        let mut order = BigNum::new()?;
        group.order(&mut order, &mut ctx)?;

        let mut num = BigNum::from_slice(&output)?;
        num.mask_bits(order.num_bits())?;

        let num = if num > order {
            let mut out = BigNum::new()?;
            out.checked_sub(&num, &order)?;
            out
        } else {
            num
        };

        let mut pub_point = EcPoint::new(&group)?;
        pub_point.mul_generator(&group, &num, &ctx)?;
        Ok(EcKey::from_private_components(&group, &num, &pub_point)?)
    }

    pub fn get_share_key(&self, is_share: bool) -> Self {
        if is_share {
            Self(kdf_ctr_hmac(
                &self.0,
                "MsaeEooevaX fooo 012".as_bytes(),
                &[],
                self.0.len(),
            ))
        } else {
            self.clone()
        }
    }

    fn hmac_sign(&self, data: &[u8]) -> Result<Vec<u8>, PushError> {
        let hmackey = kdf_ctr_hmac(
            &self.0,
            "hmackey-of-masterkey".as_bytes(),
            &[],
            self.0.len(),
        );
        let hmac = PKey::hmac(&hmackey)?;
        Ok(Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&data)?)
    }

    pub fn key_id(&self) -> Result<Vec<u8>, PushError> {
        let label_key = kdf_ctr_hmac(
            &self.0,
            "master key id labell".as_bytes(),
            &[],
            self.0.len(),
        );
        let hmac = PKey::hmac(&label_key)?;
        Ok(Signer::new(MessageDigest::sha256(), &hmac)?
            .sign_oneshot_to_vec("M key input data 2 u".as_bytes())?)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, PushError> {
        let encryption_key = kdf_ctr_hmac(
            &self.0,
            "encryption key key m".as_bytes(),
            &[],
            self.0.len(),
        );

        let (required_key, header_len) = get_ciphertext_key(ciphertext)?;
        let key_id = self.key_id()?;
        if key_id.get(..required_key.len()) != Some(required_key.as_slice()) {
            return Err(PushError::PCSKeyIdMismatch);
        }

        let tag_len = 12;
        let iv = ciphertext
            .get(header_len..header_len + 12)
            .ok_or(PushError::PCSCiphertextMalformed)?;
        let firstaad = ciphertext
            .get(..header_len)
            .ok_or(PushError::PCSCiphertextMalformed)?;
        let gcm = AesGcm::<Aes128, U12, U12>::new_from_slice(&encryption_key)
            .map_err(|_| PushError::BadMsg)?;
        let tag = ciphertext
            .get(header_len + 12..header_len + 12 + tag_len)
            .ok_or(PushError::PCSCiphertextMalformed)?;

        let mut text = ciphertext
            .get(header_len + 12 + tag_len..)
            .ok_or(PushError::PCSCiphertextMalformed)?
            .to_vec();

        gcm.decrypt_in_place_detached(
            Nonce::from_slice(iv),
            &[firstaad, aad].concat(),
            &mut text,
            Tag::from_slice(tag),
        )
        .map_err(|_| PushError::PCSDecryptionFailed)?;
        Ok(text)
    }

    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, PushError> {
        let encryption_key = kdf_ctr_hmac(
            &self.0,
            "encryption key key m".as_bytes(),
            &[],
            self.0.len(),
        );

        let gcm =
            AesGcm::<Aes128, U12, U12>::new(encryption_key[..].try_into().expect("Bad key size!"));

        let key_id = self.key_id()?;
        let header = [&[0x03u8][..], &key_id[0..2], &[0x02], &key_id[2..4]].concat();

        let iv: [u8; 12] = rand::random();

        let mut enc_buffer = plaintext.to_vec();
        let tag = gcm
            .encrypt_in_place_detached(
                &iv.try_into().unwrap(),
                &[&header, aad].concat(),
                &mut enc_buffer,
            )
            .expect("encryption failed");

        let result = [&header[..], &iv, &tag, &enc_buffer].concat();

        Ok(result)
    }
}

pub struct PCSEncryptor {
    pub keys: Vec<PCSKey>,
    pub record_id: RecordIdentifier,
}

impl PCSEncryptor {
    fn key_for_ciphertext(&self, ciphertext: &[u8]) -> Result<&PCSKey, PushError> {
        let (required_key, _) = get_ciphertext_key(ciphertext)?;
        for key in &self.keys {
            let key_id = key.key_id()?;
            if key_id.get(..required_key.len()) == Some(required_key.as_slice()) {
                return Ok(key);
            }
        }
        Err(PushError::PCSKeyIdMismatch)
    }

    /// Validates only the content-free PCS key routing header.
    ///
    /// Semantic decode uses this before the infallible legacy record decoder so
    /// a mismatched key is returned as a typed failure rather than becoming a
    /// panic or being collapsed to an empty field.
    pub fn validate_ciphertext_key(&self, ciphertext: &[u8]) -> Result<(), PushError> {
        self.key_for_ciphertext(ciphertext).map(|_| ())
    }

    pub fn decrypt_data_checked(
        &self,
        ciphertext: &[u8],
        field_name: &str,
    ) -> Result<Vec<u8>, PushError> {
        let zone_name = self
            .record_id
            .zone_identifier
            .as_ref()
            .and_then(|zone| zone.value.as_ref())
            .and_then(|identifier| identifier.name.as_deref())
            .ok_or(PushError::PCSCiphertextMalformed)?;
        let record_name = self
            .record_id
            .value
            .as_ref()
            .and_then(|identifier| identifier.name.as_deref())
            .ok_or(PushError::PCSCiphertextMalformed)?;
        let tag = format!("{zone_name}-{record_name}-{field_name}");
        self.key_for_ciphertext(ciphertext)?
            .decrypt(ciphertext, tag.as_bytes())
    }
}

impl CloudKitEncryptor for PCSEncryptor {
    fn decrypt_data(&self, dec: &[u8], field_name: &str) -> Vec<u8> {
        self.decrypt_data_checked(dec, field_name)
            .unwrap_or_default()
    }

    fn encrypt_data(&self, enc: &[u8], field_name: &str) -> Vec<u8> {
        let tag = format!(
            "{}-{}-{}",
            self.record_id
                .zone_identifier
                .as_ref()
                .unwrap()
                .value
                .as_ref()
                .unwrap()
                .name(),
            self.record_id.value.as_ref().unwrap().name(),
            field_name
        );

        self.keys
            .first()
            .expect("PCS keyset empty?")
            .encrypt(enc, tag.as_bytes())
            .expect("Encryption failed")
    }
}

#[derive(AsnType, Encode, Decode, Debug, Default)]
pub struct PCSShareProtectionSignatureData {
    // 5 is the version. non-exist is 1, 5 is 2, 4 is 3,
    // classic is 2
    // share is 3
    version: u32,
    data: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode, Debug)]
#[rasn(tag(explicit(application, 1)))]
pub struct PCSShareProtection {
    keyset: PCSKeySet,
    #[rasn(tag(explicit(context, 0)))]
    meta: rasn::types::OctetString, // encrypted
    #[rasn(tag(explicit(context, 1)))]
    signature_data: PCSShareProtectionSignatureData, // not sure this should be a sequence, maybe tag should be explicit, not sure
    hmac: rasn::types::OctetString,
    #[rasn(tag(explicit(context, 2)))]
    truncated_key_id: rasn::types::OctetString,
    #[rasn(tag(explicit(context, 3)))]
    signature: Option<PCSSignature>,
    #[rasn(tag(explicit(context, 4)))]
    attributes: Option<SequenceOf<PCSAttribute>>,
}

#[derive(AsnType, Encode, Decode, Default)]
pub struct PCSShareProtectionIdentitiesTag1 {
    unk1: u32,
    unk2: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
pub struct PCSShareProtectionIdentityData {
    unk1: u32,
    keyset: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
#[rasn(tag(explicit(application, 2)))]
pub struct PCSShareProtectionKeySet {
    unk1: String,
    keys: SetOf<PCSPrivateKey>,
    unk2: SetOf<Any>,
    hash: Option<rasn::types::OctetString>,
}

impl PCSShareProtectionKeySet {
    fn make_checksum(&mut self) {
        self.hash = Some(sha256(&rasn::der::encode(self).unwrap()).to_vec().into());
    }

    fn check_checksum(&mut self) -> Result<(), PushError> {
        let checksum = self.hash.take().ok_or(PushError::BadMsg)?;
        let checked = sha256(&rasn::der::encode(&*self).map_err(|_| PushError::BadMsg)?);

        if &checked[..] != &checksum[..] {
            self.hash = Some(checksum);
            return Err(PushError::VerificationFailed);
        }
        self.hash = Some(checksum);
        Ok(())
    }
}

struct PCSDigestData(Vec<u8>);

impl PCSDigestData {
    fn verify(&self, key: &EcKey<impl HasPublic>, sig: &PCSSignature) -> Result<(), PushError> {
        let pkey = PKey::from_ec_key(key.clone())?;
        if !sig.keyid.is_empty()
            && &*sig.keyid != TryInto::<CompactECKey<_>>::try_into(key.clone())?.compress()
        {
            return Err(PushError::VerificationFailed);
        }

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
        verifier.update(&self.0)?;
        if !verifier.verify(&sig.signature)? {
            return Err(PushError::VerificationFailed);
        }

        Ok(())
    }

    fn sign(&self, key: &EcKey<Private>, is_self: bool) -> Result<PCSSignature, PushError> {
        let pkey = PKey::from_ec_key(key.clone())?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
        signer.update(&self.0)?;

        Ok(PCSSignature {
            keyid: if is_self {
                Default::default()
            } else {
                TryInto::<CompactECKey<_>>::try_into(key.clone())?
                    .compress()
                    .to_vec()
                    .into()
            },
            digest: 1,
            signature: signer.sign_to_vec()?.into(),
        })
    }
}

pub struct ParticipantMeta {
    pub share_key: CompactECKey<Public>,
    pub sign_with_private_key: Option<PCSPrivateKey>,
}

#[derive(AsnType, Encode, Decode)]
pub struct PCSShareProtectionIdentities {
    #[rasn(tag(explicit(context, 0)))]
    symm_keys: Option<SetOf<rasn::types::OctetString>>,
    #[rasn(tag(explicit(context, 1)))]
    tag1: PCSShareProtectionIdentitiesTag1,
    #[rasn(tag(explicit(context, 2)))]
    identities: Option<SetOf<PCSShareProtectionIdentityData>>,
}

impl PCSShareProtection {
    fn signature_data(&self) -> Result<PCSObjectSignature, PushError> {
        rasn::der::decode(&self.signature_data.data).map_err(|_| PushError::BadMsg)
    }

    fn digest_data(&self, objsig: &PCSObjectSignature) -> Result<PCSDigestData, PushError> {
        let mut data = [
            &rasn::der::encode(&self.keyset).map_err(|_| PushError::BadMsg)?,
            &self.meta[..],
            &objsig.outer_sign_key_type.to_be_bytes(),
            &objsig.roll_count.to_be_bytes(),
            &objsig.symm_key_count.unwrap_or(0).to_be_bytes(),
            &objsig.public.keytype.to_be_bytes(),
            &objsig.public.pub_key[..],
        ]
        .concat();
        if let Some(attributes) = &objsig.attributes {
            data.extend_from_slice(&rasn::der::encode(attributes).map_err(|_| PushError::BadMsg)?);
        }
        if let Some(ec_key_list) = &objsig.ec_key_list {
            data.extend_from_slice(&rasn::der::encode(ec_key_list).map_err(|_| PushError::BadMsg)?);
        }
        Ok(PCSDigestData(data))
    }

    fn hmac_data(&self) -> Result<Vec<u8>, PushError> {
        Ok([
            &rasn::der::encode(&self.keyset).map_err(|_| PushError::BadMsg)?,
            &self.meta[..],
            &rasn::der::encode(&self.signature_data()?).map_err(|_| PushError::BadMsg)?,
        ]
        .concat())
    }

    pub fn decode_key_public(&self) -> Result<Vec<u8>, PushError> {
        Ok(self
            .keyset
            .keyset
            .first()
            .ok_or_else(share_key_not_found)?
            .decryption_key
            .pub_key
            .to_vec())
    }

    pub fn get_private_key(
        &self,
        keychain: &KeychainClientState,
        service: &PCSService<'_>,
    ) -> Result<PCSPrivateKey, PushError> {
        let keys = self
            .keyset
            .keyset
            .iter()
            .map(|k| Value::String(base64_encode(&k.decryption_key.pub_key)))
            .collect::<Vec<_>>();

        let item = keychain
            .items
            .get(service.zone)
            .ok_or_else(share_key_not_found)?
            .keys
            .values()
            .find(|x| matches!(x.get("acct"), Some(x) if keys.contains(x)))
            .ok_or_else(share_key_not_found)?;
        PCSPrivateKey::try_from_dict(item, keychain)
    }

    pub fn decrypt_with_keychain(
        &self,
        keychain: &KeychainClientState,
        service: &PCSService<'_>,
        custom_signing: bool,
    ) -> Result<(Vec<PCSKey>, Vec<CompactECKey<Private>>), PushError> {
        let decoded = self.get_private_key(keychain, service)?;

        let key = decoded.try_key()?;
        info!("Decoding PCS data with a keychain key");

        let signing = decoded.try_signing_key()?;
        self.decode(&[&key], if custom_signing { Some(&signing) } else { None })
    }

    pub fn to_protection_info(&self, tag: bool) -> Result<ProtectionInfo, PushError> {
        let encoded = rasn::der::encode(self).expect("Failed to encode protection info!");
        Ok(ProtectionInfo {
            protection_info_tag: if tag {
                Some(encode_hex(&sha1(&encoded)).to_uppercase())
            } else {
                None
            },
            protection_info: Some(encoded),
        })
    }

    pub fn get_inner_keys(&self) -> Vec<CompactECKey<Public>> {
        self.signature_data()
            .ok()
            .and_then(|signature| signature.ec_key_list)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|key| decode_compact_public_key(&key.pub_key).ok())
            .collect()
    }

    pub fn get_roll_count(&self) -> u32 {
        self.signature_data()
            .map(|signature| signature.roll_count)
            .unwrap_or_default()
    }

    pub fn try_from_protection_info(info: &ProtectionInfo) -> Result<Self, PushError> {
        rasn::der::decode(info.protection_info()).map_err(|_| PushError::BadMsg)
    }

    pub fn from_protection_info(info: &ProtectionInfo) -> Self {
        Self::try_from_protection_info(info).unwrap_or_else(|_| Self {
            keyset: PCSKeySet {
                unk1: 0,
                keyset: SetOf::new(),
                attributes: None,
            },
            meta: Default::default(),
            signature_data: Default::default(),
            hmac: Default::default(),
            truncated_key_id: Default::default(),
            signature: None,
            attributes: None,
        })
    }

    pub fn create_new(
        me: &CompactECKey<Private>,
        keys: &[CompactECKey<Private>],
        access: &[CompactECKey<impl HasPublic>],
        is_share: bool,
    ) -> Result<Self, PushError> {
        Ok(Self::create(
            me,
            keys,
            access,
            PCSKey::random(),
            Some(me),
            &[],
            None,
            1,
            None,
            is_share,
        )?)
    }

    pub fn get_key_attribute(&self, attr: u32) -> Option<Bytes> {
        self.keyset
            .attributes
            .clone()
            .unwrap_or_default()
            .into_iter()
            .find(|i| i.key == attr)
            .map(|i| i.value)
    }

    pub fn get_encryption_keys(&self) -> Vec<Vec<u8>> {
        self.keyset
            .keyset
            .iter()
            .map(|k| k.decryption_key.pub_key.to_vec())
            .collect()
    }

    pub fn create_participant(
        key: &CompactECKey<impl HasPublic>,
        participant_key: &[CompactECKey<Private>],
        participant_meta: &ParticipantMeta,
    ) -> Result<Self, PushError> {
        Self::create(
            &key,
            participant_key,
            &[] as &[CompactECKey<Private>],
            PCSKey::random(),
            None,
            &[],
            None,
            1,
            Some(participant_meta),
            true,
        )
    }

    // don't put "me" in access
    pub fn create(
        me: &CompactECKey<impl HasPublic>,
        keys: &[CompactECKey<Private>],
        access: &[CompactECKey<impl HasPublic>],
        rm_master_key: PCSKey,
        sign_with_key: Option<&EcKey<Private>>,
        extra_keys: &[PCSKey],
        last_key: Option<PCSKey>,
        roll_count: u32,
        participant_meta: Option<&ParticipantMeta>,
        is_share: bool,
    ) -> Result<Self, PushError> {
        let master_key = rm_master_key.get_share_key(is_share);

        let mut keyset = PCSShareProtectionKeySet {
            unk1: "".to_string(),
            keys: BTreeSet::from_iter(keys.iter().map(|k| PCSPrivateKey::V1 {
                key: k.compress_private().to_vec().into(),
                public: None,
            })),
            unk2: BTreeSet::new(),
            hash: None,
        };
        keyset.make_checksum();

        let identities = PCSShareProtectionIdentities {
            symm_keys: if extra_keys.is_empty() {
                None
            } else {
                Some(extra_keys.iter().map(|i| i.0.clone().into()).collect())
            },
            tag1: Default::default(),
            identities: if keys.is_empty() {
                None
            } else {
                Some(BTreeSet::from_iter([PCSShareProtectionIdentityData {
                    unk1: 0,
                    keyset: rasn::der::encode(&keyset).unwrap().into(),
                }]))
            },
        };

        let encrypted = master_key.encrypt(&rasn::der::encode(&identities).unwrap(), &[])?;

        let mut attributes = vec![];
        if let Some(participant) = participant_meta {
            let pub_key = participant
                .sign_with_private_key
                .as_ref()
                .map(|i| i.signing_key().compress())
                .unwrap_or(me.compress());
            attributes.push(PCSAttribute {
                key: 8,
                value: rasn::der::encode(&PCSKeyRef {
                    keytype: 3,
                    pub_key: pub_key.to_vec().into(),
                })
                .unwrap()
                .into(),
            });
            attributes.push(PCSAttribute {
                key: 9,
                value: rasn::der::encode(&PCSKeyRef {
                    keytype: 3,
                    pub_key: participant.share_key.compress().to_vec().into(),
                })
                .unwrap()
                .into(),
            });
        }

        let mut protection = PCSShareProtection {
            keyset: PCSKeySet {
                unk1: 0,
                keyset: BTreeSet::from_iter(std::iter::once(PCSShareKey {
                    decryption_key: PCSKeyRef {
                        keytype: 3,
                        pub_key: me.compress().to_vec().into(),
                    },
                    ciphertext: rm_master_key.wrap(me)?.into(),
                    flags: None,
                }).chain(access.iter().map(|k| PCSShareKey {
                    decryption_key: PCSKeyRef {
                        keytype: 3,
                        pub_key: k.compress().to_vec().into(),
                    },
                    ciphertext: master_key.wrap(k).expect("Failed to wrap key?").into(),
                    flags: if is_share { Some(1) /* mark as readonly, marks as providing derived master key not rm master key */ } else { None },
                }))),
                attributes: if attributes.is_empty() { None } else { Some(attributes) },
            },
            meta: encrypted.into(),
            signature_data: Default::default(),
            hmac: Default::default(),
            truncated_key_id: master_key.key_id()?[..4].to_vec().into(),
            signature: Default::default(),
            attributes: None,
        };

        let mut num_ctx = BigNumContext::new()?;
        let master_ec_key = rm_master_key.master_ec_key()?;

        let mut signature_attributes = vec![];
        if !extra_keys.is_empty() {
            // add list of key ids
            signature_attributes.push(PCSAttribute {
                key: 5,
                value: rasn::der::encode(
                    &extra_keys
                        .iter()
                        .map(|key| key.key_id().expect("Bad key id??")[..4].to_vec().into())
                        .collect::<Vec<Bytes>>(),
                )
                .unwrap()
                .into(),
            });
        }

        let mut signature = PCSObjectSignature {
            roll_count,
            outer_sign_key_type: if sign_with_key.is_some() { 3 } else { 0 },
            public: PCSKeyRef {
                keytype: 1,
                pub_key: master_ec_key
                    .public_key()
                    .to_bytes(
                        master_ec_key.group(),
                        PointConversionForm::UNCOMPRESSED,
                        &mut num_ctx,
                    )?
                    .into(),
            },
            signature: Default::default(),
            ec_key_list: if keys.is_empty() {
                None
            } else {
                Some(
                    keys.iter()
                        .map(|k| PCSKeyRef {
                            keytype: 3,
                            pub_key: k.compress().to_vec().into(),
                        })
                        .collect(),
                )
            },
            symm_key_count: if extra_keys.is_empty() {
                None
            } else {
                Some(extra_keys.len() as u32)
            },
            signature_2: None,
            attributes: if signature_attributes.is_empty() {
                None
            } else {
                Some(signature_attributes)
            },
        };

        let digest_data = protection.digest_data(&signature)?;
        signature.signature = digest_data.sign(&master_ec_key, true)?;

        if let Some(last_key) = last_key {
            let my_sig = digest_data.sign(&last_key.master_ec_key()?, true)?;
            signature.signature_2 = Some(my_sig);
        }

        protection.signature_data = PCSShareProtectionSignatureData {
            version: if is_share { 4 } else { 5 },
            data: rasn::der::encode(&signature).unwrap().into(),
        };

        let mut attributes = vec![];

        if let Some(share) = participant_meta.and_then(|i| i.sign_with_private_key.as_ref()) {
            let signature = digest_data.sign(&share.signing_key(), false)?;

            attributes.push(PCSAttribute {
                key: 7,
                value: rasn::der::encode(&signature).unwrap().into(),
            });
        }

        if let Some(sign_with_key) = sign_with_key {
            let signature = digest_data.sign(&sign_with_key, false)?;
            protection.signature = Some(signature);
        }

        if !attributes.is_empty() {
            protection.attributes = Some(attributes);
        }

        protection.hmac = master_key.hmac_sign(&protection.hmac_data()?)?.into();

        Ok(protection)
    }

    pub fn get_signer(&self) -> Option<CompactECKey<Public>> {
        self.signature
            .as_ref()
            .and_then(|signature| decode_compact_public_key(&signature.keyid).ok())
    }

    pub fn decode(
        &self,
        keys: &[impl Borrow<CompactECKey<Private>>],
        custom_signing_key: Option<&CompactECKey<impl HasPublic>>,
    ) -> Result<(Vec<PCSKey>, Vec<CompactECKey<Private>>), PushError> {
        info!("Decoding share protection!");
        let (key, share_key) = keys
            .iter()
            .find_map(|key| {
                let search_ref = key.borrow().compress();
                let other = self
                    .keyset
                    .keyset
                    .iter()
                    .find(|key| &*key.decryption_key.pub_key == &search_ref[..]);
                other.map(|other| (key.borrow(), other))
            })
            .ok_or_else(share_key_not_found)?;
        let rm_master_key = PCSKey::new(key, &share_key.ciphertext)?;
        let share_flags = share_key.flags.unwrap_or_default();
        let readonly = (share_flags & 1) != 0;

        let sig = self.signature_data()?;

        let digest_data = self.digest_data(&sig)?;

        info!("showed me off");

        // custom_signing_key is kind of reused here,
        // signature is not set when [4] (owner sign attr 7) is set. But sometimes we need a custom sig here.
        if let Some(sig) = &self.signature {
            if let Some(mine) = custom_signing_key {
                digest_data.verify(mine, sig)?;
            } else {
                digest_data.verify(key, sig)?;
            }
        }

        if !readonly {
            let key = &rm_master_key.master_ec_key()?;
            match digest_data.verify(key, &sig.signature) {
                Err(PushError::VerificationFailed) => {
                    info!("First verification failed, using backup!");
                    if let Some(past_signature) = &sig.signature_2 {
                        digest_data.verify(key, &past_signature)?;
                    } else {
                        return Err(PushError::VerificationFailed);
                    }
                }
                _e => _e?,
            }
        }

        info!("come");

        let owner_sign = self
            .attributes
            .clone()
            .unwrap_or_default()
            .into_iter()
            .find(|a| a.key == 7);
        if let (Some(signing), Some(review)) = (custom_signing_key, owner_sign) {
            let parsed: PCSSignature =
                rasn::der::decode(&review.value).map_err(|_| PushError::BadMsg)?;
            digest_data.verify(signing, &parsed)?;
        }

        let mut master_key = rm_master_key.clone();
        if self.signature_data.version != 5 && !readonly {
            master_key = rm_master_key.get_share_key(true);
        }

        let master_key_id = master_key.key_id()?;
        let expected_key_id = master_key_id.get(..4).ok_or(PushError::BadMsg)?;
        if expected_key_id != self.truncated_key_id.as_ref() {
            return Err(PushError::VerificationFailed);
        }

        if &master_key.hmac_sign(&self.hmac_data()?)? != &self.hmac {
            return Err(PushError::VerificationFailed);
        }

        let decrypted = master_key.decrypt(&self.meta, &[])?;

        info!("here");

        let identities: PCSShareProtectionIdentities =
            rasn::der::decode(&decrypted).map_err(|_| PushError::BadMsg)?;

        let mut keys = vec![];
        for identity in identities.identities.as_ref().unwrap_or(&SetOf::new()) {
            let mut identity: PCSShareProtectionKeySet =
                rasn::der::decode(&identity.keyset).map_err(|_| PushError::BadMsg)?;
            identity.check_checksum()?;

            for key in &identity.keys {
                keys.push(key.try_key()?);
            }
        }

        let mut pcs_keys = vec![master_key];
        pcs_keys.extend(
            identities
                .symm_keys
                .unwrap_or_default()
                .into_iter()
                .map(|symm| PCSKey(symm.to_vec())),
        );

        Ok((pcs_keys, keys))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        require_existing_service_key_dict, share_key_not_found, PCSDigestData, PCSEncryptor,
        PCSKey, PCSService, PCSShareProtection, PCSShareProtectionKeySet, PCSSignature,
        MASTER_SERVICE,
    };
    use crate::{
        cloudkit::{public_zone, record_identifier},
        keychain::SavedKeychainZone,
        util::{encode_hex, CompactECKey},
        PushError,
    };
    use cloudkit_proto::{CloudKitEncryptor, ProtectionInfo};
    use openssl::pkey::{Private, Public};
    use std::collections::BTreeSet;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn assert_content_free(error: &PushError, sentinels: &[&str]) {
        let formatted = format!("{error:?} {error}");
        for sentinel in sentinels {
            assert!(
                !formatted.contains(sentinel),
                "loggable error exposed sentinel material"
            );
        }
    }

    #[test]
    fn lookup_only_master_key_missing_state_is_typed_and_non_creating() {
        let error =
            require_existing_service_key_dict(None, &MASTER_SERVICE, PushError::MasterKeyNotFound)
                .unwrap_err();

        assert!(matches!(error, PushError::MasterKeyNotFound));
    }

    #[test]
    fn lookup_only_service_key_missing_state_is_typed_and_non_creating() {
        let sentinel_service = "SENTINEL_SHARE_KEY_ID_DO_NOT_EXPOSE";
        let service = PCSService {
            name: sentinel_service,
            view_hint: "Messages",
            zone: "chatManateeZone",
            r#type: 4,
            keychain_type: 4,
            v2: true,
            global_record: false,
        };
        let empty_zone = SavedKeychainZone::default();
        let checked = catch_unwind(AssertUnwindSafe(|| {
            require_existing_service_key_dict(Some(&empty_zone), &service, share_key_not_found())
        }));
        let error = checked
            .expect("missing lookup-only PCS service key must not panic")
            .unwrap_err();

        assert!(matches!(
            error,
            PushError::ShareKeyNotFound(ref name) if name == "unavailable"
        ));
        assert_content_free(&error, &[sentinel_service]);
    }

    #[test]
    fn digest_signature_key_mismatch_is_typed_content_free_and_never_panics() {
        let sentinel_key_id = "SENTINEL_SIGNATURE_KEY_ID_DO_NOT_EXPOSE";
        let key = CompactECKey::new().unwrap();
        let public_key = encode_hex(&key.public_key_to_der().unwrap());
        let signature = PCSSignature {
            keyid: sentinel_key_id.as_bytes().to_vec().into(),
            digest: 1,
            signature: vec![0xA5; 64].into(),
        };

        let checked = catch_unwind(AssertUnwindSafe(|| {
            PCSDigestData(b"sentinel digest fixture".to_vec()).verify(&key, &signature)
        }));
        let error = checked
            .expect("signature key mismatch must return rather than panic")
            .unwrap_err();

        assert!(matches!(error, PushError::VerificationFailed));
        assert_content_free(&error, &[sentinel_key_id, &public_key]);
    }

    #[test]
    fn truncated_zone_key_mismatch_is_typed_content_free_and_never_panics() {
        let sentinel_key_id = "SENTINEL_TRUNCATED_KEY_ID_DO_NOT_EXPOSE";
        let key = CompactECKey::new().unwrap();
        let mut protection = PCSShareProtection::create_new(
            &key,
            &[] as &[CompactECKey<Private>],
            &[] as &[CompactECKey<Private>],
            false,
        )
        .unwrap();
        protection.truncated_key_id = sentinel_key_id.as_bytes().to_vec().into();

        let checked = catch_unwind(AssertUnwindSafe(|| {
            protection.decode(&[&key], None::<&CompactECKey<Public>>)
        }));
        let error = match checked.expect("truncated PCS key mismatch must return rather than panic")
        {
            Err(error) => error,
            Ok(_) => panic!("truncated PCS key mismatch unexpectedly decoded"),
        };

        assert!(matches!(error, PushError::VerificationFailed));
        assert_content_free(&error, &[sentinel_key_id]);
    }

    #[test]
    fn malformed_signature_data_is_typed_content_free_and_never_panics() {
        let sentinel_signature = "SENTINEL_SIGNATURE_BYTES_DO_NOT_EXPOSE";
        let key = CompactECKey::new().unwrap();
        let mut protection = PCSShareProtection::create_new(
            &key,
            &[] as &[CompactECKey<Private>],
            &[] as &[CompactECKey<Private>],
            false,
        )
        .unwrap();
        protection.signature_data.data = sentinel_signature.as_bytes().to_vec().into();

        let checked = catch_unwind(AssertUnwindSafe(|| {
            protection.decode(&[&key], None::<&CompactECKey<Public>>)
        }));
        let error =
            match checked.expect("malformed PCS signature data must return rather than panic") {
                Err(error) => error,
                Ok(_) => panic!("malformed PCS signature data unexpectedly decoded"),
            };

        assert!(matches!(error, PushError::BadMsg));
        assert_content_free(&error, &[sentinel_signature]);
    }

    #[test]
    fn malformed_zone_protection_is_typed_content_free_and_never_panics() {
        let sentinel_protection = "SENTINEL_ZONE_PROTECTION_BYTES_DO_NOT_EXPOSE";
        let info = ProtectionInfo {
            protection_info: Some(sentinel_protection.as_bytes().to_vec()),
            protection_info_tag: Some("SENTINEL_PROTECTION_TAG".to_string()),
        };

        let checked = catch_unwind(AssertUnwindSafe(|| {
            PCSShareProtection::try_from_protection_info(&info)
        }));
        let error = checked
            .expect("malformed zone protection must return rather than panic")
            .unwrap_err();

        assert!(matches!(error, PushError::BadMsg));
        assert_content_free(&error, &[sentinel_protection, "SENTINEL_PROTECTION_TAG"]);

        let compatibility = catch_unwind(AssertUnwindSafe(|| {
            let protection = PCSShareProtection::from_protection_info(&info);
            let key = CompactECKey::new().unwrap();
            protection.decode(&[&key], None::<&CompactECKey<Public>>)
        }));
        let compatibility_error =
            match compatibility.expect("legacy protection adapter must not panic") {
                Err(error) => error,
                Ok(_) => panic!("legacy protection adapter unexpectedly decoded"),
            };
        assert!(matches!(
            compatibility_error,
            PushError::ShareKeyNotFound(ref label) if label == "unavailable"
        ));
        assert_content_free(&compatibility_error, &[sentinel_protection]);
    }

    #[test]
    fn missing_share_key_is_typed_content_free_and_never_panics() {
        let owner = CompactECKey::new().unwrap();
        let foreign = CompactECKey::new().unwrap();
        let protection = PCSShareProtection::create_new(
            &owner,
            &[] as &[CompactECKey<Private>],
            &[] as &[CompactECKey<Private>],
            false,
        )
        .unwrap();
        let sentinel_public_key = encode_hex(&protection.decode_key_public().unwrap());

        let checked = catch_unwind(AssertUnwindSafe(|| {
            protection.decode(&[&foreign], None::<&CompactECKey<Public>>)
        }));
        let error = match checked.expect("missing share key must return rather than panic") {
            Err(error) => error,
            Ok(_) => panic!("missing share key unexpectedly decoded"),
        };

        assert!(matches!(
            error,
            PushError::ShareKeyNotFound(ref label) if label == "unavailable"
        ));
        assert_content_free(&error, &[&sentinel_public_key]);
    }

    #[test]
    fn malformed_identity_checksum_is_typed_content_free_and_never_panics() {
        let sentinel_checksum = "SENTINEL_CHECKSUM_BYTES_DO_NOT_EXPOSE";
        let mut keyset = PCSShareProtectionKeySet {
            unk1: String::new(),
            keys: BTreeSet::new(),
            unk2: BTreeSet::new(),
            hash: Some(sentinel_checksum.as_bytes().to_vec().into()),
        };

        let checked = catch_unwind(AssertUnwindSafe(|| keyset.check_checksum()));
        let error = checked
            .expect("bad PCS identity checksum must return rather than panic")
            .unwrap_err();

        assert!(matches!(error, PushError::VerificationFailed));
        assert_content_free(&error, &[sentinel_checksum]);
    }

    #[test]
    fn ciphertext_key_mismatch_is_typed_content_free_and_never_panics() {
        let sentinel_message = "SENTINEL_MESSAGE_TEXT_DO_NOT_EXPOSE";
        let sentinel_dsid = "SENTINEL_DSID_123456789";
        let sentinel_token = "SENTINEL_CHANGE_TOKEN";
        let sentinel_peer_id = "SENTINEL_PEER_ID";
        let sentinel_key_id = "feedfacecafebeef";
        let sentinel_key_bytes = "00112233445566778899aabbccddeeff";
        let sentinel_ciphertext_bytes = "030102020304";

        let encryptor = PCSEncryptor {
            keys: vec![PCSKey(vec![0xAA; 16])],
            record_id: record_identifier(public_zone(), "sentinel-record"),
        };
        let mut ciphertext = vec![0x03, 0x01, 0x02, 0x02, 0x03, 0x04];
        ciphertext.resize(42, 0);

        let checked = catch_unwind(AssertUnwindSafe(|| {
            encryptor.decrypt_data_checked(&ciphertext, "sentinel-field")
        }));
        let error = checked
            .expect("PCS mismatch must return rather than panic")
            .expect_err("a foreign key identifier must be rejected");
        assert!(matches!(error, PushError::PCSKeyIdMismatch));

        let legacy = catch_unwind(AssertUnwindSafe(|| {
            encryptor.decrypt_data(&ciphertext, "sentinel-field")
        }));
        assert_eq!(
            legacy.expect("legacy trait adapter must not panic"),
            Vec::<u8>::new()
        );

        let formatted = format!("{error:?} {error}");
        for sentinel in [
            sentinel_message,
            sentinel_dsid,
            sentinel_token,
            sentinel_peer_id,
            sentinel_key_id,
            sentinel_key_bytes,
            sentinel_ciphertext_bytes,
        ] {
            assert!(!formatted.contains(sentinel));
        }
    }
}

#[derive(AsnType, Encode, Decode)]
pub struct PCSObjectSignature {
    roll_count: u32,
    // this is a guess, it tracks with the heuristics i've collected
    // but i don't know.
    outer_sign_key_type: u32,
    public: PCSKeyRef,
    signature: PCSSignature,
    // the ignore fields show up in weird situations, when there are multiple keys?
    #[rasn(tag(explicit(context, 0)))]
    symm_key_count: Option<u32>,
    #[rasn(tag(explicit(context, 1)))]
    signature_2: Option<PCSSignature>,
    #[rasn(tag(explicit(context, 2)))]
    ec_key_list: Option<SequenceOf<PCSKeyRef>>,
    #[rasn(tag(explicit(context, 3)))]
    attributes: Option<SequenceOf<PCSAttribute>>,
}
