use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io::{Cursor, ErrorKind, Read, Write},
    marker::PhantomData,
    ops::{ControlFlow, Deref},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    aps::APSInterestToken,
    cloudkit_operation_gate::{
        cloudkit_writer_operation_is_held, try_acquire_cloudkit_operation,
        CloudKitReadAuthenticationPermit,
    },
    util::{
        bin_deserialize, bin_serialize, proto_deserialize, proto_deserialize_opt, proto_serialize,
        proto_serialize_opt, DebugMutex, DebugRwLock,
    },
    APSConnection, APSMessage,
};

use crate::{
    auth::{MobileMeDelegateResponse, TokenProvider},
    keychain::KeychainClient,
    mmcs::{
        get_headers, get_mmcs, put_authorize_body, put_mmcs, AuthorizedOperation, MMCSConfig,
        PreparedPut,
    },
    mmcsp::FordChunk,
    pcs::{
        PCSEncryptor, PCSKey, PCSKeyRef, PCSPrivateKey, PCSService, PCSShareProtection,
        ParticipantMeta,
    },
    prepare_put,
    util::{
        base64_decode, base64_encode, base64_encode_url, decode_hex, decode_uleb128, encode_hex,
        encode_uleb128, gzip_normal, kdf_ctr_hmac, rfc6637_unwrap_key, CompactECKey, REQWEST,
        REQWEST_NO_REDIRECT,
    },
    CloudKitProtocolError, FileContainer, OSConfig, PushError,
};
use aes::{
    cipher::consts::{U12, U16},
    Aes128, Aes256,
};
use aes_gcm::KeyInit;
use aes_gcm::{aead::Aead, AesGcm, Nonce, Tag};
use aes_siv::siv::CmacSiv;
use cloudkit_derive::CloudKitRecord;
use cloudkit_proto::CloudKitEncryptor;
use cloudkit_proto::{
    identifier,
    participant::ContactInformation,
    record::{self, StableUrl},
    request_operation::header::{Database, IsolationLevel},
    retrieve_changes_response::RecordChange,
    retrieve_zone_changes_response::ChangedZone,
    AssetGetResponse, AssetsToDownload, CloudKitRecord, CreateSubscriptionRequest, Identifier,
    Invitation, Participant, ProtectionInfo, Record, RecordIdentifier, RecordZoneIdentifier,
    ResolveTokenRequest, ResolveTokenResponse, ResponseOperation, ShareAcceptRequest,
    ShareDeclineRequest, ShareIdentifier, ShareInfo, Subscription, SubscriptionNotification,
    TokenRegistration, TokenRegistrationRequest, User, UserAlias, UserAliasType, UserQueryRequest,
    Zone,
};
use hkdf::Hkdf;
use log::{info, warn};
use omnisette::{AnisetteProvider, ArcAnisetteClient};
use openssl::{
    bn::{BigNum, BigNumContext},
    conf,
    ec::{EcGroup, EcKey, EcPoint},
    hash::MessageDigest,
    nid::Nid,
    pkcs5::pbkdf2_hmac,
    pkey::{HasPublic, PKey, Private, Public},
    sha::{sha1, sha256},
    sign::{Signer, Verifier},
};
use plist::Value;
use prost::Message;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    RequestBuilder, Url,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::str::FromStr;
use uuid::Uuid;

#[cfg(test)]
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;

const CLOUDKIT_MAX_RESPONSE_FRAME_BYTES: usize = 128 * 1024 * 1024;
const CLOUDKIT_MAX_RESPONSE_BODY_BYTES: usize = 256 * 1024 * 1024;
const CLOUDKIT_MAX_RECORD_CHANGE_BYTES: usize = 8 * 1024 * 1024;
const CLOUDKIT_MAX_RECORD_CHANGE_PAGE_BYTES: usize = 24 * 1024 * 1024;

enum CloudKitHttpResponse {
    Reqwest(reqwest::Response),
    #[cfg(test)]
    Buffered(CloudKitBufferedResponse),
}

impl CloudKitHttpResponse {
    fn status(&self) -> reqwest::StatusCode {
        match self {
            Self::Reqwest(response) => response.status(),
            #[cfg(test)]
            Self::Buffered(response) => response.status,
        }
    }

    fn headers(&self) -> &HeaderMap {
        match self {
            Self::Reqwest(response) => response.headers(),
            #[cfg(test)]
            Self::Buffered(response) => &response.headers,
        }
    }
}

#[cfg(test)]
pub(crate) struct CloudKitBufferedResponse {
    pub(crate) status: reqwest::StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

#[cfg(test)]
type CloudKitTestTransportFuture =
    Pin<Box<dyn Future<Output = Result<CloudKitBufferedResponse, PushError>> + Send + 'static>>;

#[cfg(test)]
pub(crate) trait CloudKitTestHttpTransport: Send + Sync {
    fn send(&self, request: RequestBuilder) -> CloudKitTestTransportFuture;
}

#[cfg(test)]
impl<F> CloudKitTestHttpTransport for F
where
    F: Fn(RequestBuilder) -> CloudKitTestTransportFuture + Send + Sync,
{
    fn send(&self, request: RequestBuilder) -> CloudKitTestTransportFuture {
        self(request)
    }
}

#[cfg(test)]
tokio::task_local! {
    static CLOUDKIT_TEST_HTTP_TRANSPORT: Arc<dyn CloudKitTestHttpTransport>;
    static CLOUDKIT_TEST_WARM_AUTHENTICATION: ();
}

#[cfg(test)]
pub(crate) async fn with_cloudkit_test_transport<F, R>(
    transport: Arc<dyn CloudKitTestHttpTransport>,
    future: F,
) -> R
where
    F: Future<Output = R>,
{
    CLOUDKIT_TEST_WARM_AUTHENTICATION
        .scope((), CLOUDKIT_TEST_HTTP_TRANSPORT.scope(transport, future))
        .await
}

async fn send_cloudkit_http_request(
    request: RequestBuilder,
) -> Result<CloudKitHttpResponse, PushError> {
    #[cfg(test)]
    if let Ok(transport) = CLOUDKIT_TEST_HTTP_TRANSPORT.try_with(Arc::clone) {
        return transport
            .send(request)
            .await
            .map(CloudKitHttpResponse::Buffered);
    }

    Ok(CloudKitHttpResponse::Reqwest(request.send().await?))
}

fn cloudkit_protocol_error(message: &'static str) -> PushError {
    PushError::IoError(std::io::Error::new(ErrorKind::InvalidData, message))
}

fn cloudkit_zone_name(zone_id: &RecordZoneIdentifier) -> Result<String, PushError> {
    zone_id
        .value
        .as_ref()
        .and_then(|identifier| identifier.name.as_deref())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| cloudkit_protocol_error("CloudKit zone identifier name was missing"))
}

fn cloudkit_invalid_input(message: &'static str) -> PushError {
    PushError::IoError(std::io::Error::new(ErrorKind::InvalidInput, message))
}

fn ensure_cloudkit_continuation_progress(
    complete: bool,
    requested_token: Option<&[u8]>,
    next_token: Option<&[u8]>,
) -> Result<(), PushError> {
    if !complete {
        let Some(next_token) = next_token else {
            return Err(CloudKitProtocolError::ContinuationTokenNoProgress.into());
        };
        if Some(next_token) == requested_token {
            return Err(CloudKitProtocolError::ContinuationTokenNoProgress.into());
        }
    }
    Ok(())
}

fn remember_incomplete_continuation_token(
    complete: bool,
    next_token: Option<&[u8]>,
    seen_token_digests: &mut HashSet<[u8; 32]>,
) -> Result<(), PushError> {
    if complete {
        return Ok(());
    }
    let Some(next_token) = next_token else {
        return Err(CloudKitProtocolError::ContinuationTokenNoProgress.into());
    };
    if !seen_token_digests.insert(sha256(next_token)) {
        return Err(CloudKitProtocolError::ContinuationTokenNoProgress.into());
    }
    Ok(())
}

fn validate_record_change_page_size(
    changes: &[RecordChange],
    requested_max_changes: u32,
) -> Result<(), PushError> {
    let maximum_changes = requested_max_changes.clamp(1, CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE);
    if changes.len() > maximum_changes as usize {
        return Err(cloudkit_protocol_error(
            "CloudKit record page exceeded the requested change limit",
        ));
    }

    let mut aggregate_bytes = 0usize;
    for change in changes {
        let encoded_bytes = change.encoded_len();
        if encoded_bytes > CLOUDKIT_MAX_RECORD_CHANGE_BYTES {
            return Err(cloudkit_protocol_error(
                "CloudKit record change exceeded the safety limit",
            ));
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(encoded_bytes)
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| cloudkit_protocol_error("CloudKit record page size overflow"))?;
        if aggregate_bytes > CLOUDKIT_MAX_RECORD_CHANGE_PAGE_BYTES {
            return Err(cloudkit_protocol_error(
                "CloudKit record page exceeded the safety limit",
            ));
        }
    }
    Ok(())
}

fn undelimit_response(resp: &[u8]) -> Result<Vec<Vec<u8>>, PushError> {
    let mut cursor = Cursor::new(resp);
    let mut response: Vec<Vec<u8>> = vec![];
    while (cursor.position() as usize) < resp.len() {
        let length = usize::try_from(decode_uleb128(&mut cursor)?)
            .map_err(|_| cloudkit_protocol_error("CloudKit response frame length overflow"))?;
        if length > CLOUDKIT_MAX_RESPONSE_FRAME_BYTES {
            return Err(cloudkit_protocol_error(
                "CloudKit response frame exceeded the safety limit",
            ));
        }
        let remaining = resp.len().saturating_sub(cursor.position() as usize);
        if length > remaining {
            return Err(cloudkit_protocol_error(
                "CloudKit response frame was truncated",
            ));
        }
        let mut data = vec![0u8; length];
        cursor.read_exact(&mut data)?;
        response.push(data);
    }
    Ok(response)
}

pub fn contact_info_to_handle(info: &ContactInformation) -> Option<String> {
    Some(match info {
        ContactInformation {
            email_address: Some(email),
            ..
        } => format!("mailto:{email}"),
        ContactInformation {
            phone_number: Some(phone_number),
            ..
        } => format!("tel:+{phone_number}"),
        _ => return None,
    })
}

fn handle_to_contact(handle: &str) -> ContactInformation {
    if handle.starts_with("mailto:") {
        let email = handle.replacen("mailto:", "", 1);
        ContactInformation {
            email_address: Some(email.to_string()),
            ..Default::default()
        }
    } else if handle.starts_with("tel:") {
        let phone_number = handle.replacen("tel:", "", 1).replacen("+", "", 1);
        ContactInformation {
            // yes, phone_number not canonical phone number.
            phone_number: Some(phone_number.clone()),
            ..Default::default()
        }
    } else {
        panic!("Bad handle {handle}!!");
    }
}

pub fn handle_to_alias(handle: &str) -> UserAlias {
    if handle.starts_with("mailto:") {
        let email = handle.replacen("mailto:", "", 1);
        UserAlias {
            identifier: Some(encode_hex(&sha256(email.as_bytes()))),
            r#type: Some(UserAliasType::HashedEmailType as i32),
        }
    } else if handle.starts_with("tel:") {
        let phone_number = handle.replacen("tel:", "", 1).replacen("+", "", 1);
        UserAlias {
            identifier: Some(encode_hex(&sha256(phone_number.as_bytes()))),
            r#type: Some(UserAliasType::HashedCanonicalPhoneNumber as i32),
        }
    } else {
        panic!("Bad handle {handle}!!");
    }
}

const DEFAULT_ZONE: &str = "_defaultZone";

pub async fn prepare_cloudkit_put(file: impl Read + Send + Sync) -> Result<PreparedPut, PushError> {
    let file_container = FileContainer::new(file);
    Ok(prepare_put(file_container, true, 0x01).await?)
}

pub struct FetchedRecords {
    pub assets: Vec<AssetGetResponse>,
    responses: Vec<ResponseOperation>,
}

impl FetchedRecords {
    pub fn get_record<R: CloudKitRecord>(
        &self,
        record_id: &str,
        key: Option<&PCSZoneConfig>,
    ) -> Result<R, PushError> {
        for response in &self.responses {
            let record = response
                .record_retrieve_response
                .as_ref()
                .and_then(|response| response.record.as_ref())
                .ok_or_else(|| cloudkit_protocol_error("CloudKit record response was missing"))?;
            let response_record_id = record
                .record_identifier
                .as_ref()
                .and_then(|identifier| identifier.value.as_ref())
                .and_then(|identifier| identifier.name.as_deref())
                .filter(|name| !name.is_empty())
                .ok_or_else(|| cloudkit_protocol_error("CloudKit record identity was missing"))?;
            if response_record_id != record_id {
                continue;
            }

            let record_type = record
                .r#type
                .as_ref()
                .and_then(|record_type| record_type.name.as_deref())
                .filter(|name| !name.is_empty())
                .ok_or_else(|| cloudkit_protocol_error("CloudKit record type was missing"))?;
            if record_type != R::record_type() {
                return Err(cloudkit_protocol_error(
                    "CloudKit record type did not match the requested type",
                ));
            }
            let decryptor = key
                .map(|keys| pcs_keys_for_record(record, keys))
                .transpose()?;
            return Ok(R::from_record_encrypted(
                &record.record_field,
                decryptor.as_ref(),
            ));
        }

        Err(cloudkit_protocol_error(
            "CloudKit response did not contain the requested record",
        ))
    }

    pub fn new(records: &[Result<FetchedRecord, PushError>]) -> Self {
        Self {
            assets: records
                .iter()
                .filter_map(|a| a.as_ref().ok())
                .flat_map(|a| &a.assets)
                .cloned()
                .collect(),
            responses: records
                .iter()
                .filter_map(|a| a.as_ref().ok())
                .map(|a| &a.response)
                .cloned()
                .collect(),
        }
    }
}

pub struct CloudKitUploadRequest<T: Read + Send + Sync> {
    pub file: Option<T>,
    pub record_id: String,
    pub field: &'static str,
    pub prepared: PreparedPut,
    pub record_type: &'static str,
}

pub struct CloudKitPreparedAsset<'t> {
    record_id: cloudkit_proto::RecordIdentifier,
    prepared: &'t PreparedPut,
    r#type: String,
    field_name: &'static str,
}

/// Closed audit vocabulary for the native semantic fetch/decode lane.
///
/// `CkAppInit` belongs to explicit authentication bootstrap only. Warm
/// semantic pulls never select it. The remaining variants are the complete
/// CloudKit content/key/trust read allowlist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticReadOperation {
    CkAppInit,
    FetchRecordChanges,
    FetchZone,
    CuttlefishFetchChanges,
    CuttlefishFetchRecoverableTlkShares,
}

impl SemanticReadOperation {
    pub const ALL: [Self; 5] = [
        Self::CkAppInit,
        Self::FetchRecordChanges,
        Self::FetchZone,
        Self::CuttlefishFetchChanges,
        Self::CuttlefishFetchRecoverableTlkShares,
    ];

    pub const fn is_warm_semantic_transport(self) -> bool {
        !matches!(self, Self::CkAppInit)
    }
}

pub trait CloudKitOp {
    type Response;

    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation);
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError>;

    fn flow_control_key() -> &'static str;
    fn operation() -> cloudkit_proto::operation::Type;
    fn locale() -> Option<cloudkit_proto::Locale> {
        None
    }
    fn is_fetch() -> bool {
        false
    }
    fn link() -> &'static str;
    fn tags() -> bool {
        true
    }
    fn provides_assets() -> bool {
        false
    }
    fn is_grouped() -> bool {
        true
    }
    fn is_flow() -> bool {
        true
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::Never
    }
    fn custom_headers(&self) -> HeaderMap {
        HeaderMap::new()
    }
    fn semantic_read_operation(&self) -> Option<SemanticReadOperation> {
        None
    }
}

fn record_semantic_read_operations<Op: CloudKitOp>(
    operations: &[Op],
) -> Result<Vec<SemanticReadOperation>, PushError> {
    operations
        .iter()
        .map(|operation| {
            operation
                .semantic_read_operation()
                .filter(|operation| operation.is_warm_semantic_transport())
                .ok_or(PushError::CloudKitSemanticOperationDenied)
        })
        .collect()
}

fn cloudkit_writer_permit_required<Op: CloudKitOp>(operations: &[Op]) -> bool {
    operations
        .iter()
        .any(|operation| operation.semantic_read_operation().is_none())
}

fn validate_semantic_read_request_operation(
    semantic_operation: SemanticReadOperation,
    link: &str,
    retry_safety: CloudKitRetrySafety,
    operation: &cloudkit_proto::RequestOperation,
) -> Result<&'static str, PushError> {
    if !semantic_operation.is_warm_semantic_transport()
        || retry_safety != CloudKitRetrySafety::ReadOnly
    {
        return Err(PushError::CloudKitSemanticOperationDenied);
    }

    let url = Url::parse(link).map_err(|_| PushError::CloudKitSemanticOperationDenied)?;
    if url.scheme() != "https"
        || url.host_str() != Some("gateway.icloud.com")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PushError::CloudKitSemanticOperationDenied);
    }

    let populated_payloads = [
        operation.zone_save_request.is_some(),
        operation.zone_retrieve_request.is_some(),
        operation.zone_delete_request.is_some(),
        operation.retrieve_zone_changes_request.is_some(),
        operation.record_save_request.is_some(),
        operation.record_retrieve_request.is_some(),
        operation.retrieve_changes_request.is_some(),
        operation.record_delete_request.is_some(),
        operation.resolve_token_request.is_some(),
        operation.query_retrieve_request.is_some(),
        operation.asset_upload_token_retrieve_request.is_some(),
        operation.create_subscription_request.is_some(),
        operation.user_query_request.is_some(),
        operation.share_accept_request.is_some(),
        operation.share_decline_request.is_some(),
        operation.token_registration_request.is_some(),
        operation.token_unregistration_request.is_some(),
        operation.function_invoke_request.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if populated_payloads != 1 {
        return Err(PushError::CloudKitSemanticOperationDenied);
    }

    let operation_type = operation
        .request
        .as_ref()
        .and_then(|request| request.r#type)
        .and_then(|value| cloudkit_proto::operation::Type::try_from(value).ok());
    match semantic_operation {
        SemanticReadOperation::FetchRecordChanges
            if url.path() == "/ckdatabase/api/client/record/sync"
                && operation.retrieve_changes_request.is_some()
                && operation_type
                    == Some(cloudkit_proto::operation::Type::RecordRetrieveChangesType) =>
        {
            Ok("record/sync")
        }
        SemanticReadOperation::FetchZone
            if url.path() == "/ckdatabase/api/client/zone/retrieve"
                && operation.zone_retrieve_request.is_some()
                && operation_type == Some(cloudkit_proto::operation::Type::ZoneRetrieveType) =>
        {
            Ok("zone/retrieve")
        }
        SemanticReadOperation::CuttlefishFetchChanges
            if url.path() == "/ckcoderouter/api/client/code/invoke"
                && operation_type == Some(cloudkit_proto::operation::Type::FunctionInvokeType)
                && matches!(
                    operation.function_invoke_request.as_ref(),
                    Some(function)
                        if function.service.as_deref() == Some("Cuttlefish")
                            && function.name.as_deref() == Some("fetchChanges")
                ) =>
        {
            Ok("Cuttlefish/fetchChanges")
        }
        SemanticReadOperation::CuttlefishFetchRecoverableTlkShares
            if url.path() == "/ckcoderouter/api/client/code/invoke"
                && operation_type == Some(cloudkit_proto::operation::Type::FunctionInvokeType)
                && matches!(
                    operation.function_invoke_request.as_ref(),
                    Some(function)
                        if function.service.as_deref() == Some("Cuttlefish")
                            && function.name.as_deref() == Some("fetchRecoverableTLKShares")
                ) =>
        {
            Ok("Cuttlefish/fetchRecoverableTLKShares")
        }
        _ => Err(PushError::CloudKitSemanticOperationDenied),
    }
}

fn validate_semantic_read_request_headers(
    semantic_operation: SemanticReadOperation,
    headers: &HeaderMap,
) -> Result<(), PushError> {
    const ROUTING_HINT: &str = "x-cloudkit-functionroutinghint";

    let expected_routing_hint = match semantic_operation {
        SemanticReadOperation::FetchRecordChanges | SemanticReadOperation::FetchZone => None,
        SemanticReadOperation::CuttlefishFetchChanges => Some("Cuttlefish/fetchChanges"),
        SemanticReadOperation::CuttlefishFetchRecoverableTlkShares => {
            Some("Cuttlefish/fetchRecoverableTLKShares")
        }
        SemanticReadOperation::CkAppInit => {
            return Err(PushError::CloudKitSemanticOperationDenied);
        }
    };

    match expected_routing_hint {
        None if headers.is_empty() => Ok(()),
        Some(expected)
            if headers.len() == 1
                && headers
                    .get(ROUTING_HINT)
                    .and_then(|value| value.to_str().ok())
                    == Some(expected) =>
        {
            Ok(())
        }
        _ => Err(PushError::CloudKitSemanticOperationDenied),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudKitRetrySafety {
    Never,
    Idempotent,
    ReadOnly,
}

pub const CLOUDKIT_MAX_OPERATIONS_PER_REQUEST: usize = 256;
pub const CLOUDKIT_MAX_ONE_SHOT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE: u32 = 200;
// Private CloudKit wire values observed in Apple-compatible responses. These
// are empirical protocol constants, not values documented by public CloudKit.
const CLOUDKIT_RECORD_CHANGES_REQUEST_ALL: i32 = 3;
const CLOUDKIT_RECORD_CHANGES_STATUS_COMPLETE: i32 = 3;
const CLOUDKIT_ZONE_CHANGES_STATUS_COMPLETE: i32 = 2;
const CLOUDKIT_MAX_LEGACY_SYNC_PAGES: usize = 4096;

#[derive(Clone, Debug)]
pub struct CloudKitRetryPolicy {
    pub max_attempts: usize,
    pub base_delay: Duration,
    pub max_delay: Duration,
    /// The longest server-directed wait performed inside one cancellable call.
    /// Larger Retry-After values are returned intact to the durable caller.
    pub max_server_internal_delay: Duration,
    pub request_timeout: Duration,
}

impl Default for CloudKitRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(30),
            max_server_internal_delay: Duration::from_secs(15 * 60),
            request_timeout: Duration::from_secs(45),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudKitFailureClass {
    Throttled,
    TransientServer,
    Authentication,
    Conflict,
    ResetRequired,
    Permanent,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitRequestIdentity {
    http_request_uuid: String,
    operation_uuids: Vec<String>,
}

impl CloudKitRequestIdentity {
    pub fn new(http_request_uuid: String, operation_uuids: Vec<String>) -> Result<Self, PushError> {
        let identity = Self {
            http_request_uuid,
            operation_uuids,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn generated(operation_count: usize) -> Self {
        Self {
            http_request_uuid: Uuid::new_v4().to_string().to_uppercase(),
            operation_uuids: (0..operation_count)
                .map(|_| Uuid::new_v4().to_string().to_uppercase())
                .collect(),
        }
    }

    fn validate(&self) -> Result<(), PushError> {
        fn is_canonical_uuid(value: &str) -> bool {
            Uuid::parse_str(value)
                .map(|uuid| uuid.to_string().to_uppercase() == value)
                .unwrap_or(false)
        }

        if !is_canonical_uuid(&self.http_request_uuid)
            || self
                .operation_uuids
                .iter()
                .any(|value| !is_canonical_uuid(value))
            || self.operation_uuids.iter().collect::<HashSet<_>>().len()
                != self.operation_uuids.len()
        {
            return Err(cloudkit_invalid_input(
                "CloudKit request identity was malformed or duplicated",
            ));
        }
        Ok(())
    }

    fn validate_operation_count(&self, operation_count: usize) -> Result<(), PushError> {
        self.validate()?;
        if self.operation_uuids.len() != operation_count {
            return Err(cloudkit_invalid_input(
                "CloudKit request identity count did not match operations",
            ));
        }
        Ok(())
    }

    pub fn http_request_uuid(&self) -> &str {
        &self.http_request_uuid
    }

    pub fn operation_uuids(&self) -> &[String] {
        &self.operation_uuids
    }
}

/// Ephemeral credentials prepared before a durable writer records that remote
/// submission has started. This value is intentionally neither serializable
/// nor cloneable and must never cross the protected native boundary.
pub struct CloudKitPreparedAuthentication<T: AnisetteProvider> {
    client: Arc<CloudKitClient<T>>,
    user_id: String,
    bundle_id: String,
    container_id: String,
    database_type: Database,
    cloudkit_token: String,
    anisette_headers: HeaderMap,
}

fn cloudkit_anisette_header_map(
    base_headers: &HashMap<String, String>,
) -> Result<HeaderMap, PushError> {
    let mut headers = HeaderMap::with_capacity(base_headers.len());
    for (name, value) in base_headers {
        let name = HeaderName::from_str(name)
            .map_err(|_| cloudkit_protocol_error("CloudKit Anisette header name was malformed"))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| cloudkit_protocol_error("CloudKit Anisette header value was malformed"))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

fn validate_cloudkit_response_identities(
    request_identity: &CloudKitRequestIdentity,
    response: &[ResponseOperation],
) -> Result<(), PushError> {
    let requested = request_identity
        .operation_uuids()
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut seen = HashSet::with_capacity(response.len());
    for operation_response in response {
        let response_uuid = operation_response
            .response
            .as_ref()
            .and_then(|operation| operation.operation_uuid.as_deref())
            .ok_or_else(|| {
                cloudkit_protocol_error("CloudKit operation response identity was missing")
            })?;
        if !requested.contains(response_uuid) {
            return Err(cloudkit_protocol_error(
                "CloudKit operation response identity was unexpected",
            ));
        }
        if !seen.insert(response_uuid) {
            return Err(cloudkit_protocol_error(
                "CloudKit operation response identity was duplicated",
            ));
        }
    }
    if seen.len() != requested.len() {
        return Err(cloudkit_protocol_error(
            "CloudKit operation response identity was missing",
        ));
    }
    Ok(())
}

fn validate_cloudkit_operation_headers(headers: &HeaderMap) -> Result<(), PushError> {
    const RESERVED_HEADERS: &[&str] = &[
        "x-apple-request-uuid",
        "x-apple-operation-group-id",
        "x-apple-operation-id",
        "x-cloudkit-userid",
        "x-cloudkit-authtoken",
        "x-cloudkit-bundleid",
        "x-cloudkit-containerid",
        "x-cloudkit-databasescope",
        "x-cloudkit-environment",
        "x-mme-client-info",
    ];
    if RESERVED_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return Err(cloudkit_invalid_input(
            "CloudKit operation attempted to override reserved request metadata",
        ));
    }
    Ok(())
}

pub struct CloudKitOperationOutcome<T> {
    pub request_index: usize,
    pub operation_uuid: String,
    pub result: Result<T, PushError>,
    pub retry_after: Option<Duration>,
    pub failure_class: Option<CloudKitFailureClass>,
}

pub struct CloudKitBatchResponse<T> {
    pub request_identity: CloudKitRequestIdentity,
    pub outcomes: Vec<CloudKitOperationOutcome<T>>,
}

#[derive(Debug)]
pub struct CloudKitRequestFailure {
    pub error: PushError,
    pub retry_after: Option<Duration>,
    pub failure_class: Option<CloudKitFailureClass>,
    pub request_identity: Option<CloudKitRequestIdentity>,
    /// True once the one-shot request has entered `reqwest::send`. At that
    /// point a missing or malformed response cannot prove that Apple did not
    /// commit the mutation, so a durable caller must reconcile rather than
    /// replay it as an ordinary failure.
    pub outcome_may_be_committed: bool,
}

impl From<PushError> for CloudKitRequestFailure {
    fn from(error: PushError) -> Self {
        Self {
            error,
            retry_after: None,
            failure_class: None,
            request_identity: None,
            outcome_may_be_committed: false,
        }
    }
}

fn cloudkit_retry_after(result: &cloudkit_proto::response_operation::Result) -> Option<Duration> {
    result
        .error
        .as_ref()
        .and_then(|error| error.retry_after_seconds)
        .filter(|seconds| *seconds > 0)
        .map(|seconds| Duration::from_secs(seconds as u64))
}

pub fn classify_cloudkit_failure(
    result: &cloudkit_proto::response_operation::Result,
) -> CloudKitFailureClass {
    use cloudkit_proto::response_operation::result::error::{client, server};

    let Some(error) = result.error.as_ref() else {
        return CloudKitFailureClass::Unknown;
    };

    if let Some(code) = error.client_error.as_ref().and_then(|error| error.r#type) {
        return match client::Code::try_from(code) {
            Ok(
                client::Code::Throttled | client::Code::OpLockFailure | client::Code::AtomicFailure,
            ) => CloudKitFailureClass::Throttled,
            Ok(client::Code::BadAuthToken | client::Code::NeedsAuthentication) => {
                CloudKitFailureClass::Authentication
            }
            Ok(
                client::Code::StaleRecordUpdate
                | client::Code::Exists
                | client::Code::UniqueFieldFailure,
            ) => CloudKitFailureClass::Conflict,
            Ok(
                client::Code::ResetNeeded
                | client::Code::FullResetNeeded
                | client::Code::UserDeletedDataForZone,
            ) => CloudKitFailureClass::ResetRequired,
            Ok(_) => CloudKitFailureClass::Permanent,
            Err(_) => CloudKitFailureClass::Unknown,
        };
    }

    if let Some(code) = error.server_error.as_ref().and_then(|error| error.r#type) {
        return match server::Code::try_from(code) {
            Ok(
                server::Code::Overloaded
                | server::Code::ContainerUnavailable
                | server::Code::ZoneBusy
                | server::Code::ZoneUnavailable,
            ) => CloudKitFailureClass::TransientServer,
            Ok(_) => CloudKitFailureClass::Permanent,
            Err(_) => CloudKitFailureClass::Unknown,
        };
    }

    CloudKitFailureClass::Unknown
}

pub fn is_retryable_cloudkit_failure(result: &cloudkit_proto::response_operation::Result) -> bool {
    matches!(
        classify_cloudkit_failure(result),
        CloudKitFailureClass::Throttled | CloudKitFailureClass::TransientServer
    )
}

fn redact_cloudkit_result(
    mut result: cloudkit_proto::response_operation::Result,
) -> cloudkit_proto::response_operation::Result {
    if let Some(error) = result.error.as_mut() {
        error.error_description = None;
        error.error_key = None;
        error.error_internal = None;
        if let Some(extension) = error.extension_error.as_mut() {
            extension.extension_name = None;
            extension.extension_payload = None;
        }
    }
    result
}

/// Classifies Apple's Cuttlefish sentinel before free-form descriptions are
/// redacted. Callers receive a typed, content-free signal and never inspect or
/// format the server description themselves.
fn is_change_token_expired_result(result: &cloudkit_proto::response_operation::Result) -> bool {
    result
        .error
        .as_ref()
        .and_then(|error| error.error_description.as_deref())
        == Some(".changeTokenExpired")
}

fn content_safe_cloudkit_error(result: &cloudkit_proto::response_operation::Result) -> PushError {
    if is_change_token_expired_result(result) {
        PushError::CloudKitChangeTokenExpired
    } else {
        PushError::CloudKitError(redact_cloudkit_result(result.clone()))
    }
}

fn parse_retry_after(value: Option<&HeaderValue>) -> Option<Duration> {
    let value = value?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let date = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let remaining = date.signed_duration_since(chrono::Utc::now());
    remaining.to_std().ok()
}

fn classify_cloudkit_http_failure(status: reqwest::StatusCode) -> CloudKitFailureClass {
    match status {
        reqwest::StatusCode::TOO_MANY_REQUESTS => CloudKitFailureClass::Throttled,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            CloudKitFailureClass::Authentication
        }
        reqwest::StatusCode::CONFLICT => CloudKitFailureClass::Conflict,
        reqwest::StatusCode::REQUEST_TIMEOUT => CloudKitFailureClass::TransientServer,
        status if status.is_server_error() => CloudKitFailureClass::TransientServer,
        _ => CloudKitFailureClass::Permanent,
    }
}

fn backoff_cap(policy: &CloudKitRetryPolicy, failure_number: usize) -> Duration {
    let exponent = u32::try_from(failure_number.saturating_sub(1))
        .unwrap_or(u32::MAX)
        .min(31);
    let multiplier = 1u32 << exponent;
    policy
        .base_delay
        .checked_mul(multiplier)
        .unwrap_or(policy.max_delay)
        .min(policy.max_delay)
}

fn retry_delay(
    policy: &CloudKitRetryPolicy,
    failure_number: usize,
    server_hint: Option<Duration>,
) -> Option<Duration> {
    if let Some(server_hint) = server_hint {
        return (server_hint <= policy.max_server_internal_delay).then_some(server_hint);
    }

    let cap = backoff_cap(policy, failure_number);
    let cap_millis = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX);
    if cap_millis == 0 {
        return Some(Duration::ZERO);
    }
    let jitter_millis = if cap_millis == u64::MAX {
        rand::random::<u64>()
    } else {
        rand::random::<u64>() % (cap_millis + 1)
    };
    Some(Duration::from_millis(jitter_millis))
}

async fn read_cloudkit_response_body(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, PushError> {
    if response
        .content_length()
        .is_some_and(|length| length > CLOUDKIT_MAX_RESPONSE_BODY_BYTES as u64)
    {
        return Err(cloudkit_protocol_error(
            "CloudKit response body exceeded the safety limit",
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > CLOUDKIT_MAX_RESPONSE_BODY_BYTES {
            return Err(cloudkit_protocol_error(
                "CloudKit response body exceeded the safety limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_cloudkit_http_response_body(
    response: CloudKitHttpResponse,
) -> Result<Vec<u8>, PushError> {
    match response {
        CloudKitHttpResponse::Reqwest(response) => read_cloudkit_response_body(response).await,
        #[cfg(test)]
        CloudKitHttpResponse::Buffered(response) => {
            if response.body.len() > CLOUDKIT_MAX_RESPONSE_BODY_BYTES {
                return Err(cloudkit_protocol_error(
                    "CloudKit response body exceeded the safety limit",
                ));
            }
            Ok(response.body)
        }
    }
}

fn decode_cloudkit_response_body(body: Vec<u8>) -> Result<Vec<ResponseOperation>, PushError> {
    undelimit_response(&body)?
        .into_iter()
        .map(|frame| Ok(ResponseOperation::decode(&mut Cursor::new(frame))?))
        .collect()
}

/// Awaits one phase of a protected one-shot CloudKit request without extending
/// its total network budget. Callers must reuse the same deadline for every
/// phase after the ambiguity boundary.
async fn within_cloudkit_one_shot_deadline<T, F>(
    deadline: tokio::time::Instant,
    future: F,
    timeout_message: &'static str,
) -> Result<T, PushError>
where
    F: Future<Output = Result<T, PushError>>,
{
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| {
            PushError::IoError(std::io::Error::new(ErrorKind::TimedOut, timeout_message))
        })?
}

pub fn pcs_keys_for_record(
    record: &Record,
    keys: &PCSZoneConfig,
) -> Result<PCSEncryptor, PushError> {
    let record_id = record
        .record_identifier
        .clone()
        .ok_or_else(|| cloudkit_protocol_error("CloudKit PCS record identity was missing"))?;
    let Some(protection) = &record.protection_info else {
        let pcskey = record
            .pcs_key
            .as_ref()
            .filter(|key| !key.is_empty())
            .ok_or(PushError::PCSRecordKeyMissing)?;
        if !keys.default_record_keys.iter().any(|i| {
            i.key_id()
                .ok()
                .and_then(|id| id.get(..pcskey.len()).map(|prefix| prefix == pcskey))
                .unwrap_or(false)
        }) {
            return Err(PushError::PCSRecordKeyMissing);
        }

        return Ok(PCSEncryptor {
            keys: keys.default_record_keys.clone(),
            record_id,
        });
    };
    Ok(PCSEncryptor {
        keys: keys.decode_record_protection(protection)?,
        record_id,
    })
}

pub struct UploadAssetOperation(pub cloudkit_proto::AssetUploadTokenRetrieveRequest);
impl CloudKitOp for UploadAssetOperation {
    type Response = cloudkit_proto::AssetUploadTokenRetrieveResponse;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.asset_upload_token_retrieve_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        response
            .asset_upload_token_retrieve_response
            .clone()
            .ok_or_else(|| cloudkit_protocol_error("CloudKit asset-token response was missing"))
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordsOperation"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::AssetUploadTokenRetrieveType
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/asset/retrieve/token"
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::Idempotent
    }
}

impl UploadAssetOperation {
    fn new(
        assets: Vec<CloudKitPreparedAsset<'_>>,
        mmcs_headers: HashMap<&'static str, String>,
        mmcs_body: Vec<u8>,
    ) -> Self {
        Self(cloudkit_proto::AssetUploadTokenRetrieveRequest {
            asset_upload: assets.iter().map(|CloudKitPreparedAsset { record_id, prepared, r#type, field_name }| {
                cloudkit_proto::asset_upload_token_retrieve_request::AssetUpload {
                    record: Some(record_id.clone()),
                    record_type: Some(cloudkit_proto::record::Type {
                        name: Some(r#type.to_string()),
                    }),
                    asset: Some(cloudkit_proto::asset_upload_token_retrieve_request::asset_upload::Asset {
                        name: Some(cloudkit_proto::asset_upload_token_retrieve_request::asset_upload::Name {
                            name: Some(field_name.to_string()),
                        }),
                        data: Some(cloudkit_proto::AssetUploadData {
                            sig: Some(prepared.total_sig.clone()),
                            size: Some(prepared.total_len as u32),
                            associated_record: Some(record_id.clone()),
                            ford_sig: prepared.ford.as_ref().map(|f| f.0.to_vec()),
                            container: None, // these 3 used during downloads
                            host: None,
                            dsid: None,
                        })
                    })
                }
            }).collect(),
            header: mmcs_headers.iter().map(|(a, b)| cloudkit_proto::NamedHeader { name: Some(a.to_string()), value: Some(b.to_string()) }).collect(),
            authorize_put: Some(mmcs_body.clone()),
            unk1: Some(1),
        })
    }
}

#[derive(Clone)]
pub struct SaveRecordOperation(pub cloudkit_proto::RecordSaveRequest);
impl CloudKitOp for SaveRecordOperation {
    type Response = Option<cloudkit_proto::Record>;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.record_save_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        Ok(response
            .record_save_response
            .as_ref()
            .ok_or_else(|| cloudkit_protocol_error("CloudKit save response was missing"))?
            .server_fields
            .clone())
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordsOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/save"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::RecordSaveType
    }
    fn locale() -> Option<cloudkit_proto::Locale> {
        Some(cloudkit_proto::Locale {
            language_code: Some("en".to_string()),
            region_code: Some("US".to_string()),
            ..Default::default()
        })
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::Idempotent
    }
}

impl SaveRecordOperation {
    // new with a *custom* record protection entry
    pub fn new_protected<R: CloudKitRecord>(
        id: RecordIdentifier,
        record: R,
        key: &PCSZoneConfig,
        update: Option<String>,
    ) -> (Self, String) {
        // create a key for this record
        let record_protection = PCSShareProtection::create_new(
            &key.zone_keys[0],
            &[],
            &[] as &[CompactECKey<Private>],
            false,
        )
        .unwrap();
        let prot = record_protection.to_protection_info(true).unwrap();
        let tag = prot.protection_info_tag.clone().unwrap();
        let protection_info = Some(prot);
        let pcs_key = key
            .decode_record_protection(protection_info.as_ref().unwrap())
            .expect("Failed to decode record protection")
            .remove(0);

        (
            Self(cloudkit_proto::RecordSaveRequest {
                record: Some(cloudkit_proto::Record {
                    record_identifier: Some(id.clone()),
                    r#type: Some(cloudkit_proto::record::Type {
                        name: Some(R::record_type().to_string()),
                    }),
                    record_field: record.to_record_encrypted(Some(&PCSEncryptor {
                        keys: vec![pcs_key],
                        record_id: id.clone(),
                    })),
                    protection_info,
                    ..Default::default()
                }),
                merge: Some(true),
                fields_to_delete_if_exist_on_merge: Vec::new(),
                save_semantics: Some(if update.is_some() { 3 } else { 2 }),
                record_protection_info_tag: update,
                zone_protection_info_tag: key.zone_protection_tag.clone(),
            }),
            tag,
        )
    }

    /// Builds a save operation after validating the PCS material needed by
    /// the generated record. New fail-closed callers should use this method so
    /// a missing default record key becomes a typed error instead of a panic.
    pub fn try_new<R: CloudKitRecord>(
        id: RecordIdentifier,
        record: R,
        key: Option<&PCSZoneConfig>,
        update: bool,
    ) -> Result<Self, PushError> {
        let pcs_key = match key {
            Some(key) => {
                let default_key = key.default_record_keys.first().ok_or_else(|| {
                    cloudkit_invalid_input("CloudKit PCS default record key was missing")
                })?;
                let key_id = default_key.key_id()?;
                if key_id.len() < 4 {
                    return Err(cloudkit_invalid_input(
                        "CloudKit PCS default record key identifier was malformed",
                    ));
                }
                Some(key_id[..4].to_vec())
            }
            None => None,
        };

        Ok(Self(cloudkit_proto::RecordSaveRequest {
            record: Some(cloudkit_proto::Record {
                record_identifier: Some(id.clone()),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some(R::record_type().to_string()),
                }),
                record_field: record.to_record_encrypted(
                    key.map(|k| PCSEncryptor {
                        keys: k.default_record_keys.clone(),
                        record_id: id.clone(),
                    })
                    .as_ref(),
                ),
                pcs_key,
                ..Default::default()
            }),
            merge: Some(true),
            fields_to_delete_if_exist_on_merge: Vec::new(),
            save_semantics: Some(if update { 3 } else { 2 }),
            record_protection_info_tag: key.and_then(|k| k.record_prot_tag.clone()),
            zone_protection_info_tag: key.and_then(|k| k.zone_protection_tag.clone()),
        }))
    }

    /// Compatibility spelling retained for callers that have not adopted the
    /// explicit `try_new` name. It is fallible as well; malformed PCS material
    /// must never terminate the process.
    #[deprecated(note = "use SaveRecordOperation::try_new")]
    pub fn new<R: CloudKitRecord>(
        id: RecordIdentifier,
        record: R,
        key: Option<&PCSZoneConfig>,
        update: bool,
    ) -> Result<Self, PushError> {
        Self::try_new(id, record, key, update)
    }
}

pub struct FetchedRecord {
    pub assets: Vec<AssetGetResponse>,
    response: ResponseOperation,
}

impl FetchedRecord {
    pub fn get_raw_record(&self) -> Result<&Record, PushError> {
        self.response
            .record_retrieve_response
            .as_ref()
            .ok_or_else(|| cloudkit_protocol_error("CloudKit retrieve response was missing"))?
            .record
            .as_ref()
            .ok_or_else(|| cloudkit_protocol_error("CloudKit retrieved record was missing"))
    }

    pub fn get_record<R: CloudKitRecord>(
        &self,
        key: Option<&PCSZoneConfig>,
    ) -> Result<R, PushError> {
        let record = self.get_raw_record()?;

        let record_type = record
            .r#type
            .as_ref()
            .and_then(|record_type| record_type.name.as_deref())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| cloudkit_protocol_error("CloudKit record type was missing"))?;
        if record_type != R::record_type() {
            return Err(cloudkit_protocol_error(
                "CloudKit record type did not match the requested type",
            ));
        }
        let decryptor = key
            .map(|keys| pcs_keys_for_record(record, keys))
            .transpose()?;
        Ok(R::from_record_encrypted(
            &record.record_field,
            decryptor.as_ref(),
        ))
    }

    pub fn get_id(&self) -> Result<String, PushError> {
        self.get_raw_record()?
            .record_identifier
            .as_ref()
            .and_then(|identifier| identifier.value.as_ref())
            .and_then(|identifier| identifier.name.as_deref())
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| cloudkit_protocol_error("CloudKit record identity was missing"))
    }

    /// Proves that a retrieve response belongs to the exact stable record
    /// requested by the caller before any decoded payload is trusted.
    pub fn verify_id(&self, expected_record_id: &str) -> Result<(), PushError> {
        if self.get_id()?.as_str() != expected_record_id {
            return Err(cloudkit_protocol_error(
                "CloudKit record identity did not match the request",
            ));
        }
        Ok(())
    }
}

pub struct FetchRecordOperation(pub cloudkit_proto::RecordRetrieveRequest);
impl CloudKitOp for FetchRecordOperation {
    type Response = FetchedRecord;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.record_retrieve_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        let mut clonedresponse = response.clone();
        if clonedresponse
            .record_retrieve_response
            .as_ref()
            .and_then(|response| response.record.as_ref())
            .is_none()
        {
            return Err(cloudkit_protocol_error(
                "CloudKit record response was missing",
            ));
        }
        Ok(FetchedRecord {
            assets: clonedresponse
                .header
                .take()
                .map(|header| header.bundled)
                .unwrap_or_default(),
            response: clonedresponse,
        })
    }
    fn flow_control_key() -> &'static str {
        "CKDFetchRecordsOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/retrieve"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::RecordRetrieveType
    }
    fn provides_assets() -> bool {
        true
    }
    fn is_grouped() -> bool {
        false
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::ReadOnly
    }
}
impl FetchRecordOperation {
    pub fn new(assets: &cloudkit_proto::AssetsToDownload, record_id: RecordIdentifier) -> Self {
        Self(cloudkit_proto::RecordRetrieveRequest {
            record_identifier: Some(record_id),
            assets_to_download: Some(assets.clone()),
            ..Default::default()
        })
    }

    pub fn many(
        assets: &cloudkit_proto::AssetsToDownload,
        zone: &RecordZoneIdentifier,
        record_ids: &[String],
    ) -> Vec<Self> {
        record_ids
            .iter()
            .map(|record_id| {
                Self(cloudkit_proto::RecordRetrieveRequest {
                    record_identifier: Some(record_identifier(zone.clone(), record_id)),
                    assets_to_download: Some(assets.clone()),
                    ..Default::default()
                })
            })
            .collect()
    }
}

pub struct FetchZoneOperation(pub cloudkit_proto::ZoneRetrieveRequest);
impl CloudKitOp for FetchZoneOperation {
    type Response = cloudkit_proto::zone_retrieve_response::ZoneSummary;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.zone_retrieve_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        response
            .zone_retrieve_response
            .as_ref()
            .and_then(|response| response.zone_summary.first())
            .cloned()
            .ok_or_else(|| cloudkit_protocol_error("CloudKit zone response was missing"))
    }
    fn flow_control_key() -> &'static str {
        "CKDFetchRecordZonesOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/zone/retrieve"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ZoneRetrieveType
    }
    fn is_grouped() -> bool {
        false
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::ReadOnly
    }
    fn semantic_read_operation(&self) -> Option<SemanticReadOperation> {
        Some(SemanticReadOperation::FetchZone)
    }
}
impl FetchZoneOperation {
    pub fn new(id: RecordZoneIdentifier) -> Self {
        Self(cloudkit_proto::ZoneRetrieveRequest {
            zone_identifier: Some(id),
        })
    }
}

pub struct DeleteRecordOperation(pub cloudkit_proto::RecordDeleteRequest);
impl CloudKitOp for DeleteRecordOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.record_delete_request = Some(self.0.clone());
    }
    fn retrieve_response(
        _response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        Ok(())
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordsOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/delete"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::RecordDeleteType
    }
    fn tags() -> bool {
        false
    }
    fn is_grouped() -> bool {
        false
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::Idempotent
    }
}

pub fn get_participant_id(participant: &Participant) -> &str {
    participant
        .participant_id
        .as_ref()
        .expect("No participant iD??")
        .name()
}

pub fn create_share(
    zone: &cloudkit_proto::RecordZoneIdentifier,
    share_id: &str,
    sharer: &PCSPrivateKey,
) -> Result<ShareInfo, PushError> {
    let participant_key = CompactECKey::new()?;
    let self_prot_info = PCSShareProtection::create_participant(
        &sharer.key(),
        &[participant_key.clone()],
        &ParticipantMeta {
            share_key: CompactECKey::decompress(sharer.key().compress()),
            sign_with_private_key: Some(sharer.clone()),
        },
    )?;
    Ok(ShareInfo {
        identifier: Some(ShareIdentifier {
            value: Some(Identifier {
                name: Some(share_id.to_string()),
                r#type: Some(identifier::Type::Share as i32),
            }),
            zone_identifier: Some(zone.clone()),
        }),
        // no clue what this means, is this actually public???
        participants: vec![Participant {
            participant_id: Some(Identifier {
                name: Some(Uuid::new_v4().to_string().to_uppercase()),
                r#type: Some(identifier::Type::User as i32),
            }),
            contact_information: Some(Default::default()),
            // 1 for pending, 2 for accepted
            state: Some(2),
            participant_type: Some(1),
            permission: Some(3),
            created_in_process: Some(true),
            public_key: Some(ProtectionInfo {
                protection_info: Some(sharer.key().compress().to_vec()),
                protection_info_tag: None,
            }),
            protection_info: Some(self_prot_info.to_protection_info(false)?),
            // may be same as PCS type
            public_key_version: Some(211),
            accepted_in_process: Some(false),
            is_org_user: Some(false),
            key_health: Some(1),
            is_annonymous_invited_participant: Some(false),
            is_approved_requestor: Some(false),
            ..Default::default()
        }],
        public_access: Some(1),
        annonymous_public_access: Some(false),
        displayed_hostname: Some("www.icloud.com".to_string()),
        publisher_model_type: Some(1),
        participant_self_removal_behavior: Some(3),
        deny_access_requests: Some(true),
        pcs_invited_keys_to_remove: Some(Default::default()),
        pcs_added_keys_to_remove: Some(Default::default()),
        ..Default::default()
    })
}

impl DeleteRecordOperation {
    pub fn new(record_id: RecordIdentifier) -> Self {
        Self(cloudkit_proto::RecordDeleteRequest {
            record: Some(record_id),
        })
    }
}

pub struct QueryRecordOperation<R>(pub cloudkit_proto::QueryRetrieveRequest, PhantomData<R>);
impl<R: CloudKitRecord> CloudKitOp for QueryRecordOperation<R> {
    type Response = (Vec<QueryResult<R>>, Vec<AssetGetResponse>);
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.query_retrieve_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        let extras = response
            .header
            .clone()
            .map(|header| header.bundled)
            .unwrap_or_default();
        let retrieve = response
            .query_retrieve_response
            .clone()
            .ok_or_else(|| cloudkit_protocol_error("CloudKit query response was missing"))?
            .query_results;

        let records = retrieve
            .into_iter()
            .filter_map(|r| r.record)
            .map(|retrieve| {
                let got_type = retrieve
                    .r#type
                    .and_then(|record_type| record_type.name)
                    .ok_or_else(|| {
                        cloudkit_protocol_error("CloudKit query record type was missing")
                    })?;
                if got_type != R::record_type() {
                    return Err(cloudkit_protocol_error(
                        "CloudKit query returned an unexpected record type",
                    ));
                }

                let record_id = retrieve
                    .record_identifier
                    .and_then(|identifier| identifier.value)
                    .and_then(|identifier| identifier.name)
                    .ok_or_else(|| {
                        cloudkit_protocol_error("CloudKit query record identifier was missing")
                    })?;

                Ok(QueryResult {
                    record_id,
                    result: R::from_record(&retrieve.record_field),
                })
            })
            .collect::<Result<Vec<_>, PushError>>()?;

        Ok((records, extras))
    }
    fn flow_control_key() -> &'static str {
        "CKDQueryOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/query/retrieve"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::QueryRetrieveType
    }
    fn locale() -> Option<cloudkit_proto::Locale> {
        Some(cloudkit_proto::Locale {
            language_code: Some("en".to_string()),
            region_code: Some("US".to_string()),
            ..Default::default()
        })
    }
    fn tags() -> bool {
        false
    }
    fn provides_assets() -> bool {
        true
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::ReadOnly
    }
}
impl<R> QueryRecordOperation<R> {
    pub fn new(
        assets: &cloudkit_proto::AssetsToDownload,
        zone: cloudkit_proto::RecordZoneIdentifier,
        query: cloudkit_proto::Query,
    ) -> Self {
        Self(
            cloudkit_proto::QueryRetrieveRequest {
                query: Some(query),
                zone_identifier: Some(zone.clone()),
                assets_to_download: Some(assets.clone()),
                ..Default::default()
            },
            PhantomData,
        )
    }
}

pub struct FetchRecordChangesOperation(pub cloudkit_proto::RetrieveChangesRequest);
impl CloudKitOp for FetchRecordChangesOperation {
    type Response = (
        Vec<AssetGetResponse>,
        cloudkit_proto::RetrieveChangesResponse,
    );
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.retrieve_changes_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        let extras = response
            .header
            .clone()
            .map(|header| header.bundled)
            .unwrap_or_default();
        Ok((
            extras,
            response.retrieve_changes_response.clone().ok_or_else(|| {
                cloudkit_protocol_error("CloudKit record-changes response was missing")
            })?,
        ))
    }
    fn flow_control_key() -> &'static str {
        "CKDFetchRecordZoneChangesOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/sync"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::RecordRetrieveChangesType
    }
    fn provides_assets() -> bool {
        true
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::ReadOnly
    }
    fn semantic_read_operation(&self) -> Option<SemanticReadOperation> {
        Some(SemanticReadOperation::FetchRecordChanges)
    }
}

pub struct CloudKitRecordChangePage {
    pub assets: Vec<AssetGetResponse>,
    pub changes: Vec<RecordChange>,
    pub next_token: Option<Vec<u8>>,
    pub status: i32,
}

impl CloudKitRecordChangePage {
    pub fn is_complete(&self) -> bool {
        self.status == CLOUDKIT_RECORD_CHANGES_STATUS_COMPLETE
    }
}

#[derive(Serialize, Deserialize)]
pub struct CloudKitChangeNotifCloudkitChange {
    #[serde(rename = "zid")]
    zone_id: String,
    // dbs: u32
    #[serde(rename = "zoid")]
    zone_owner_id: String,
    #[serde(rename = "sid")]
    subscription_id: String,
}

impl CloudKitChangeNotifCloudkitChange {
    fn zone(&self) -> RecordZoneIdentifier {
        cloudkit_proto::RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(self.zone_id.clone()),
                r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into()),
            }),
            owner_identifier: Some(cloudkit_proto::Identifier {
                name: Some(self.zone_owner_id.clone()),
                r#type: Some(cloudkit_proto::identifier::Type::User.into()),
            }),
            environment: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CloudKitChangeNotifCloudkit {
    ckuserid: String,
    #[serde(rename = "nid")]
    notif_id: String,
    #[serde(rename = "cid")]
    container_id: String,
    #[serde(rename = "met", alias = "fet")]
    change: CloudKitChangeNotifCloudkitChange,
}

#[derive(Serialize, Deserialize)]
pub struct CloudKitChangeNotif {
    // also aps: { "content-available": 1 }
    #[serde(rename = "ck")]
    cloudkit: CloudKitChangeNotifCloudkit,
}

pub struct CloudKitNotifWatcher {
    _interest_token: APSInterestToken,
    for_topic: [u8; 20],
    container: String,
    changed_zones: DebugMutex<Vec<RecordZoneIdentifier>>,
    gen: AtomicU64,
}

impl CloudKitNotifWatcher {
    pub async fn handle(&self, msg: &APSMessage) -> Result<Vec<RecordZoneIdentifier>, PushError> {
        let APSMessage::Notification {
            topic,
            payload: Value::Data(payload),
            ..
        } = &msg
        else {
            return Ok(vec![]);
        };
        if topic != &self.for_topic {
            return Ok(vec![]);
        }

        let parsed: CloudKitChangeNotif = serde_json::from_slice(payload)?;
        info!("Received CloudKit change notification");

        if parsed.cloudkit.container_id != self.container {
            return Ok(vec![]);
        }

        let mut changed_zones = self.changed_zones.lock().await;
        let changed_zone = parsed.cloudkit.change.zone();
        if !changed_zones.contains(&changed_zone) {
            changed_zones.push(changed_zone);
        }
        drop(changed_zones);

        let mine = self.gen.fetch_add(1, Ordering::SeqCst) + 1;
        tokio::time::sleep(Duration::from_secs(10)).await;

        if self.gen.load(Ordering::SeqCst) != mine {
            return Ok(vec![]);
        }

        let mut changed_zones = self.changed_zones.lock().await;

        Ok(std::mem::take(&mut *changed_zones))
    }
}

pub const ALL_ASSETS: AssetsToDownload = AssetsToDownload {
    all_assets: Some(true),
    asset_fields: None,
};

pub const NO_ASSETS: AssetsToDownload = AssetsToDownload {
    all_assets: Some(false),
    asset_fields: None,
};

impl FetchRecordChangesOperation {
    pub fn new(
        zone: cloudkit_proto::RecordZoneIdentifier,
        continuation_token: Option<Vec<u8>>,
        assets: &cloudkit_proto::AssetsToDownload,
    ) -> Self {
        Self::new_with_limit(
            zone,
            continuation_token,
            assets,
            CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE,
        )
    }

    pub fn new_with_limit(
        zone: cloudkit_proto::RecordZoneIdentifier,
        continuation_token: Option<Vec<u8>>,
        assets: &cloudkit_proto::AssetsToDownload,
        max_changes: u32,
    ) -> Self {
        Self(cloudkit_proto::RetrieveChangesRequest {
            sync_continuation_token: continuation_token,
            zone_identifier: Some(zone),
            requested_fields: None,
            max_changes: Some(max_changes.clamp(1, CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE)),
            requested_changes_types: Some(CLOUDKIT_RECORD_CHANGES_REQUEST_ALL),
            assets_to_download: Some(assets.clone()),
            newest_first: Some(false),
            ignore_calling_device_changes: None,
            include_mergeable_deltas: None,
        })
    }

    pub async fn fetch_page(
        container: &CloudKitOpenContainer<'_, impl AnisetteProvider>,
        zone: cloudkit_proto::RecordZoneIdentifier,
        continuation_token: Option<Vec<u8>>,
        assets: &cloudkit_proto::AssetsToDownload,
    ) -> Result<CloudKitRecordChangePage, PushError> {
        Self::fetch_page_with_limit(
            container,
            zone,
            continuation_token,
            assets,
            CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE,
        )
        .await
    }

    pub async fn fetch_page_with_limit(
        container: &CloudKitOpenContainer<'_, impl AnisetteProvider>,
        zone: cloudkit_proto::RecordZoneIdentifier,
        continuation_token: Option<Vec<u8>>,
        assets: &cloudkit_proto::AssetsToDownload,
        max_changes: u32,
    ) -> Result<CloudKitRecordChangePage, PushError> {
        Self::fetch_page_with_limit_and_access(
            container,
            zone,
            continuation_token,
            assets,
            max_changes,
            false,
        )
        .await
    }

    pub async fn fetch_page_with_limit_lookup_only(
        container: &CloudKitOpenContainer<'_, impl AnisetteProvider>,
        zone: cloudkit_proto::RecordZoneIdentifier,
        continuation_token: Option<Vec<u8>>,
        assets: &cloudkit_proto::AssetsToDownload,
        max_changes: u32,
    ) -> Result<CloudKitRecordChangePage, PushError> {
        Self::fetch_page_with_limit_and_access(
            container,
            zone,
            continuation_token,
            assets,
            max_changes,
            true,
        )
        .await
    }

    async fn fetch_page_with_limit_and_access(
        container: &CloudKitOpenContainer<'_, impl AnisetteProvider>,
        zone: cloudkit_proto::RecordZoneIdentifier,
        continuation_token: Option<Vec<u8>>,
        assets: &cloudkit_proto::AssetsToDownload,
        max_changes: u32,
        lookup_only: bool,
    ) -> Result<CloudKitRecordChangePage, PushError> {
        let requested_token = continuation_token.clone();
        let operation = Self::new_with_limit(zone, continuation_token, assets, max_changes);
        let (assets, response) = if lookup_only {
            container
                .perform_semantic_read_only(&CloudKitSession::new(), operation)
                .await?
        } else {
            container
                .perform(&CloudKitSession::new(), operation)
                .await?
        };
        let status = response.status();
        validate_record_change_page_size(&response.change, max_changes)?;
        let page = CloudKitRecordChangePage {
            assets,
            changes: response.change,
            next_token: response.sync_continuation_token,
            status,
        };
        ensure_cloudkit_continuation_progress(
            page.is_complete(),
            requested_token.as_deref(),
            page.next_token.as_deref(),
        )?;
        Ok(page)
    }

    pub async fn do_sync(
        container: &CloudKitOpenContainer<'_, impl AnisetteProvider>,
        zones: &[(cloudkit_proto::RecordZoneIdentifier, Option<Vec<u8>>)],
        assets: &cloudkit_proto::AssetsToDownload,
    ) -> Result<Vec<(Vec<AssetGetResponse>, Vec<RecordChange>, Option<Vec<u8>>)>, PushError> {
        Self::do_sync_with_access(container, zones, assets, false).await
    }

    pub async fn do_sync_lookup_only(
        container: &CloudKitOpenContainer<'_, impl AnisetteProvider>,
        zones: &[(cloudkit_proto::RecordZoneIdentifier, Option<Vec<u8>>)],
        assets: &cloudkit_proto::AssetsToDownload,
    ) -> Result<Vec<(Vec<AssetGetResponse>, Vec<RecordChange>, Option<Vec<u8>>)>, PushError> {
        Self::do_sync_with_access(container, zones, assets, true).await
    }

    async fn do_sync_with_access(
        container: &CloudKitOpenContainer<'_, impl AnisetteProvider>,
        zones: &[(cloudkit_proto::RecordZoneIdentifier, Option<Vec<u8>>)],
        assets: &cloudkit_proto::AssetsToDownload,
        lookup_only: bool,
    ) -> Result<Vec<(Vec<AssetGetResponse>, Vec<RecordChange>, Option<Vec<u8>>)>, PushError> {
        let mut responses = zones
            .iter()
            .map(|zone| (vec![], vec![], zone.1.clone()))
            .collect::<Vec<_>>();

        let mut finished_zones = vec![];
        let mut seen_token_digests = zones
            .iter()
            .map(|zone| {
                zone.1
                    .as_deref()
                    .map(sha256)
                    .into_iter()
                    .collect::<HashSet<_>>()
            })
            .collect::<Vec<_>>();
        let mut pages = 0usize;
        while finished_zones.len() != zones.len() {
            pages += 1;
            if pages > CLOUDKIT_MAX_LEGACY_SYNC_PAGES {
                return Err(cloudkit_protocol_error(
                    "CloudKit record sync exceeded the page limit",
                ));
            }
            let mut sync_zones_here = zones
                .iter()
                .enumerate()
                .filter(|(_, zone)| !finished_zones.contains(&zone.0))
                .collect::<Vec<_>>();
            let fetch_operations = sync_zones_here
                .iter()
                .map(|(idx, zone)| {
                    FetchRecordChangesOperation::new(
                        zone.0.clone(),
                        responses[*idx].2.clone(),
                        assets,
                    )
                })
                .collect::<Vec<_>>();
            let operations = if lookup_only {
                container
                    .perform_semantic_read_only_operations_checked(
                        &CloudKitSession::new(),
                        &fetch_operations,
                        IsolationLevel::Zone,
                    )
                    .await?
            } else {
                container
                    .perform_operations_checked(
                        &CloudKitSession::new(),
                        &fetch_operations,
                        IsolationLevel::Zone,
                    )
                    .await?
            };
            for (result, (zone_idx, zone)) in operations.into_iter().zip(sync_zones_here.iter_mut())
            {
                let previous_token = responses[*zone_idx].2.clone();
                let status = result.1.status();
                let next_token = result.1.sync_continuation_token.clone();
                validate_record_change_page_size(
                    &result.1.change,
                    CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE,
                )?;
                if status == CLOUDKIT_RECORD_CHANGES_STATUS_COMPLETE {
                    // done syncing
                    finished_zones.push(zone.0.clone());
                }
                responses[*zone_idx].0.extend(result.0);
                responses[*zone_idx].1.extend(result.1.change);
                responses[*zone_idx].2 = next_token;
                ensure_cloudkit_continuation_progress(
                    status == CLOUDKIT_RECORD_CHANGES_STATUS_COMPLETE,
                    previous_token.as_deref(),
                    responses[*zone_idx].2.as_deref(),
                )?;
                remember_incomplete_continuation_token(
                    status == CLOUDKIT_RECORD_CHANGES_STATUS_COMPLETE,
                    responses[*zone_idx].2.as_deref(),
                    &mut seen_token_digests[*zone_idx],
                )?;
            }
        }

        Ok(responses)
    }
}

pub struct FetchZoneChangesOperation(pub cloudkit_proto::RetrieveZoneChangesRequest);
impl CloudKitOp for FetchZoneChangesOperation {
    type Response = cloudkit_proto::RetrieveZoneChangesResponse;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.retrieve_zone_changes_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        response
            .retrieve_zone_changes_response
            .clone()
            .ok_or_else(|| cloudkit_protocol_error("CloudKit zone-changes response was missing"))
    }
    fn flow_control_key() -> &'static str {
        panic!("not flow")
    }
    fn is_flow() -> bool {
        false
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/zone/sync"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ZoneRetrieveChangesType
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::ReadOnly
    }
}

pub struct CloudKitZoneChangePage {
    pub changes: Vec<ChangedZone>,
    pub next_token: Option<Vec<u8>>,
    pub status: i32,
}

impl CloudKitZoneChangePage {
    pub fn is_complete(&self) -> bool {
        self.status == CLOUDKIT_ZONE_CHANGES_STATUS_COMPLETE
    }
}

impl FetchZoneChangesOperation {
    pub fn new(continuation_token: Option<Vec<u8>>) -> Self {
        Self(cloudkit_proto::RetrieveZoneChangesRequest {
            sync_continuation_token: continuation_token,
            max_changed_zones: Some(CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE),
        })
    }

    pub async fn fetch_page(
        container: &CloudKitOpenContainer<'_, impl AnisetteProvider>,
        continuation_token: Option<Vec<u8>>,
    ) -> Result<CloudKitZoneChangePage, PushError> {
        let requested_token = continuation_token.clone();
        let response = container
            .perform(&CloudKitSession::new(), Self::new(continuation_token))
            .await?;
        let page = CloudKitZoneChangePage {
            changes: response.changes,
            next_token: response.sync_continuation_token,
            status: response.status.unwrap_or_default(),
        };
        ensure_cloudkit_continuation_progress(
            page.is_complete(),
            requested_token.as_deref(),
            page.next_token.as_deref(),
        )?;
        Ok(page)
    }

    pub async fn do_sync(
        container: &CloudKitOpenContainer<'_, impl AnisetteProvider>,
        mut sync_token: Option<Vec<u8>>,
    ) -> Result<(Vec<ChangedZone>, Option<Vec<u8>>), PushError> {
        let mut responses = vec![];
        let mut seen_token_digests = sync_token
            .as_deref()
            .map(sha256)
            .into_iter()
            .collect::<HashSet<_>>();
        for _ in 0..CLOUDKIT_MAX_LEGACY_SYNC_PAGES {
            let page = Self::fetch_page(container, sync_token).await?;
            let is_complete = page.is_complete();
            responses.extend(page.changes);
            sync_token = page.next_token;
            if is_complete {
                // done syncing
                return Ok((responses, sync_token));
            }
            remember_incomplete_continuation_token(
                false,
                sync_token.as_deref(),
                &mut seen_token_digests,
            )?;
        }
        Err(cloudkit_protocol_error(
            "CloudKit zone sync exceeded the page limit",
        ))
    }
}

pub fn should_reset(error: Option<&PushError>) -> bool {
    matches!(error, Some(PushError::CloudKitError(cloudkit_proto::response_operation::Result { error: Some(cloudkit_proto::response_operation::result::Error {
            client_error: Some(cloudkit_proto::response_operation::result::error::Client {
                r#type: Some(errortype)
            }),
            ..
        }), .. })) if *errortype == cloudkit_proto::response_operation::result::error::client::Code::FullResetNeeded as i32)
}

pub struct FunctionInvokeOperation(pub cloudkit_proto::FunctionInvokeRequest);
impl CloudKitOp for FunctionInvokeOperation {
    type Response = Vec<u8>;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.function_invoke_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        response
            .function_invoke_response
            .as_ref()
            .and_then(|response| response.serialized_result.clone())
            .ok_or_else(|| cloudkit_protocol_error("CloudKit function response was missing"))
    }
    fn flow_control_key() -> &'static str {
        panic!("not flow")
    }
    fn is_flow() -> bool {
        false
    }
    fn is_grouped() -> bool {
        false
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::FunctionInvokeType
    }
    fn provides_assets() -> bool {
        true
    }
    fn is_fetch() -> bool {
        true
    }
    fn custom_headers(&self) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            "x-cloudkit-functionroutinghint",
            HeaderValue::from_str(&format!(
                "{}/{}",
                self.0.service.as_ref().unwrap(),
                self.0.name.as_ref().unwrap()
            ))
            .unwrap(),
        );
        map
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        if self.semantic_read_operation().is_some() {
            CloudKitRetrySafety::ReadOnly
        } else {
            CloudKitRetrySafety::Never
        }
    }
    fn semantic_read_operation(&self) -> Option<SemanticReadOperation> {
        match (self.0.service.as_deref(), self.0.name.as_deref()) {
            (Some("Cuttlefish"), Some("fetchChanges")) => {
                Some(SemanticReadOperation::CuttlefishFetchChanges)
            }
            (Some("Cuttlefish"), Some("fetchRecoverableTLKShares")) => {
                Some(SemanticReadOperation::CuttlefishFetchRecoverableTlkShares)
            }
            _ => None,
        }
    }
}

impl FunctionInvokeOperation {
    pub fn new(service: String, name: String, parameters: Vec<u8>) -> Self {
        Self(cloudkit_proto::FunctionInvokeRequest {
            service: Some(service),
            name: Some(name),
            parameters: Some(parameters),
        })
    }
}

pub struct ZoneDeleteOperation(pub cloudkit_proto::ZoneDeleteRequest);
impl CloudKitOp for ZoneDeleteOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.zone_delete_request = Some(self.0.clone());
    }
    fn retrieve_response(
        _response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        Ok(())
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordZonesOperation"
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/zone/delete"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ZoneDeleteType
    }
}

impl ZoneDeleteOperation {
    pub fn new(zone: RecordZoneIdentifier) -> Self {
        Self(cloudkit_proto::ZoneDeleteRequest {
            zone: Some(zone),
            unk2: Some(0),
        })
    }
}

pub struct ResolveTokenOperation(pub cloudkit_proto::ResolveTokenRequest);
impl CloudKitOp for ResolveTokenOperation {
    type Response = cloudkit_proto::ResolveTokenResponse;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.resolve_token_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        response.resolve_token_response.clone().ok_or_else(|| {
            cloudkit_protocol_error("CloudKit token-resolution response was missing")
        })
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/resolveToken"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ResolveTokenType
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::ReadOnly
    }
}

pub struct ShareAcceptOperation(pub cloudkit_proto::ShareAcceptRequest);
impl CloudKitOp for ShareAcceptOperation {
    type Response = cloudkit_proto::ShareInfo;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.share_accept_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        response
            .share_accept_response
            .as_ref()
            .and_then(|response| response.share.clone())
            .ok_or_else(|| cloudkit_protocol_error("CloudKit share-accept response was missing"))
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckshare/api/client/share/accept"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ShareAcceptType
    }
}

pub struct ShareDeclineOperation(pub cloudkit_proto::ShareDeclineRequest);
impl CloudKitOp for ShareDeclineOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.share_decline_request = Some(self.0.clone());
    }
    fn retrieve_response(
        _response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        Ok(())
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/share/decline"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ShareDeclineType
    }
}

// pulls from keychain DB (pcspublickey)
pub struct UserQueryOperation(pub cloudkit_proto::UserQueryRequest);
impl CloudKitOp for UserQueryOperation {
    type Response = Option<User>;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.user_query_request = Some(self.0.clone());
    }
    fn retrieve_response(
        response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        Ok(response
            .user_query_response
            .as_ref()
            .ok_or_else(|| cloudkit_protocol_error("CloudKit user-query response was missing"))?
            .user
            .clone())
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckshare/api/client/membership/query/stream"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::UserQuerytype
    }
    fn retry_safety(&self) -> CloudKitRetrySafety {
        CloudKitRetrySafety::ReadOnly
    }
}

pub struct TokenRegistrationOperation(pub cloudkit_proto::TokenRegistrationRequest);
impl CloudKitOp for TokenRegistrationOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.token_registration_request = Some(self.0.clone());
    }
    fn retrieve_response(
        _response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        Ok(())
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn is_grouped() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdevice/api/client/pushRegister"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::PushRegisterType
    }
}

pub struct CreateSubscriptionOperation(pub cloudkit_proto::CreateSubscriptionRequest);
impl CloudKitOp for CreateSubscriptionOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.create_subscription_request = Some(self.0.clone());
    }
    fn retrieve_response(
        _response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        Ok(())
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/subscription/create"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::SubscriptionCreateType
    }
}

pub struct ZoneSaveOperation(pub cloudkit_proto::ZoneSaveRequest);
impl CloudKitOp for ZoneSaveOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.zone_save_request = Some(self.0.clone());
    }
    fn retrieve_response(
        _response: &cloudkit_proto::ResponseOperation,
    ) -> Result<Self::Response, PushError> {
        Ok(())
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordZonesOperation"
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/zone/save"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ZoneSaveType
    }
}

impl ZoneSaveOperation {
    pub fn roll_keys(
        config: &mut PCSZoneConfig,
        access_keys: &[CompactECKey<Private>],
    ) -> Result<Self, PushError> {
        assert!(!config.default_record_keys.is_empty()); // only support zones with unified record protection

        config.zone_roll_count += 1;
        config.record_roll_count += 2;

        let zone_key = CompactECKey::new()?;
        let protection_key = PCSKey::random();
        let protection_info = PCSShareProtection::create(
            &access_keys[0],
            &[zone_key.clone()],
            &access_keys[1..],
            protection_key.clone(),
            Some(&access_keys[0]),
            &[],
            config.zone_pcs_key.first().cloned(),
            config.zone_roll_count,
            None,
            access_keys.len() > 1,
        )?;

        config.zone_pcs_key = vec![protection_key.get_share_key(access_keys.len() > 1)];
        config.zone_keys = vec![zone_key.clone()];

        let record_key = PCSKey::random();
        let record_protection_info = PCSShareProtection::create(
            &zone_key,
            &[],
            &[] as &[CompactECKey<Private>],
            record_key.clone(),
            Some(&zone_key),
            &config.default_record_keys,
            config.default_record_keys.first().cloned(),
            config.record_roll_count,
            None,
            false,
        )?;

        config
            .default_record_keys
            .insert(0, record_key.get_share_key(false));
        config.record_prot_tag = None;

        let zone_prot = protection_info.to_protection_info(true)?;
        config.zone_protection_tag = zone_prot.protection_info_tag.clone();

        Ok(Self(cloudkit_proto::ZoneSaveRequest {
            zone: Some(Zone {
                zone_identifier: Some(config.identifier.clone()),
                etag: None,
                protection_info: Some(zone_prot),
                record_protection_info: Some(record_protection_info.to_protection_info(false)?),
            }),
        }))
    }

    pub fn new(
        zone: RecordZoneIdentifier,
        access_keys: &[CompactECKey<Private>],
        with_record: bool,
    ) -> Result<Self, PushError> {
        let mut protection_info: Option<ProtectionInfo> = None;
        let mut record_protection_info: Option<ProtectionInfo> = None;
        if !access_keys.is_empty() {
            let zone_key = CompactECKey::new()?;
            let main_protection = PCSShareProtection::create_new(
                &access_keys[0],
                &[zone_key.clone()],
                &access_keys[1..],
                access_keys.len() > 1,
            )?;

            if with_record {
                let record_protection = PCSShareProtection::create_new(
                    &zone_key,
                    &[],
                    &[] as &[CompactECKey<Private>],
                    false,
                )?;
                record_protection_info = Some(record_protection.to_protection_info(false)?);
            }
            protection_info = Some(main_protection.to_protection_info(true)?)
        }

        Ok(Self(cloudkit_proto::ZoneSaveRequest {
            zone: Some(Zone {
                zone_identifier: Some(zone),
                etag: None,
                protection_info,
                record_protection_info,
            }),
        }))
    }
}

pub struct CloudKitSession {
    op_group_id: [u8; 8],
    op_id: [u8; 8],
}

impl CloudKitSession {
    pub fn new() -> Self {
        Self {
            op_group_id: rand::random(),
            op_id: rand::random(),
        }
    }
}

impl Default for CloudKitSession {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CloudKitRecordNameAllocation {
    Existing(String),
    /// The caller must durably persist this mapping before issuing a CloudKit
    /// request. Calling the allocator again intentionally produces a new name.
    NewlyAllocated(String),
}

impl CloudKitRecordNameAllocation {
    pub fn record_name(&self) -> &str {
        match self {
            Self::Existing(record_name) | Self::NewlyAllocated(record_name) => record_name,
        }
    }

    pub fn requires_persistence(&self) -> bool {
        matches!(self, Self::NewlyAllocated(_))
    }
}

pub fn allocate_or_reuse_record_name(
    existing_record_name: Option<&str>,
) -> Result<CloudKitRecordNameAllocation, PushError> {
    match existing_record_name {
        Some(record_name) if !record_name.is_empty() => Ok(CloudKitRecordNameAllocation::Existing(
            record_name.to_owned(),
        )),
        Some(_) => Err(cloudkit_invalid_input("CloudKit record mapping was empty")),
        None => Ok(CloudKitRecordNameAllocation::NewlyAllocated(
            Uuid::new_v4().to_string().to_uppercase(),
        )),
    }
}

pub fn record_identifier(zone: RecordZoneIdentifier, id: &str) -> cloudkit_proto::RecordIdentifier {
    cloudkit_proto::RecordIdentifier {
        value: Some(cloudkit_proto::Identifier {
            name: Some(id.to_string()),
            r#type: Some(cloudkit_proto::identifier::Type::Record.into()),
        }),
        zone_identifier: Some(zone),
    }
}

pub fn record_identifier_for_allocation(
    zone: RecordZoneIdentifier,
    allocation: &CloudKitRecordNameAllocation,
) -> cloudkit_proto::RecordIdentifier {
    record_identifier(zone, allocation.record_name())
}

pub fn public_zone() -> cloudkit_proto::RecordZoneIdentifier {
    cloudkit_proto::RecordZoneIdentifier {
        value: Some(cloudkit_proto::Identifier {
            name: Some(DEFAULT_ZONE.to_string()),
            r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into()),
        }),
        owner_identifier: Some(cloudkit_proto::Identifier {
            name: Some("_defaultOwner".to_string()),
            r#type: Some(cloudkit_proto::identifier::Type::User.into()),
        }),
        environment: None,
    }
}

pub fn record_identifier_public(id: &str) -> cloudkit_proto::RecordIdentifier {
    record_identifier(public_zone(), id)
}

#[derive(Serialize, Deserialize)]
pub struct CloudKitState {
    dsid: String,
}

impl CloudKitState {
    pub fn new(dsid: String) -> Option<Self> {
        Some(Self { dsid })
    }

    /// Native-only account binding for callers that must derive a protected
    /// identifier. Do not bridge this raw value to Dart or diagnostics.
    pub(crate) fn account_identifier(&self) -> &str {
        &self.dsid
    }
}

fn get_participant_prot_key(participant: &Participant) -> Result<CompactECKey<Public>, PushError> {
    if let Some(public) = &participant.protection_info_public_key {
        return Ok(CompactECKey::decompress(
            public.clone().try_into().expect("Prot pub key wrogn size!"),
        ));
    }

    let my_participant_prot = PCSShareProtection::from_protection_info(
        &participant
            .protection_info
            .as_ref()
            .expect("No participant protection info!"),
    );
    Ok(my_participant_prot
        .get_inner_keys()
        .into_iter()
        .next()
        .expect("Participant has no key??"))
}

#[derive(CloudKitRecord, Debug, Default, Clone, Serialize, Deserialize)]
#[cloudkit_record(type = "cloudkit.share", encrypted, rename_all = "camelCase")]
pub struct CloudKitShare {
    pub display_name: String,
    #[cloudkit(skip)]
    #[serde(
        serialize_with = "proto_serialize",
        deserialize_with = "proto_deserialize"
    )]
    pub share_info: ShareInfo,
    #[cloudkit(skip)]
    #[serde(
        serialize_with = "proto_serialize_opt",
        deserialize_with = "proto_deserialize_opt"
    )]
    pub url: Option<StableUrl>,
    #[cloudkit(skip)]
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub public_sharing_key: Vec<u8>,
}

impl CloudKitShare {
    pub fn from_record(record: &Record, config: &PCSZoneConfig) -> Self {
        let got_type = record
            .r#type
            .as_ref()
            .expect("no TYpe")
            .name
            .as_ref()
            .expect("No ta");
        if got_type.as_str() != Self::record_type() {
            panic!(
                "Wrong record type, got {} expected {}",
                got_type,
                Self::record_type()
            );
        }

        let key = pcs_keys_for_record(record, config).expect("no PCS key");
        let mut decrypted = Self::from_record_encrypted(&record.record_field, Some(&key));

        let share_info = record
            .share_info
            .as_ref()
            .expect("Zone share has no share info??");

        let url = record
            .stable_url
            .as_ref()
            .unwrap()
            .encrypted_public_sharing_key();

        // for individual participants the field name is the participant ID (field 1)
        let decrypted_pub = key.decrypt_data(url, "encryptedPublicSharingKey");

        decrypted.share_info = share_info.clone();
        decrypted.url = record.stable_url.clone();
        decrypted.public_sharing_key = decrypted_pub;

        decrypted
    }

    fn get_full_token(&self) -> String {
        format!(
            "{}{}",
            base64_encode_url(&[0x10, 0, 0]),
            base64_encode_url(&self.public_sharing_key)
        )
    }

    fn get_sharing_token(&self) -> [u8; 16] {
        sha256(self.get_full_token().as_bytes())[..16]
            .try_into()
            .unwrap()
    }

    fn get_short_token(&self) -> String {
        base64_encode_url(&self.get_sharing_token())
    }

    fn get_short_token_hash(&self) -> [u8; 32] {
        sha256(self.get_short_token().as_bytes())
    }

    pub fn get_share_url(&self) -> Result<String, PushError> {
        let Some(url) = &self.url else {
            return Err(PushError::NoRoutingKey);
        };
        let key = url.routing_key.as_ref().ok_or(PushError::NoRoutingKey)?;
        let encoded = self.get_short_token();

        Ok(format!(
            "https://{}/share/{}{}",
            url.displayed_hostname
                .as_ref()
                .map(|i| i.as_str())
                .unwrap_or("www.icloud.com"),
            key,
            encoded
        ))
    }

    pub fn find_participant_by_handle(&self, handle: &str) -> Option<&Participant> {
        let contact_information = handle_to_contact(handle);
        self.share_info.participants.iter().find(|p| {
            let Some(i) = &p.contact_information else {
                return false;
            };
            if i.email_address.is_some() && i.email_address == contact_information.email_address {
                return true;
            };
            if i.phone_number.is_some() && i.phone_number == contact_information.phone_number {
                return true;
            };
            false
        })
    }
}

#[derive(CloudKitRecord, Debug, Default, Clone)]
#[cloudkit_record(type = "ZoneUpdatePlugin")]
pub struct ZoneUpdatePlugin {
    #[cloudkit(rename = "___zoneUpdateData")]
    zone_update_data: Vec<u8>,
}

pub struct CloudKitClient<P: AnisetteProvider> {
    pub anisette: ArcAnisetteClient<P>,
    pub state: DebugRwLock<CloudKitState>,
    pub config: Arc<dyn OSConfig>,
    pub token_provider: Arc<TokenProvider<P>>,
}

pub struct CloudKitContainer<'t> {
    pub database_type: cloudkit_proto::request_operation::header::Database,
    pub bundleid: &'t str,
    pub containerid: &'t str,
    pub env: cloudkit_proto::request_operation::header::ContainerEnvironment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CloudKitReadAuthenticationContainer {
    Messages,
    Cuttlefish,
    Securityd,
}

impl CloudKitReadAuthenticationContainer {
    fn matches(self, container: &CloudKitContainer<'_>) -> bool {
        let (bundle_id, container_id) = match self {
            Self::Messages => ("com.apple.imagent", "com.apple.messages.cloud"),
            Self::Cuttlefish => (
                "com.apple.security.cuttlefish",
                "com.apple.security.keychain",
            ),
            Self::Securityd => ("com.apple.securityd", "com.apple.security.keychain"),
        };
        container.bundleid == bundle_id
            && container.containerid == container_id
            && container.database_type
                == cloudkit_proto::request_operation::header::Database::PrivateDb
            && container.env
                == cloudkit_proto::request_operation::header::ContainerEnvironment::Production
    }
}

#[derive(Default)]
struct CkAppInitRetryBudget {
    attempts: u8,
    refreshes: u8,
}

impl CkAppInitRetryBudget {
    fn begin_attempt(&mut self) -> Result<(), PushError> {
        if self.attempts >= 2 {
            return Err(PushError::UnauthorizedAccountError);
        }
        self.attempts += 1;
        Ok(())
    }

    fn authorize_refresh(&mut self) -> Result<(), PushError> {
        if self.attempts != 1 || self.refreshes != 0 {
            return Err(PushError::UnauthorizedAccountError);
        }
        self.refreshes = 1;
        Ok(())
    }
}

impl<'t> CloudKitContainer<'t> {
    async fn headers<T: AnisetteProvider>(
        &self,
        client: &CloudKitClient<T>,
        builder: RequestBuilder,
        session: &CloudKitSession,
        r#type: &Database,
        request_uuid: &str,
        prepared_anisette_headers: Option<&HeaderMap>,
    ) -> Result<RequestBuilder, PushError> {
        let mut anisette_headers = match prepared_anisette_headers {
            Some(headers) => headers.clone(),
            None => {
                let mut locked = client.anisette.lock().await;
                cloudkit_anisette_header_map(locked.get_headers().await?)?
            }
        };
        anisette_headers.remove("x-apple-request-uuid");

        Ok(builder.header("accept", "application/x-protobuf")
            .header("accept-encoding", "gzip")
            .header("accept-language", "en-US,en;q=0.9")
            .header("cache-control", "no-transform")
            .header("content-encoding", "gzip")
            .header("content-type", r#"application/x-protobuf; desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true"#)
            .header("user-agent", "CloudKit/1970 (19H384)")
            .header("x-apple-c2-metric-triggers", "0")
            .header("x-apple-operation-group-id", encode_hex(&session.op_group_id).to_uppercase())
            .header("x-apple-operation-id", encode_hex(&session.op_id).to_uppercase())
            .header("x-apple-request-uuid", request_uuid)
            .header("x-cloudkit-bundleid", self.bundleid)
            .header("x-cloudkit-containerid", self.containerid)
            .header("x-cloudkit-databasescope", r#type.ck_type())
            .header("x-cloudkit-duetpreclearedmode", "None")
            .header("x-cloudkit-environment", "Production")
            .header("x-mme-client-info", client.config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"))
            .headers(anisette_headers))
    }

    pub async fn watch_notifs(&self, conn: &APSConnection) -> CloudKitNotifWatcher {
        let topic = format!("com.apple.icloud-container.{}", self.bundleid);
        CloudKitNotifWatcher {
            _interest_token: conn.request_topics(&[&topic]).await,
            for_topic: sha1(topic.as_bytes()),
            container: self.containerid.to_string(),
            changed_zones: DebugMutex::new(vec![]),
            gen: AtomicU64::new(0),
        }
    }

    pub async fn init<T: AnisetteProvider>(
        &'t self,
        client: Arc<CloudKitClient<T>>,
    ) -> Result<CloudKitOpenContainer<'t, T>, PushError> {
        // A warm semantic read uses an already-open container. Any cold
        // initialization performs token/anisette work and ckAppInit, so admit
        // it as writer-side work before the first authentication or network
        // side effect. Known writer workflows already hold the task-local
        // permit; unknown callers get the same fail-closed backstop here.
        let _writer_operation_permit = if cloudkit_writer_operation_is_held() {
            None
        } else {
            Some(try_acquire_cloudkit_operation()?)
        };
        self.init_after_admission(client).await
    }

    pub(crate) async fn init_for_read_authentication<T: AnisetteProvider>(
        &'t self,
        client: Arc<CloudKitClient<T>>,
        permit: &CloudKitReadAuthenticationPermit<'_>,
        allowed_container: CloudKitReadAuthenticationContainer,
    ) -> Result<CloudKitOpenContainer<'t, T>, PushError> {
        permit.validate()?;
        if !allowed_container.matches(self) {
            return Err(PushError::IoError(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "CloudKit container is not allowed for read authentication",
            )));
        }
        let container = self.init_after_admission(client.clone()).await?;
        permit.validate()?;
        container
            .validate_read_authentication_identity(&client, allowed_container)
            .await?;
        Ok(container)
    }

    async fn init_after_admission<T: AnisetteProvider>(
        &'t self,
        client: Arc<CloudKitClient<T>>,
    ) -> Result<CloudKitOpenContainer<'t, T>, PushError> {
        let session = CloudKitSession::new();
        let account_dsid = client.state.read().await.dsid.clone();

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CkInitResponse {
            cloud_kit_user_id: String,
        }

        let mut retry_budget = CkAppInitRetryBudget::default();
        let response = loop {
            retry_budget.begin_attempt()?;
            let mme_token = client.token_provider.get_mme_token("mmeAuthToken").await?;
            let init_request_uuid = Uuid::new_v4().to_string().to_uppercase();
            let response = self
                .headers(
                    &client,
                    REQWEST.post("https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit"),
                    &session,
                    &self.database_type,
                    &init_request_uuid,
                    None,
                )
                .await?
                .query(&[("container", &self.containerid)])
                .basic_auth(&account_dsid, Some(&mme_token))
                .send()
                .await?;

            if response.status() != reqwest::StatusCode::UNAUTHORIZED {
                break response;
            }
            retry_budget.authorize_refresh()?;
            client.token_provider.refresh_mme().await?;
        };

        let response: CkInitResponse = response.json().await?;
        if client.state.read().await.dsid != account_dsid {
            return Err(PushError::UnauthorizedAccountError);
        }

        Ok(CloudKitOpenContainer {
            database_type: self.database_type,
            container: self,
            user_id: response.cloud_kit_user_id,
            client,
            account_dsid,
            keys: DebugMutex::new(HashMap::new()),
        })
    }
}

pub struct QueryResult<T: CloudKitRecord> {
    pub record_id: String,
    pub result: T,
}

#[derive(Clone)]
pub struct PCSZoneConfig {
    identifier: RecordZoneIdentifier,
    zone_keys: Vec<CompactECKey<Private>>,
    zone_protection_tag: Option<String>,
    default_record_keys: Vec<PCSKey>,
    pub record_prot_tag: Option<String>,
    zone_pcs_key: Vec<PCSKey>,
    zone_roll_count: u32,
    record_roll_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ZoneEncryptionConfigAccess {
    /// The historical path may create a missing PCS zone for callers that
    /// explicitly use the legacy helper.
    AllowCreate,
    /// Semantic decode may resolve existing configuration, but cannot create
    /// or modify a CloudKit zone.
    LookupOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MissingZoneAction {
    ReturnError,
    CreateAndFetch,
}

impl ZoneEncryptionConfigAccess {
    const fn missing_zone_action(self) -> MissingZoneAction {
        match self {
            Self::AllowCreate => MissingZoneAction::CreateAndFetch,
            Self::LookupOnly => MissingZoneAction::ReturnError,
        }
    }
}

impl PCSZoneConfig {
    fn decode_record_protection(
        &self,
        protection: &ProtectionInfo,
    ) -> Result<Vec<PCSKey>, PushError> {
        let record_protection = PCSShareProtection::try_from_protection_info(protection)?;
        let (key, _record_keys) =
            record_protection.decode(&self.zone_keys, None::<&CompactECKey<Public>>)?;

        Ok(key)
    }
}

pub struct CloudKitOpenContainer<'t, T: AnisetteProvider> {
    container: &'t CloudKitContainer<'t>,
    pub user_id: String,
    pub client: Arc<CloudKitClient<T>>,
    account_dsid: String,
    pub keys: DebugMutex<HashMap<String, PCSZoneConfig>>,
    pub database_type: cloudkit_proto::request_operation::header::Database,
}

impl<'t, T: AnisetteProvider> Deref for CloudKitOpenContainer<'t, T> {
    type Target = CloudKitContainer<'t>;
    fn deref(&self) -> &Self::Target {
        &self.container
    }
}

impl<'t, T: AnisetteProvider> CloudKitOpenContainer<'t, T> {
    pub(crate) async fn validate_read_authentication_identity(
        &self,
        expected_client: &Arc<CloudKitClient<T>>,
        allowed_container: CloudKitReadAuthenticationContainer,
    ) -> Result<(), PushError> {
        let exact_container = allowed_container.matches(self.container)
            && self.database_type == cloudkit_proto::request_operation::header::Database::PrivateDb;
        let exact_client = Arc::ptr_eq(&self.client, expected_client);
        let exact_account = expected_client.state.read().await.dsid == self.account_dsid;
        if !exact_container || !exact_client || !exact_account {
            return Err(PushError::IoError(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "cached CloudKit read-authentication identity mismatch",
            )));
        }
        Ok(())
    }

    pub fn private_zone(&self, name: String) -> cloudkit_proto::RecordZoneIdentifier {
        cloudkit_proto::RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(name),
                r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into()),
            }),
            owner_identifier: Some(cloudkit_proto::Identifier {
                name: Some(self.user_id.clone()),
                r#type: Some(cloudkit_proto::identifier::Type::User.into()),
            }),
            environment: None,
        }
    }

    pub fn shared_zone(&self, name: String, user: String) -> cloudkit_proto::RecordZoneIdentifier {
        if self.database_type != Database::SharedDb {
            panic!("Cannot get shared zone for private db!");
        }

        cloudkit_proto::RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(name),
                r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into()),
            }),
            owner_identifier: Some(cloudkit_proto::Identifier {
                name: Some(user),
                r#type: Some(cloudkit_proto::identifier::Type::User.into()),
            }),
            environment: None,
        }
    }

    pub async fn clear_cache_zone_encryption_config(
        &self,
        zone: &cloudkit_proto::RecordZoneIdentifier,
    ) {
        let mut cached_keys = self.keys.lock().await;
        let zone_name = zone.value.as_ref().unwrap().name().to_string();
        cached_keys.remove(&zone_name);
    }

    pub async fn get_zone_encryption_config(
        &self,
        zone_id: &cloudkit_proto::RecordZoneIdentifier,
        client: &KeychainClient<T>,
        pcs_service: &PCSService<'_>,
    ) -> Result<PCSZoneConfig, PushError> {
        self.get_zone_encryption_config_sev_with_policy(
            &[(zone_id.clone(), None)],
            client,
            pcs_service,
            true,
            ZoneEncryptionConfigAccess::AllowCreate,
        )
        .await?
        .remove(0)
    }

    /// Resolves the PCS configuration using reads only.
    ///
    /// Unlike the legacy helper above, a missing or deleted zone is returned as
    /// an error. Semantic CloudKit pulls must never create a zone as a side
    /// effect of decoding an already-fetched record.
    pub async fn get_zone_encryption_config_lookup_only(
        &self,
        zone_id: &cloudkit_proto::RecordZoneIdentifier,
        client: &KeychainClient<T>,
        pcs_service: &PCSService<'_>,
    ) -> Result<PCSZoneConfig, PushError> {
        self.get_zone_encryption_config_sev_with_policy(
            &[(zone_id.clone(), None)],
            client,
            pcs_service,
            true,
            ZoneEncryptionConfigAccess::LookupOnly,
        )
        .await?
        .remove(0)
    }

    pub async fn get_zone_encryption_config_share(
        &self,
        zone_id: &cloudkit_proto::RecordZoneIdentifier,
        client: &KeychainClient<T>,
        pcs_service: &PCSService<'_>,
        share: Option<ShareInfo>,
    ) -> Result<PCSZoneConfig, PushError> {
        self.get_zone_encryption_config_sev_with_policy(
            &[(zone_id.clone(), share)],
            client,
            pcs_service,
            true,
            ZoneEncryptionConfigAccess::AllowCreate,
        )
        .await?
        .remove(0)
    }

    pub async fn get_zone_encryption_config_sev(
        &self,
        zone_ids: &[(cloudkit_proto::RecordZoneIdentifier, Option<ShareInfo>)],
        client: &KeychainClient<T>,
        pcs_service: &PCSService<'_>,
        sync_keychain: bool,
    ) -> Result<Vec<Result<PCSZoneConfig, PushError>>, PushError> {
        self.get_zone_encryption_config_sev_with_policy(
            zone_ids,
            client,
            pcs_service,
            sync_keychain,
            ZoneEncryptionConfigAccess::AllowCreate,
        )
        .await
    }

    async fn get_zone_encryption_config_sev_with_policy(
        &self,
        zone_ids: &[(cloudkit_proto::RecordZoneIdentifier, Option<ShareInfo>)],
        client: &KeychainClient<T>,
        pcs_service: &PCSService<'_>,
        sync_keychain: bool,
        access: ZoneEncryptionConfigAccess,
    ) -> Result<Vec<Result<PCSZoneConfig, PushError>>, PushError> {
        let mut cached_keys = self.keys.lock().await;
        let mut get_needed = Vec::new();
        for (zone_id, share) in zone_ids {
            let zone_name = cloudkit_zone_name(zone_id)?;
            if !cached_keys.contains_key(&zone_name) {
                get_needed.push((zone_id.clone(), share.clone()));
            }
        }

        let mut add_errors = HashMap::new();
        // todo what if get_needed is empty
        if !get_needed.is_empty() {
            if sync_keychain {
                if access == ZoneEncryptionConfigAccess::LookupOnly {
                    client
                        .sync_keychain_lookup_only(&[&pcs_service.zone, "ProtectedCloudStorage"])
                        .await?;
                } else {
                    client
                        .sync_keychain(&[&pcs_service.zone, "ProtectedCloudStorage"])
                        .await?;
                }
            }

            let zone_operations = get_needed
                .iter()
                .map(|(zone, _share)| FetchZoneOperation::new(zone.clone()))
                .collect::<Vec<_>>();
            let zones = if access == ZoneEncryptionConfigAccess::LookupOnly {
                self.perform_semantic_read_only_operations(
                    &CloudKitSession::new(),
                    &zone_operations,
                    IsolationLevel::Zone,
                )
                .await?
            } else {
                self.perform_operations(
                    &CloudKitSession::new(),
                    &zone_operations,
                    IsolationLevel::Zone,
                )
                .await?
            };
            if zones.len() != get_needed.len() {
                return Err(cloudkit_protocol_error(
                    "CloudKit zone response count did not match the request",
                ));
            }

            let mut add_zones = vec![];
            let mut result_zones = vec![];
            let mut fetch_shares = vec![];
            for (result, (zone_id, share_info)) in zones.into_iter().zip(&get_needed) {
                if share_info.is_none() && self.database_type == Database::SharedDb {
                    if access == ZoneEncryptionConfigAccess::LookupOnly {
                        return Err(PushError::CloudKitSemanticOperationDenied);
                    }
                    fetch_shares.push(FetchRecordOperation::new(
                        &NO_ASSETS,
                        record_identifier(zone_id.clone(), "cloudkit.zoneshare"),
                    ));
                }
                result_zones.push(match result {
                    Ok(data) => data.target_zone.ok_or_else(|| {
                        cloudkit_protocol_error("CloudKit zone response omitted the target zone")
                    })?,
                    Err(error @ PushError::CloudKitError(
                        cloudkit_proto::response_operation::Result {
                            error:
                                Some(cloudkit_proto::response_operation::result::Error {
                                    client_error: Some(
                                        cloudkit_proto::response_operation::result::error::Client {
                                            r#type: Some(48 | 59),
                                        },
                                    ),
                                    ..
                                }),
                            ..
                        },
                    )) => {
                        match access.missing_zone_action() {
                            MissingZoneAction::ReturnError => return Err(error),
                            MissingZoneAction::CreateAndFetch => {}
                        }
                        let service = PCSPrivateKey::get_service_key(
                            client,
                            pcs_service,
                            self.client.config.as_ref(),
                        )
                        .await?;

                        info!("Creating CloudKit zone");

                        let request = ZoneSaveOperation::new(
                            zone_id.clone(),
                            &[service.key()],
                            pcs_service.global_record,
                        )?;
                        let zone = request.0.clone().zone.unwrap();
                        add_zones.push(request);
                        info!("Created zone");
                        zone
                    }
                    Err(err) => return Err(err),
                });
            }

            if !add_zones.is_empty() {
                self.perform_operations_checked(
                    &CloudKitSession::new(),
                    &add_zones,
                    IsolationLevel::Zone,
                )
                .await?;
            }

            if !fetch_shares.is_empty() {
                let mut shares = self
                    .perform_operations_checked(
                        &CloudKitSession::new(),
                        &fetch_shares,
                        IsolationLevel::Zone,
                    )
                    .await?;
                for zone in &mut get_needed {
                    if zone.1.is_some() {
                        continue;
                    }
                    let share = shares.first().ok_or_else(|| {
                        cloudkit_protocol_error("CloudKit zone share response was missing")
                    })?;
                    let share_info =
                        share.get_raw_record()?.share_info.clone().ok_or_else(|| {
                            cloudkit_protocol_error("CloudKit zone share metadata was missing")
                        })?;
                    shares.remove(0);
                    zone.1 = Some(share_info);
                }
            }

            for (zone, (zone_id, share_info)) in result_zones.into_iter().zip(get_needed) {
                let zone_name = cloudkit_zone_name(&zone_id)?;

                let service = match access {
                    ZoneEncryptionConfigAccess::LookupOnly => {
                        PCSPrivateKey::require_existing_service_key(client, pcs_service).await?
                    }
                    ZoneEncryptionConfigAccess::AllowCreate => {
                        PCSPrivateKey::get_service_key(
                            client,
                            pcs_service,
                            self.client.config.as_ref(),
                        )
                        .await?
                    }
                };

                let data = client.state.read().await;
                let decrypt = (|| -> Result<_, PushError> {
                    let zone_protection_info = zone.protection_info.as_ref().ok_or_else(|| {
                        cloudkit_protocol_error(
                            "CloudKit zone response omitted PCS protection information",
                        )
                    })?;
                    let zone_protection =
                        PCSShareProtection::try_from_protection_info(zone_protection_info)?;
                    let (parent_keys, keys) = if self.database_type == Database::SharedDb {
                        let raw = share_info.expect("No share info provided??");
                        let my_participant = self.get_my_participant(&service, &raw);
                        if my_participant.state() == 3 {
                            return Err(PushError::RemovedFromShare);
                        }

                        let user_protection = PCSShareProtection::from_protection_info(
                            my_participant
                                .protection_info
                                .as_ref()
                                .expect("No protection info!"),
                        );
                        let (_, keys) =
                            user_protection.decrypt_with_keychain(&data, pcs_service, true)?;

                        info!("Decoded user!");

                        let invited_protection = PCSShareProtection::from_protection_info(
                            raw.invited_pcs.as_ref().unwrap(),
                        );
                        let owner_key = invited_protection.get_signer();
                        // it's signed with the owner private key.
                        let (_, keys) = invited_protection.decode(&keys, owner_key.as_ref())?;

                        info!("Decoded Share!");

                        zone_protection.decode(&keys, owner_key.as_ref())?
                    } else {
                        zone_protection.decrypt_with_keychain(&data, pcs_service, false)?
                    };

                    let mut keys = PCSZoneConfig {
                        identifier: zone_id.clone(),
                        zone_keys: keys,
                        zone_protection_tag: zone_protection_info.protection_info_tag.clone(),
                        default_record_keys: vec![],
                        record_prot_tag: if let Some(record_protection_info) =
                            &zone.record_protection_info
                        {
                            record_protection_info.protection_info_tag.clone()
                        } else {
                            None
                        },
                        zone_pcs_key: parent_keys,
                        zone_roll_count: zone_protection.get_roll_count(),
                        record_roll_count: 1,
                    };

                    if let Some(record_protection_info) = &zone.record_protection_info {
                        let record_protection =
                            PCSShareProtection::try_from_protection_info(record_protection_info)?;
                        let (key, _record_keys) = record_protection
                            .decode(&keys.zone_keys, None::<&CompactECKey<Public>>)?;
                        keys.record_roll_count = record_protection.get_roll_count();
                        keys.default_record_keys = key;
                    }

                    Ok(keys)
                })();

                match decrypt {
                    Ok(result) => {
                        cached_keys.insert(zone_name, result.clone());
                    }
                    Err(err) => {
                        add_errors.insert(zone_name, err);
                    }
                }
            }
        }

        let keys = zone_ids
            .iter()
            .map(|(zone_id, share)| {
                let zone_name = cloudkit_zone_name(zone_id)?;
                if let Some(zone) = cached_keys.get(&zone_name) {
                    Ok(zone.clone())
                } else {
                    Err(add_errors.remove(&zone_name).unwrap_or_else(|| {
                        cloudkit_protocol_error("CloudKit zone configuration result was missing")
                    }))
                }
            })
            .collect::<Vec<_>>();

        Ok(keys)
    }

    pub fn shared(&self) -> Self {
        if self.database_type != Database::PrivateDb {
            panic!("Can only convert private to shared!");
        }

        CloudKitOpenContainer {
            container: self.container,
            user_id: self.user_id.clone(),
            client: self.client.clone(),
            account_dsid: self.account_dsid.clone(),
            keys: DebugMutex::new(HashMap::new()),
            database_type: Database::SharedDb,
        }
    }

    fn get_my_participant<'a>(
        &self,
        my_key: &PCSPrivateKey,
        share: &'a ShareInfo,
    ) -> &'a Participant {
        if let Some(participant) = share
            .participants
            .iter()
            .find(|p| p.user_id.as_ref().map(|u| u.name()) == Some(&self.user_id))
        {
            participant
        } else {
            // search by public key
            let search_key = my_key.key().compress();

            share
                .participants
                .iter()
                .find(|p| {
                    p.public_key
                        .as_ref()
                        .expect("No public key?")
                        .protection_info()
                        == &search_key
                })
                .expect("Not a participant in share??")
        }
    }

    pub async fn get_zone_share(
        &self,
        zone: &cloudkit_proto::RecordZoneIdentifier,
        config: &PCSZoneConfig,
    ) -> Result<CloudKitShare, PushError> {
        let record = self
            .perform(
                &CloudKitSession::new(),
                FetchRecordOperation::new(
                    &NO_ASSETS,
                    record_identifier(zone.clone(), "cloudkit.zoneshare"),
                ),
            )
            .await?;

        let raw = record.get_raw_record()?;

        Ok(CloudKitShare::from_record(raw, config))
    }

    async fn fetch_share_url(&self, share_url: &str) -> Result<ResolveTokenResponse, PushError> {
        let parsed = Url::parse(share_url).expect("Failed to parse share url!");
        let segments = parsed.path_segments().expect("invalid url!");
        let invite_key = segments.last().expect("no last segment?");

        // we need 16 bytes, which is 22 bytes in base64
        let routing_len = invite_key.len() - 22;
        let (routing, short_token) = invite_key.split_at(routing_len);
        let short_token_hash = sha256(short_token.as_bytes());

        let request = ResolveTokenOperation(ResolveTokenRequest {
            routing_key: Some(routing.to_string()),
            short_token_hash: Some(short_token_hash.to_vec()),
            should_fetch_root_record: Some(false),
            root_record_desired_keys: vec!["__recordID".to_string()],
            ..Default::default()
        });

        let result = self.perform(&CloudKitSession::new(), request).await?;
        Ok(result)
    }

    pub async fn create_sync_subscription(&self) -> Result<(), PushError> {
        let op = CreateSubscriptionOperation(CreateSubscriptionRequest {
            subscription: Some(Subscription {
                identifier: Some(Identifier {
                    name: Some(format!(
                        "CKSyncEngineDatabaseSubscription-{}",
                        self.database_type.ck_type()
                    )),
                    r#type: Some(cloudkit_proto::identifier::Type::Subscription.into()),
                }),
                evaulation_type: Some(3),
                notification: Some(SubscriptionNotification {
                    alert: Some(vec![]),
                    should_badge: Some(false),
                    should_send_content_available: Some(true),
                    should_send_mutable_content: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        });
        self.perform(&CloudKitSession::new(), op).await
    }

    pub async fn register_token(&self, conn: &APSConnection) -> Result<(), PushError> {
        let token = conn.get_token().await;
        let op = TokenRegistrationOperation(TokenRegistrationRequest {
            registration: Some(TokenRegistration {
                token: Some(token.to_vec()),
                bundle_id: Some(self.bundleid.to_string()),
                environment: Some(self.env as i32),
                skip_bundle_id_check: Some(false),
            }),
        });
        self.perform(&CloudKitSession::new(), op).await
    }

    pub async fn decline_participant(&self, share_url: &str) -> Result<(), PushError> {
        let result = self.fetch_share_url(share_url).await?;

        let my_participant = result
            .share_metadata
            .as_ref()
            .expect("No share metadata?")
            .caller_participant
            .as_ref()
            .expect("No caller participant?");
        let share_record = result
            .share_record
            .as_ref()
            .expect("No share record?")
            .share_info
            .as_ref()
            .expect("No share info?");

        let op = ShareDeclineOperation(ShareDeclineRequest {
            share_id: share_record.identifier.clone(),
            participant_id: my_participant
                .participant_id
                .as_ref()
                .expect("No pid!")
                .name
                .clone(),
            protection_info: None,
        });

        self.perform(&CloudKitSession::new(), op).await?;
        Ok(())
    }

    pub async fn accept_participant(
        &self,
        client: &KeychainClient<T>,
        pcs_service: &PCSService<'_>,
        invitation: &[u8],
        share_url: &str,
    ) -> Result<(), PushError> {
        let invitation = Invitation::decode(&mut Cursor::new(invitation))?;

        let parsed_invitation: PCSShareProtection =
            rasn::der::decode(invitation.protection_info()).expect("Bad accept protection?");
        let data = client.state.read().await;
        let using_key = parsed_invitation.get_private_key(&*data, pcs_service)?;
        let (_, decrypted) = parsed_invitation.decrypt_with_keychain(&*data, pcs_service, false)?;
        drop(data);

        let share_key: PCSKeyRef = rasn::der::decode(
            &parsed_invitation
                .get_key_attribute(9)
                .expect("No share key??"),
        )
        .expect("Bad share keY??");
        let parsed_invitation = PCSShareProtection::create_participant(
            &using_key.key(),
            &decrypted,
            &ParticipantMeta {
                share_key: CompactECKey::decompress(
                    share_key
                        .pub_key
                        .to_vec()
                        .try_into()
                        .expect("Wrong size pub key!"),
                ),
                sign_with_private_key: Some(using_key.clone()),
            },
        )?;

        let result = self.fetch_share_url(share_url).await?;

        let my_participant = result
            .share_metadata
            .as_ref()
            .expect("No share metadata?")
            .caller_participant
            .as_ref()
            .expect("No caller participant?");
        let share_record = result
            .share_record
            .as_ref()
            .expect("No share record?")
            .share_info
            .as_ref()
            .expect("No share info?");

        let accept = ShareAcceptOperation(ShareAcceptRequest {
            share_id: share_record.identifier.clone(),
            public_key: Some(ProtectionInfo {
                protection_info: Some(using_key.key().compress().to_vec()),
                protection_info_tag: None,
            }),
            protection_info: Some(parsed_invitation.to_protection_info(false)?),
            participant_id: my_participant.participant_id.clone().expect("No pid!").name,
            public_key_version: my_participant.public_key_version.clone(),
            accepted_in_process: Some(true),
            ..Default::default()
        });

        let result = self.perform(&CloudKitSession::new(), accept).await?;

        Ok(())
    }

    pub async fn query_user(&self, handle: &str) -> Result<User, PushError> {
        let alias = handle_to_alias(handle);
        let query = UserQueryOperation(UserQueryRequest {
            alias: Some(alias),
            public_key_requested: Some(true),
        });

        let response = self
            .perform(&CloudKitSession::new(), query)
            .await?
            .ok_or(PushError::UserNotFound)?;
        if response.protection_info.is_none() {
            return Err(PushError::UserNotFound);
        }
        Ok(response)
    }

    async fn create_participant(
        &self,
        handle: &str,
        pcs_service: &PCSService<'_>,
        sharer_key: &PCSPrivateKey,
    ) -> Result<(Participant, Vec<u8>), PushError> {
        let contactinfo = handle_to_contact(handle);

        let response = self.query_user(handle).await?;
        let user_public = CompactECKey::decompress(
            response
                .protection_info
                .as_ref()
                .expect("User has no prot info?")
                .protection_info()
                .try_into()
                .expect("Bad prot info len!"),
        );

        let participant_key = CompactECKey::new()?;
        let self_prot_info = PCSShareProtection::create_participant(
            &user_public,
            &[participant_key.clone()],
            &ParticipantMeta {
                share_key: CompactECKey::decompress(sharer_key.key().compress()),
                sign_with_private_key: None,
            },
        )?;

        let invitation = Invitation {
            protection_info: Some(rasn::der::encode(&self_prot_info).expect("Failed to encode")),
            public_key: Some(user_public.compress().to_vec()),
        };

        Ok((
            Participant {
                participant_id: Some(Identifier {
                    name: Some(Uuid::new_v4().to_string().to_uppercase()),
                    r#type: Some(identifier::Type::User as i32),
                }),
                contact_information: Some(contactinfo),
                // 1 for pending, 2 for accepted, 3 for removed
                state: Some(1),
                participant_type: Some(3),
                permission: Some(3),
                inviter_id: None,
                created_in_process: Some(true),
                public_key: Some(ProtectionInfo {
                    protection_info: Some(user_public.compress().to_vec()),
                    protection_info_tag: None,
                }),
                public_key_version: Some(pcs_service.r#type as i32),
                accepted_in_process: Some(false),
                is_org_user: Some(false),
                protection_info_public_key: Some(participant_key.compress().to_vec()),
                key_health: Some(1),
                is_annonymous_invited_participant: Some(false),
                is_approved_requestor: Some(false),
                ..Default::default()
            },
            invitation.encode_to_vec(),
        ))
    }

    pub async fn remove_participant(
        &self,
        config: &mut PCSZoneConfig,
        client: &KeychainClient<T>,
        pcs_service: &PCSService<'_>,
        share: &mut CloudKitShare,
        participant_id: &str,
    ) -> Result<(), PushError> {
        let participant = share
            .share_info
            .participants
            .iter_mut()
            .find(|i| get_participant_id(i) == participant_id)
            .expect("Participant to remove not found!");
        participant.key_health = Some(0);
        participant.state = Some(3);

        self.update_zone_share(config, client, pcs_service, share)
            .await?;

        Ok(())
    }

    pub async fn add_participant(
        &self,
        config: &mut PCSZoneConfig,
        client: &KeychainClient<T>,
        pcs_service: &PCSService<'_>,
        share: &mut CloudKitShare,
        handle: &str,
    ) -> Result<Vec<u8>, PushError> {
        let service =
            PCSPrivateKey::get_service_key(client, pcs_service, self.client.config.as_ref())
                .await?;
        let (participant, invitation) = self
            .create_participant(handle, pcs_service, &service)
            .await?;
        let contact_information = participant
            .contact_information
            .as_ref()
            .expect("contact information");
        share.share_info.participants.retain(|p| {
            let Some(i) = &p.contact_information else {
                return true;
            };
            if i.email_address.is_some() && i.email_address == contact_information.email_address {
                return false;
            };
            if i.phone_number.is_some() && i.phone_number == contact_information.phone_number {
                return false;
            };
            true
        });
        share.share_info.participants.push(participant);
        self.update_zone_share(config, client, pcs_service, share)
            .await?;
        Ok(invitation)
    }

    pub async fn update_zone_share(
        &self,
        config: &mut PCSZoneConfig,
        client: &KeychainClient<T>,
        pcs_service: &PCSService<'_>,
        share: &mut CloudKitShare,
    ) -> Result<(), PushError> {
        let service =
            PCSPrivateKey::get_service_key(client, pcs_service, self.client.config.as_ref())
                .await?;

        // STEP 1. Find my participant
        let my_participant = self.get_my_participant(&service, &share.share_info);

        // STEP 2. Decrypt the existing protection info
        let my_participant_prot = PCSShareProtection::from_protection_info(
            &my_participant
                .protection_info
                .as_ref()
                .expect("No participant protection info!"),
        );
        let data = client.state.read().await;
        let (_, decrypted_keys) =
            my_participant_prot.decrypt_with_keychain(&*data, pcs_service, true)?;
        drop(data);

        // STEP 3. Decrypt the existing invited PCS
        let (invited, invited_keys, roll_count) =
            if let Some(invited_pcs) = &share.share_info.invited_pcs {
                let invited_protection = PCSShareProtection::from_protection_info(invited_pcs);
                let owner_key = invited_protection.get_signer();
                // it's signed with the owner private key.
                let result = invited_protection.decode(&decrypted_keys, owner_key.as_ref())?;
                (result.0, result.1, invited_protection.get_roll_count() + 2)
            } else {
                (vec![], vec![], 1)
            };

        // get existing keys
        let my_key = get_participant_prot_key(my_participant)?;
        let other_keys = share
            .share_info
            .participants
            .iter()
            .filter_map(|i| {
                // we've been removed.
                if i.state() == 3 {
                    return None;
                }
                let key = get_participant_prot_key(i).ok()?;
                if key.compress() == my_key.compress() {
                    None
                } else {
                    Some(key)
                }
            })
            .collect::<Vec<_>>();

        let invited_key = CompactECKey::new()?;
        let invited_protection = PCSShareProtection::create(
            &my_key,
            &[invited_key.clone()],
            &other_keys,
            PCSKey::random(),
            // interestingly enough we don't use the signing key here... I wonder why
            // maybe because outwardly the signing key doesn't exist and the encryption key is the "owner key"
            Some(&service.key()),
            &[],
            invited.first().cloned(),
            roll_count,
            None,
            true,
        )?;
        share.share_info.invited_pcs = Some(invited_protection.to_protection_info(false)?);

        let (self_master, self_ec, roll) =
            if let Some(self_added) = &share.share_info.self_added_pcs {
                let protection = PCSShareProtection::from_protection_info(self_added);
                let (self_add_pcs_keys, self_add_keys) =
                    protection.decode(&invited_keys, None::<&CompactECKey<Public>>)?;

                let key = self_add_pcs_keys
                    .first()
                    .expect("no first pcs key?")
                    .clone();
                (key, self_add_keys, protection.get_roll_count() + 2)
            } else {
                (PCSKey::random(), vec![CompactECKey::new()?], 1)
            };

        let self_added_protection = PCSShareProtection::create(
            &invited_key,
            &self_ec,
            &self_ec,
            self_master,
            None,
            &[],
            None,
            roll,
            None,
            false,
        )?;
        share.share_info.self_added_pcs = Some(self_added_protection.to_protection_info(false)?);

        let zone_update =
            ZoneSaveOperation::roll_keys(config, &[service.key(), invited_key.clone()])?;
        let share_record_id = record_identifier(config.identifier.clone(), "cloudkit.zoneshare");

        // calculate short token hash from self add EC key
        if let Some(self_ec) = self_ec.first() {
            let public_sharing_key = rasn::der::encode(&PCSKeyRef {
                keytype: 1,
                pub_key: self_ec.compress_private_small().to_vec().into(),
            })
            .expect("Failed to encode ref?");
            share.public_sharing_key = public_sharing_key;
            let full_token = share.get_full_token();
            let sharing_token = share.get_sharing_token();
            let short_token_hash = share.get_short_token_hash();

            assert!(
                share.share_info.short_token_hash.is_none()
                    || share.share_info.short_token_hash == Some(short_token_hash.to_vec())
            );
            share.share_info.short_token_hash = Some(short_token_hash.to_vec());

            if share.url.is_none() {
                let cipher = AesGcm::<Aes128, U16>::new(&sharing_token.into());
                let nonce: [u8; 16] = rand::random();
                let encrypted = cipher
                    .encrypt(Nonce::from_slice(&nonce), full_token.as_bytes())
                    .expect("Failed to encrypt");

                let encryptor = PCSEncryptor {
                    keys: config.default_record_keys.clone(),
                    record_id: share_record_id.clone(),
                };
                let public_encrypted =
                    encryptor.encrypt_data(&share.public_sharing_key, "encryptedPublicSharingKey");

                share.url = Some(StableUrl {
                    routing_key: None, // populated by server
                    short_token_hash: Some(short_token_hash.to_vec()),
                    protected_full_token: Some([nonce.to_vec(), encrypted].concat()),
                    encrypted_public_sharing_key: Some(public_encrypted),
                    displayed_hostname: Some("www.icloud.com".to_string()),
                })
            }
        }

        let mut saved =
            SaveRecordOperation::try_new(share_record_id, share.clone(), Some(&config), true)?;
        let record = saved.0.record.as_mut().unwrap();
        record.share_info = Some(share.share_info.clone());
        record.stable_url = share.url.clone();
        record.plugin_fields = ZoneUpdatePlugin {
            zone_update_data: zone_update.0.zone.as_ref().unwrap().encode_to_vec(),
        }
        .to_record_encrypted(None::<&PCSEncryptor>);

        let result = self
            .perform(&CloudKitSession::new(), saved)
            .await?
            .expect("no share save result!");
        share.share_info = result.share_info.expect("No share save info!");
        share.url = result.stable_url;

        let mut items = self.keys.lock().await;
        let zone_name = config.identifier.value.as_ref().unwrap().name().to_string();
        items.insert(zone_name, config.clone());

        Ok(())
    }

    pub fn build_request<Op: CloudKitOp>(
        &self,
        operation: &Op,
        config: &dyn OSConfig,
        is_first: bool,
        is_last: bool,
        uuid: String,
        isolation_level: IsolationLevel,
    ) -> Vec<u8> {
        let operation = self.build_request_operation(
            operation,
            config,
            is_first,
            is_last,
            uuid,
            isolation_level,
        );
        Self::frame_request_operation(&operation)
    }

    fn build_request_operation<Op: CloudKitOp>(
        &self,
        operation: &Op,
        config: &dyn OSConfig,
        is_first: bool,
        is_last: bool,
        uuid: String,
        isolation_level: IsolationLevel,
    ) -> cloudkit_proto::RequestOperation {
        let debugmeta = config.get_debug_meta();
        let mut op = cloudkit_proto::RequestOperation {
            header: if is_first {
                Some(cloudkit_proto::request_operation::Header {
                    user_token: None,
                    application_container: Some(self.containerid.to_string()),
                    application_bundle: Some(self.bundleid.to_string()),
                    application_version: None,
                    application_config_version: None,
                    global_config_version: None,
                    device_identifier: if Op::is_fetch() {
                        None
                    } else {
                        Some(cloudkit_proto::Identifier {
                            name: Some(config.get_device_uuid()),
                            r#type: Some(cloudkit_proto::identifier::Type::Device.into()),
                        })
                    },
                    device_software_version: Some(debugmeta.user_version),
                    device_hardware_version: Some(debugmeta.hardware_version),
                    device_library_name: Some("com.apple.cloudkit.CloudKitDaemon".to_string()), // ever different??
                    device_library_version: Some("1970".to_string()),
                    device_flow_control_key: if Op::is_flow() {
                        Some(format!(
                            "{}-{}",
                            Op::flow_control_key(),
                            self.database_type.ck_type()
                        ))
                    } else {
                        None
                    },
                    device_flow_control_budget: if Op::is_flow() { Some(0) } else { None },
                    device_flow_control_budget_cap: if Op::is_flow() { Some(0) } else { None },
                    device_flow_control_regeneration: if Op::is_flow() {
                        Some(0.0f32)
                    } else {
                        None
                    },
                    device_protocol_version: None,
                    locale: Op::locale(),
                    mmcs_protocol_version: Some("5.0".to_string()),
                    application_container_environment: Some(self.env.into()),
                    client_change_token: None,
                    device_assigned_name: if Op::is_fetch() {
                        None
                    } else {
                        Some(config.get_device_name())
                    },
                    device_hardware_id: if Op::is_fetch() {
                        None
                    } else {
                        Some(config.get_udid())
                    },
                    target_database: Some(self.database_type.into()),
                    user_id_container_id: None,
                    isolation_level: Some(isolation_level.into()),
                    group: if Op::is_grouped() {
                        Some("EphemeralGroup".to_string())
                    } else {
                        None
                    }, // initialfetch sometimes
                    unk1: Some(0),
                    mmcs_headers: if Op::provides_assets() {
                        Some(cloudkit_proto::request_operation::header::MmcsHeaders {
                            headers: get_headers(config.get_mme_clientinfo(
                                "com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)",
                            ))
                            .into_iter()
                            .map(|(h, v)| cloudkit_proto::NamedHeader {
                                name: Some(h.to_string()),
                                value: Some(v),
                            })
                            .collect(),
                            unk1: Some(0),
                        })
                    } else {
                        None
                    },
                    active_throttling_labels: Vec::new(),
                    unk2: if Op::is_fetch() {
                        None
                    } else {
                        Some(encode_hex(&sha1(config.get_device_uuid().as_bytes())))
                    }, // tied to user or device, can be random
                    device_serial: if Op::is_fetch() {
                        None
                    } else {
                        Some(debugmeta.serial_number)
                    },
                    unk3: Some(0),
                    unk4: Some(1),
                })
            } else {
                None
            },
            request: Some(cloudkit_proto::Operation {
                operation_uuid: Some(uuid),
                r#type: Some(Op::operation().into()),
                synchronous_mode: None,
                last: Some(is_last),
            }),
            ..Default::default()
        };
        operation.set_request(&mut op);
        op
    }

    fn frame_request_operation(operation: &cloudkit_proto::RequestOperation) -> Vec<u8> {
        let encoded = operation.encode_to_vec();
        let mut buf: Vec<u8> = encode_uleb128(encoded.len() as u64);
        buf.extend(encoded);
        buf
    }

    fn parse_operation_responses<Op: CloudKitOp>(
        &self,
        request_identity: &CloudKitRequestIdentity,
        response: &[ResponseOperation],
    ) -> Result<CloudKitBatchResponse<Op::Response>, PushError> {
        validate_cloudkit_response_identities(request_identity, response)?;
        let outcomes = request_identity
            .operation_uuids()
            .iter()
            .enumerate()
            .map(|(request_index, request_uuid)| {
                let mut matching = response.iter().filter(|response| {
                    response
                        .response
                        .as_ref()
                        .and_then(|operation| operation.operation_uuid.as_deref())
                        == Some(request_uuid.as_str())
                });
                let Some(operation_response) = matching.next() else {
                    return CloudKitOperationOutcome {
                        request_index,
                        operation_uuid: request_uuid.clone(),
                        result: Err(cloudkit_protocol_error(
                            "CloudKit operation response was missing",
                        )),
                        retry_after: None,
                        failure_class: Some(CloudKitFailureClass::Unknown),
                    };
                };
                if matching.next().is_some() {
                    return CloudKitOperationOutcome {
                        request_index,
                        operation_uuid: request_uuid.clone(),
                        result: Err(cloudkit_protocol_error(
                            "CloudKit operation response was duplicated",
                        )),
                        retry_after: None,
                        failure_class: Some(CloudKitFailureClass::Unknown),
                    };
                }

                let Some(result) = operation_response.result.as_ref() else {
                    return CloudKitOperationOutcome {
                        request_index,
                        operation_uuid: request_uuid.clone(),
                        result: Err(cloudkit_protocol_error(
                            "CloudKit operation result was missing",
                        )),
                        retry_after: None,
                        failure_class: Some(CloudKitFailureClass::Unknown),
                    };
                };
                let retry_after = cloudkit_retry_after(result);
                if result.code() != cloudkit_proto::response_operation::result::Code::Success {
                    let failure_class = classify_cloudkit_failure(result);
                    warn!(
                        "CloudKit {:?} operation {} failed ({failure_class:?}, retry_after={:?})",
                        Op::operation(),
                        request_index,
                        retry_after,
                    );
                    let error = content_safe_cloudkit_error(result);
                    return CloudKitOperationOutcome {
                        request_index,
                        operation_uuid: request_uuid.clone(),
                        result: Err(error),
                        retry_after,
                        failure_class: Some(failure_class),
                    };
                }

                CloudKitOperationOutcome {
                    request_index,
                    operation_uuid: request_uuid.clone(),
                    result: Op::retrieve_response(operation_response),
                    retry_after: None,
                    failure_class: None,
                }
            })
            .collect();

        Ok(CloudKitBatchResponse {
            request_identity: request_identity.clone(),
            outcomes,
        })
    }

    pub async fn perform_operations_detailed<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        ops: &[Op],
        isolation_level: IsolationLevel,
    ) -> Result<CloudKitBatchResponse<Op::Response>, CloudKitRequestFailure> {
        self.perform_operations_detailed_with_policy(
            session,
            ops,
            isolation_level,
            &CloudKitRetryPolicy::default(),
        )
        .await
    }

    pub async fn perform_operations_detailed_with_policy<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        ops: &[Op],
        isolation_level: IsolationLevel,
        retry_policy: &CloudKitRetryPolicy,
    ) -> Result<CloudKitBatchResponse<Op::Response>, CloudKitRequestFailure> {
        let request_identity = CloudKitRequestIdentity::generated(ops.len());
        self.perform_operations_detailed_with_identity_internal(
            session,
            ops,
            isolation_level,
            retry_policy,
            request_identity,
            true,
            None,
            None,
        )
        .await
    }

    /// Performs one identified request without any automatic network or
    /// authentication replay. This is the only safe primitive for a durable
    /// caller that must classify a missing response as an unknown outcome.
    pub async fn perform_operations_detailed_once_with_identity<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        ops: &[Op],
        isolation_level: IsolationLevel,
        retry_policy: &CloudKitRetryPolicy,
        request_identity: CloudKitRequestIdentity,
        prepared_authentication: CloudKitPreparedAuthentication<T>,
    ) -> Result<CloudKitBatchResponse<Op::Response>, CloudKitRequestFailure> {
        if retry_policy.request_timeout.is_zero()
            || retry_policy.request_timeout > CLOUDKIT_MAX_ONE_SHOT_REQUEST_TIMEOUT
        {
            return Err(CloudKitRequestFailure {
                error: cloudkit_invalid_input(
                    "CloudKit one-shot request timeout was outside the supported range",
                ),
                retry_after: None,
                failure_class: None,
                request_identity: Some(request_identity),
                outcome_may_be_committed: false,
            });
        }
        let Some(deadline) = tokio::time::Instant::now().checked_add(retry_policy.request_timeout)
        else {
            return Err(CloudKitRequestFailure {
                error: cloudkit_invalid_input("CloudKit one-shot request deadline overflowed"),
                retry_after: None,
                failure_class: None,
                request_identity: Some(request_identity),
                outcome_may_be_committed: false,
            });
        };
        self.perform_operations_detailed_with_identity_internal(
            session,
            ops,
            isolation_level,
            retry_policy,
            request_identity,
            false,
            Some(prepared_authentication),
            Some(deadline),
        )
        .await
    }

    /// Refreshes CloudKit authentication, if required, before a durable caller
    /// crosses its remote-submission ambiguity boundary.
    pub async fn prepare_operations_authentication(
        &self,
    ) -> Result<CloudKitPreparedAuthentication<T>, PushError> {
        let cloudkit_token = self
            .client
            .token_provider
            .get_mme_token("cloudKitToken")
            .await?;
        let anisette_headers = {
            let mut locked = self.client.anisette.lock().await;
            cloudkit_anisette_header_map(locked.get_headers().await?)?
        };
        Ok(CloudKitPreparedAuthentication {
            client: self.client.clone(),
            user_id: self.user_id.clone(),
            bundle_id: self.bundleid.to_owned(),
            container_id: self.containerid.to_owned(),
            database_type: self.database_type,
            cloudkit_token,
            anisette_headers,
        })
    }

    /// Prepares one warm semantic read without provisioning or refreshing the
    /// MobileMe delegate. An explicit login/bootstrap must already have opened
    /// the container and populated the token cache.
    ///
    /// Generating anisette headers is authentication work and may update
    /// session or ADI state. It is deliberately outside the guarantee below,
    /// which is limited to zero CloudKit content, key, or trust mutation.
    async fn prepare_semantic_read_authentication(
        &self,
    ) -> Result<CloudKitPreparedAuthentication<T>, PushError> {
        #[cfg(test)]
        if CLOUDKIT_TEST_WARM_AUTHENTICATION.try_with(|_| ()).is_ok() {
            return Ok(CloudKitPreparedAuthentication {
                client: self.client.clone(),
                user_id: self.user_id.clone(),
                bundle_id: self.bundleid.to_owned(),
                container_id: self.containerid.to_owned(),
                database_type: self.database_type,
                cloudkit_token: "semantic-test-warm-token".to_owned(),
                anisette_headers: HeaderMap::new(),
            });
        }

        let cloudkit_token = self
            .client
            .token_provider
            .get_mme_token_cached("cloudKitToken")
            .await?;
        let anisette_headers = {
            let mut locked = self.client.anisette.lock().await;
            cloudkit_anisette_header_map(locked.get_headers().await?)?
        };
        Ok(CloudKitPreparedAuthentication {
            client: self.client.clone(),
            user_id: self.user_id.clone(),
            bundle_id: self.bundleid.to_owned(),
            container_id: self.containerid.to_owned(),
            database_type: self.database_type,
            cloudkit_token,
            anisette_headers,
        })
    }

    /// Executes only operations admitted by the closed semantic read policy.
    ///
    /// This transport seam never performs `ckAppInit`, token refresh, an HTTP
    /// authentication replay, or a CloudKit content/key/trust write. It may
    /// perform the authentication/ADI header work documented above.
    pub async fn perform_semantic_read_only_operations<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        operations: &[Op],
        isolation_level: IsolationLevel,
    ) -> Result<Vec<Result<Op::Response, PushError>>, PushError> {
        let _recorded = record_semantic_read_operations(operations)?;
        let mut responses = Vec::with_capacity(operations.len());
        for batch in operations.chunks(CLOUDKIT_MAX_OPERATIONS_PER_REQUEST) {
            let prepared_authentication = self.prepare_semantic_read_authentication().await?;
            let request_identity = CloudKitRequestIdentity::generated(batch.len());
            let retry_policy = CloudKitRetryPolicy {
                max_attempts: 1,
                ..CloudKitRetryPolicy::default()
            };
            responses.extend(
                self.perform_operations_detailed_once_with_identity(
                    session,
                    batch,
                    isolation_level,
                    &retry_policy,
                    request_identity,
                    prepared_authentication,
                )
                .await
                .map_err(|failure| failure.error)?
                .outcomes
                .into_iter()
                .map(|outcome| outcome.result),
            );
        }
        Ok(responses)
    }

    pub async fn perform_semantic_read_only_operations_checked<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        operations: &[Op],
        isolation_level: IsolationLevel,
    ) -> Result<Vec<Op::Response>, PushError> {
        self.perform_semantic_read_only_operations(session, operations, isolation_level)
            .await?
            .into_iter()
            .collect()
    }

    pub async fn perform_semantic_read_only<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        operation: Op,
    ) -> Result<Op::Response, PushError> {
        Ok(self
            .perform_semantic_read_only_operations(session, &[operation], IsolationLevel::Zone)
            .await?
            .remove(0)?)
    }

    async fn perform_operations_detailed_with_identity_internal<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        ops: &[Op],
        isolation_level: IsolationLevel,
        retry_policy: &CloudKitRetryPolicy,
        request_identity: CloudKitRequestIdentity,
        allow_automatic_replay: bool,
        prepared_authentication: Option<CloudKitPreparedAuthentication<T>>,
        one_shot_deadline: Option<tokio::time::Instant>,
    ) -> Result<CloudKitBatchResponse<Op::Response>, CloudKitRequestFailure> {
        if let Err(error) = request_identity.validate_operation_count(ops.len()) {
            return Err(error.into());
        }
        if allow_automatic_replay == prepared_authentication.is_some() {
            return Err(cloudkit_invalid_input(
                "CloudKit authentication mode did not match replay policy",
            )
            .into());
        }
        if allow_automatic_replay == one_shot_deadline.is_some() {
            return Err(cloudkit_invalid_input(
                "CloudKit deadline mode did not match replay policy",
            )
            .into());
        }
        if let Some(prepared) = prepared_authentication.as_ref() {
            if !Arc::ptr_eq(&prepared.client, &self.client)
                || prepared.user_id != self.user_id
                || prepared.bundle_id != self.bundleid
                || prepared.container_id != self.containerid
                || prepared.database_type != self.database_type
            {
                return Err(cloudkit_invalid_input(
                    "CloudKit prepared authentication scope did not match request",
                )
                .into());
            }
        }
        let failure_identity = request_identity.clone();
        let mut submission_started = false;
        let result: Result<CloudKitBatchResponse<Op::Response>, CloudKitRequestFailure> = async {
        if ops.is_empty() {
            return Ok(CloudKitBatchResponse {
                request_identity: request_identity.clone(),
                outcomes: vec![],
            });
        }
        if ops.len() > CLOUDKIT_MAX_OPERATIONS_PER_REQUEST {
            return Err(cloudkit_invalid_input(
                "CloudKit operation batch exceeded the request limit",
            )
            .into());
        }

        // The semantic pull owns the exclusive pause permit. Every other CloudKit
        // request must fail closed before request construction, authentication, or
        // transport so startup trust repair, Find My, and future writer call sites
        // cannot bypass the higher-level Passwords gate.
        let _writer_operation_permit = if cloudkit_writer_permit_required(ops)
            && !cloudkit_writer_operation_is_held()
        {
            Some(try_acquire_cloudkit_operation()?)
        } else {
            None
        };

        let custom_headers = ops[0].custom_headers();
        validate_cloudkit_operation_headers(&custom_headers)?;
        for operation in ops {
            if let Some(semantic_operation) = operation.semantic_read_operation() {
                validate_semantic_read_request_headers(semantic_operation, &custom_headers)?;
            }
        }

        let request = ops
            .iter()
            .enumerate()
            .map(|(idx, op)| {
                let request_operation = self.build_request_operation(
                    op,
                    self.client.config.as_ref(),
                    idx == 0,
                    idx == ops.len() - 1,
                    request_identity.operation_uuids()[idx].clone(),
                    isolation_level,
                );
                if let Some(semantic_operation) = op.semantic_read_operation() {
                    validate_semantic_read_request_operation(
                        semantic_operation,
                        Op::link(),
                        op.retry_safety(),
                        &request_operation,
                    )?;
                }
                Ok(Self::frame_request_operation(&request_operation))
            })
            .collect::<Result<Vec<_>, PushError>>()?
            .concat();
        let compressed_request = gzip_normal(&request).map_err(PushError::from)?;
        let automatic_retry_safe = allow_automatic_replay
            && ops
                .iter()
                .all(|op| op.retry_safety() != CloudKitRetrySafety::Never);
        let max_attempts = retry_policy.max_attempts.max(1);
        let mut authentication_refreshed = false;

        let mut attempt = 1usize;
        loop {
            let token = if allow_automatic_replay {
                self.client
                    .token_provider
                    .get_mme_token("cloudKitToken")
                    .await?
            } else {
                prepared_authentication
                    .as_ref()
                    .ok_or_else(|| {
                        cloudkit_invalid_input("CloudKit prepared authentication was missing")
                    })?
                    .cloudkit_token
                    .clone()
            };

            let request_client = if allow_automatic_replay {
                &*REQWEST
            } else {
                &*REQWEST_NO_REDIRECT
            };
            let request = self
                .headers(
                    &self.client,
                    request_client.post(Op::link()),
                    session,
                    &self.database_type,
                    request_identity.http_request_uuid(),
                    prepared_authentication
                        .as_ref()
                        .map(|prepared| &prepared.anisette_headers),
                )
                .await?
                .header("x-cloudkit-userid", &self.user_id)
                .header("x-cloudkit-authtoken", &token)
                .headers(custom_headers.clone())
                .body(compressed_request.clone());

            if one_shot_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
            {
                return Err(PushError::IoError(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "CloudKit one-shot operation timed out before remote submission",
                ))
                .into());
            }
            // Conservatively cross the ambiguity boundary before entering
            // reqwest. A transport error after this point cannot prove that no
            // request bytes reached Apple.
            submission_started = true;
            let response = if let Some(deadline) = one_shot_deadline {
                within_cloudkit_one_shot_deadline(
                    deadline,
                    send_cloudkit_http_request(request),
                    "CloudKit one-shot operation timed out before receiving response headers",
                )
                .await?
            } else {
                match tokio::time::timeout(
                    retry_policy.request_timeout,
                    send_cloudkit_http_request(request),
                )
                .await
                {
                    Ok(Ok(response)) => response,
                    Ok(Err(error)) => {
                        if matches!(error, PushError::RequestError(_))
                            && automatic_retry_safe
                            && attempt < max_attempts
                        {
                            let delay = retry_delay(retry_policy, attempt, None)
                                .unwrap_or(Duration::ZERO);
                            warn!(
                                "CloudKit {:?} request transport failed; retrying attempt {} after {:?}",
                                Op::operation(),
                                attempt + 1,
                                delay,
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(error.into());
                    }
                    Err(_) => {
                        if automatic_retry_safe && attempt < max_attempts {
                            let delay = retry_delay(retry_policy, attempt, None)
                                .unwrap_or(Duration::ZERO);
                            warn!(
                                "CloudKit {:?} request timed out; retrying attempt {} after {:?}",
                                Op::operation(),
                                attempt + 1,
                                delay,
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(PushError::IoError(std::io::Error::new(
                            ErrorKind::TimedOut,
                            "CloudKit request timed out",
                        ))
                        .into());
                    }
                }
            };

            let status = response.status();
            let retry_after =
                parse_retry_after(response.headers().get(reqwest::header::RETRY_AFTER));
            if allow_automatic_replay
                && status == reqwest::StatusCode::UNAUTHORIZED
                && !authentication_refreshed
            {
                self.client.token_provider.refresh_mme().await?;
                authentication_refreshed = true;
                continue;
            }
            let transient_status = status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || status == reqwest::StatusCode::REQUEST_TIMEOUT
                || status.is_server_error();
            if transient_status && automatic_retry_safe && attempt < max_attempts {
                if let Some(delay) = retry_delay(retry_policy, attempt, retry_after) {
                    warn!(
                        "CloudKit {:?} request returned HTTP {}; retrying attempt {} after {:?}",
                        Op::operation(),
                        status.as_u16(),
                        attempt + 1,
                        delay,
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
            }
            if !status.is_success() {
                let failure_class = classify_cloudkit_http_failure(status);
                return Err(CloudKitRequestFailure {
                    error: PushError::CloudKitHttpError {
                        status: status.as_u16(),
                        retry_after,
                    },
                    retry_after,
                    failure_class: Some(failure_class),
                    request_identity: None,
                    outcome_may_be_committed: false,
                });
            }

            let body = if let Some(deadline) = one_shot_deadline {
                within_cloudkit_one_shot_deadline(
                    deadline,
                    read_cloudkit_http_response_body(response),
                    "CloudKit one-shot operation timed out while reading response body",
                )
                .await?
            } else {
                match tokio::time::timeout(
                    retry_policy.request_timeout,
                    read_cloudkit_http_response_body(response),
                )
                .await
                {
                    Ok(Ok(body)) => body,
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_) => {
                        return Err(PushError::IoError(std::io::Error::new(
                            ErrorKind::TimedOut,
                            "CloudKit response body timed out",
                        ))
                        .into())
                    }
                }
            };
            let response = if let Some(deadline) = one_shot_deadline {
                within_cloudkit_one_shot_deadline(
                    deadline,
                    async move {
                        tokio::task::spawn_blocking(move || decode_cloudkit_response_body(body))
                            .await
                            .map_err(|_| {
                                cloudkit_protocol_error(
                                    "CloudKit response decoder task failed unexpectedly",
                                )
                            })?
                    },
                    "CloudKit one-shot operation timed out while decoding response body",
                )
                .await?
            } else {
                decode_cloudkit_response_body(body)?
            };

            return Ok(self.parse_operation_responses::<Op>(&request_identity, &response)?);
        }
        }
        .await;
        result.map_err(|mut failure| {
            failure.request_identity = Some(failure_identity);
            failure.outcome_may_be_committed |= submission_started;
            failure
        })
    }

    pub async fn perform_operations_checked<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        ops: &[Op],
        isolation_level: IsolationLevel,
    ) -> Result<Vec<Op::Response>, PushError> {
        self.perform_operations(session, ops, isolation_level)
            .await?
            .into_iter()
            .collect()
    }

    pub async fn perform_operations<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        ops: &[Op],
        isolation_level: IsolationLevel,
    ) -> Result<Vec<Result<Op::Response, PushError>>, PushError> {
        let mut responses = Vec::with_capacity(ops.len());
        for batch in ops.chunks(CLOUDKIT_MAX_OPERATIONS_PER_REQUEST) {
            responses.extend(
                self.perform_operations_detailed(session, batch, isolation_level)
                    .await
                    .map_err(|failure| failure.error)?
                    .outcomes
                    .into_iter()
                    .map(|outcome| outcome.result),
            );
        }

        Ok(responses)
    }

    pub async fn perform<Op: CloudKitOp>(
        &self,
        session: &CloudKitSession,
        op: Op,
    ) -> Result<Op::Response, PushError> {
        Ok(self
            .perform_operations(session, &[op], IsolationLevel::Zone)
            .await?
            .remove(0)?)
    }

    pub async fn get_assets<V: Write + Send + Sync>(
        &self,
        responses: &[AssetGetResponse],
        assets: Vec<(&cloudkit_proto::Asset, V)>,
    ) -> Result<(), PushError> {
        let mut requests: HashMap<&String, Vec<(&cloudkit_proto::Asset, V)>> = HashMap::new();
        for asset in assets {
            requests
                .entry(
                    asset
                        .0
                        .bundled_request_id
                        .as_ref()
                        .expect("No bundled asset!"),
                )
                .or_default()
                .push(asset);
        }

        let mmcs_config = MMCSConfig {
            mme_client_info: self.client.config.get_mme_clientinfo(
                "com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)",
            ),
            user_agent: self.client.config.get_normal_ua("CloudKit/1970"),
            dataclass: "com.apple.Dataclass.CloudKit",
            mini_ua: self.client.config.get_version_ua(),
            dsid: Some(self.client.state.read().await.dsid.to_string()),
            cloudkit_headers: Default::default(),
            extra_1: None,
            extra_2: None,
        };

        for (request, asset) in requests {
            let response = responses
                .iter()
                .find(|r| r.asset_id.as_ref() == Some(request))
                .expect("No bundled asset!");
            let authorized = AuthorizedOperation {
                body: response.body.clone().expect("No body!!"),
                ..Default::default()
            };

            let assets = asset
                .into_iter()
                .map(|(a, l)| {
                    (
                        a.signature.clone().expect("No signature?"),
                        "", /* unused */
                        FileContainer::new(l),
                        a.protection_info
                            .as_ref()
                            .and_then(|p| p.protection_info.clone()),
                    )
                })
                .collect::<Vec<_>>();

            get_mmcs(&mmcs_config, authorized, assets, |a, b| {}, false).await?;
        }

        Ok(())
    }

    pub async fn upload_asset<F: Read + Send + Sync>(
        &self,
        session: &CloudKitSession,
        zone: &RecordZoneIdentifier,
        mut assets: Vec<CloudKitUploadRequest<F>>,
    ) -> Result<HashMap<String, Vec<cloudkit_proto::Asset>>, PushError> {
        if assets.is_empty() {
            return Ok(HashMap::new()); // empty requests not allowed
        }
        let cloudkit_headers = [
            ("x-cloudkit-app-bundleid", self.bundleid), // these header names are slightly different, do not commonize, blame the stupid apple engineers
            ("x-cloudkit-container", &self.containerid),
            ("x-cloudkit-databasescope", self.database_type.ck_type()),
            ("x-cloudkit-duetpreclearedmode", "None"),
            ("x-cloudkit-environment", "production"),
            ("x-cloudkit-deviceid", &self.client.config.get_udid()),
            (
                "x-cloudkit-zones",
                &zone.value.as_ref().unwrap().name.as_ref().unwrap(),
            ),
            (
                "x-apple-operation-group-id",
                &encode_hex(&session.op_group_id).to_uppercase(),
            ),
            (
                "x-apple-operation-id",
                &encode_hex(&session.op_id).to_uppercase(),
            ),
        ]
        .into_iter()
        .map(|(a, b)| (a, b.to_string()))
        .collect();

        let mmcs_config = MMCSConfig {
            mme_client_info: self.client.config.get_mme_clientinfo(
                "com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)",
            ),
            user_agent: self.client.config.get_normal_ua("CloudKit/1970"),
            dataclass: "com.apple.Dataclass.CloudKit",
            mini_ua: self.client.config.get_version_ua(),
            dsid: Some(self.client.state.read().await.dsid.to_string()),
            cloudkit_headers,
            extra_1: Some("2022-08-11".to_string()),
            extra_2: Some("fxd".to_string()),
        };

        let mut inputs = vec![];
        let mut cloudkit_put: Vec<CloudKitPreparedAsset> = vec![];
        for asset in &mut assets {
            inputs.push((
                &asset.prepared,
                None,
                FileContainer::new(asset.file.take().unwrap()),
            ));
            cloudkit_put.push(CloudKitPreparedAsset {
                record_id: record_identifier(zone.clone(), &asset.record_id),
                prepared: &asset.prepared,
                r#type: asset.record_type.to_string(),
                field_name: asset.field,
            });
        }
        let (headers, body) = put_authorize_body(&mmcs_config, &inputs);
        let operation = UploadAssetOperation::new(cloudkit_put, headers, body);
        let asset_response = self.perform(session, operation).await?;

        let asset_data = asset_response
            .asset_info
            .into_iter()
            .next()
            .expect("No asset info?")
            .asset
            .expect("No asset?");
        let (_, _, receipts) = put_mmcs(
            &mmcs_config,
            inputs,
            AuthorizedOperation {
                url: format!(
                    "{}/{}",
                    asset_data.host.expect("No host??"),
                    asset_data.container.expect("No container??")
                ),
                dsid: asset_data.dsid.expect("No dsid??"),
                body: asset_response.upload_info.expect("No upload info??"),
            },
            |p, t| {},
        )
        .await?;

        let mut item: HashMap<String, Vec<cloudkit_proto::Asset>> = HashMap::new();
        for req in assets {
            item.entry(req.field.to_string())
                .or_default()
                .push(cloudkit_proto::Asset {
                    signature: Some(req.prepared.total_sig.clone()),
                    size: Some(req.prepared.total_len as u64),
                    record_id: Some(record_identifier(zone.clone(), &req.record_id)),
                    upload_receipt: Some(
                        receipts
                            .get(&req.prepared.total_sig)
                            .expect("No receipt for upload??")
                            .clone(),
                    ),
                    protection_info: req.prepared.ford_key.map(|k| ProtectionInfo {
                        protection_info: Some(k.to_vec()),
                        protection_info_tag: None,
                    }),
                    reference_signature: req.prepared.ford.as_ref().map(|f| f.0.to_vec()),
                    ..Default::default()
                });
        }

        Ok(item)
    }
}

#[cfg(test)]
mod cloud_sync_transport_tests {
    use super::*;
    use crate::{
        cloud_messages::{
            CloudMessage, CloudMessageRecordKind, CloudMessageSaveInput, CloudMessagesClient,
        },
        keychain::KeychainClientState,
        util::ungzip,
    };
    use icloud_auth::AppleAccount;
    use omnisette::{AnisetteClient, AnisetteError, LoginClientInfo};
    use std::sync::{Mutex as StdMutex, OnceLock};

    const HTTP_REQUEST_UUID: &str = "11111111-2222-4ABC-8DEF-555555555555";
    const OPERATION_UUID_A: &str = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE";
    const OPERATION_UUID_B: &str = "01234567-89AB-4CDE-8F01-23456789ABCD";

    struct OneShotTestAnisette;

    impl AnisetteProvider for OneShotTestAnisette {
        fn get_anisette_headers(
            &mut self,
        ) -> impl Future<Output = Result<HashMap<String, String>, AnisetteError>> + Send {
            async { Ok(HashMap::new()) }
        }
    }

    struct OneShotTestConfig;

    #[async_trait::async_trait]
    impl OSConfig for OneShotTestConfig {
        fn build_activation_info(&self, _csr: Vec<u8>) -> crate::activation::ActivationInfo {
            unreachable!("one-shot loopback tests do not activate a device")
        }

        fn get_activation_device(&self) -> String {
            "test-device".to_owned()
        }

        async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
            unreachable!("one-shot loopback tests use prepared authentication")
        }

        fn get_protocol_version(&self) -> u32 {
            1
        }

        fn get_register_meta(&self) -> crate::RegisterMeta {
            crate::RegisterMeta {
                hardware_version: "test-hardware".to_owned(),
                os_version: "test-os".to_owned(),
                software_version: "test-software".to_owned(),
            }
        }

        fn get_normal_ua(&self, item: &str) -> String {
            item.to_owned()
        }

        fn get_mme_clientinfo(&self, item: &str) -> String {
            item.to_owned()
        }

        fn get_version_ua(&self) -> String {
            "test-version".to_owned()
        }

        fn get_device_name(&self) -> String {
            "test-device".to_owned()
        }

        fn get_device_uuid(&self) -> String {
            "test-device-uuid".to_owned()
        }

        fn get_private_data(&self) -> plist::Dictionary {
            plist::Dictionary::new()
        }

        fn get_debug_meta(&self) -> crate::DebugMeta {
            crate::DebugMeta {
                user_version: "test-user-version".to_owned(),
                hardware_version: "test-hardware".to_owned(),
                serial_number: "test-serial".to_owned(),
            }
        }

        fn get_login_url(&self) -> &'static str {
            "http://127.0.0.1/unused"
        }

        fn get_serial_number(&self) -> String {
            "test-serial".to_owned()
        }

        fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
            HashMap::new()
        }

        fn get_aoskit_version(&self) -> String {
            "test-aoskit".to_owned()
        }

        fn get_udid(&self) -> String {
            "test-udid".to_owned()
        }
    }

    static BEFORE_HEADERS_ENDPOINT: OnceLock<String> = OnceLock::new();
    static SHARED_BUDGET_ENDPOINT: OnceLock<String> = OnceLock::new();
    static DROPPED_RESPONSE_ENDPOINT: OnceLock<String> = OnceLock::new();
    static REDIRECT_ENDPOINT: OnceLock<String> = OnceLock::new();
    static UNAUTHORIZED_ENDPOINT: OnceLock<String> = OnceLock::new();
    static SERVER_ERROR_ENDPOINT: OnceLock<String> = OnceLock::new();

    async fn read_complete_http_headers(socket: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt;

        let mut request = Vec::with_capacity(1024);
        loop {
            let mut chunk = [0u8; 1024];
            let read = socket.read(&mut chunk).await.unwrap();
            assert!(read > 0, "loopback client closed before sending headers");
            request.extend_from_slice(&chunk[..read]);
            assert!(
                request.len() <= 64 * 1024,
                "loopback request headers too large"
            );
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return String::from_utf8_lossy(&request).into_owned();
            }
        }
    }

    macro_rules! one_shot_loopback_operation {
        ($name:ident, $endpoint:ident) => {
            struct $name;

            impl CloudKitOp for $name {
                type Response = ();

                fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
                    output.zone_retrieve_request = Some(Default::default());
                }

                fn retrieve_response(
                    _response: &cloudkit_proto::ResponseOperation,
                ) -> Result<Self::Response, PushError> {
                    Ok(())
                }

                fn flow_control_key() -> &'static str {
                    "OneShotDeadlineLoopback"
                }

                fn operation() -> cloudkit_proto::operation::Type {
                    cloudkit_proto::operation::Type::ZoneRetrieveType
                }

                fn is_fetch() -> bool {
                    true
                }

                fn link() -> &'static str {
                    $endpoint
                        .get()
                        .expect("loopback endpoint must be initialized")
                }

                fn retry_safety(&self) -> CloudKitRetrySafety {
                    CloudKitRetrySafety::ReadOnly
                }
            }
        };
    }

    one_shot_loopback_operation!(BeforeHeadersOperation, BEFORE_HEADERS_ENDPOINT);
    one_shot_loopback_operation!(SharedBudgetOperation, SHARED_BUDGET_ENDPOINT);
    one_shot_loopback_operation!(DroppedResponseOperation, DROPPED_RESPONSE_ENDPOINT);
    one_shot_loopback_operation!(RedirectOperation, REDIRECT_ENDPOINT);
    one_shot_loopback_operation!(UnauthorizedOperation, UNAUTHORIZED_ENDPOINT);
    one_shot_loopback_operation!(ServerErrorOperation, SERVER_ERROR_ENDPOINT);

    fn one_shot_test_open_container<'a>(
        container: &'a CloudKitContainer<'a>,
    ) -> CloudKitOpenContainer<'a, OneShotTestAnisette> {
        let anisette = Arc::new(tokio::sync::Mutex::new(AnisetteClient::new(
            OneShotTestAnisette,
        )));
        let account = AppleAccount::new_with_anisette(LoginClientInfo::default(), anisette.clone())
            .expect("test Apple account must initialize");
        let config: Arc<dyn OSConfig> = Arc::new(OneShotTestConfig);
        let token_provider = TokenProvider::new(Arc::new(DebugMutex::new(account)), config.clone());
        let client = Arc::new(CloudKitClient {
            anisette,
            state: DebugRwLock::new(CloudKitState::new("test-dsid".to_owned()).unwrap()),
            config,
            token_provider,
        });

        CloudKitOpenContainer {
            container,
            user_id: "test-cloudkit-user".to_owned(),
            client,
            account_dsid: "test-dsid".to_owned(),
            keys: DebugMutex::new(HashMap::new()),
            database_type: container.database_type,
        }
    }

    fn one_shot_test_authentication(
        open: &CloudKitOpenContainer<'_, OneShotTestAnisette>,
    ) -> CloudKitPreparedAuthentication<OneShotTestAnisette> {
        CloudKitPreparedAuthentication {
            client: open.client.clone(),
            user_id: open.user_id.clone(),
            bundle_id: open.bundleid.to_owned(),
            container_id: open.containerid.to_owned(),
            database_type: open.database_type,
            cloudkit_token: "test-cloudkit-token".to_owned(),
            anisette_headers: HeaderMap::new(),
        }
    }

    fn one_shot_test_container() -> CloudKitContainer<'static> {
        CloudKitContainer {
            database_type: Database::PrivateDb,
            bundleid: "com.example.cloudkit-deadline-test",
            containerid: "com.example.cloudkit-deadline-test",
            env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
        }
    }

    #[test]
    fn read_authentication_container_allowlist_requires_exact_identity() {
        let approved = [
            (
                CloudKitReadAuthenticationContainer::Messages,
                "com.apple.imagent",
                "com.apple.messages.cloud",
            ),
            (
                CloudKitReadAuthenticationContainer::Cuttlefish,
                "com.apple.security.cuttlefish",
                "com.apple.security.keychain",
            ),
            (
                CloudKitReadAuthenticationContainer::Securityd,
                "com.apple.securityd",
                "com.apple.security.keychain",
            ),
        ];

        for (allowed, bundleid, containerid) in approved {
            let exact = CloudKitContainer {
                database_type: Database::PrivateDb,
                bundleid,
                containerid,
                env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
            };
            assert!(allowed.matches(&exact));

            let wrong_bundle = CloudKitContainer {
                bundleid: "com.example.unapproved",
                ..exact
            };
            assert!(!allowed.matches(&wrong_bundle));

            let wrong_container = CloudKitContainer {
                containerid: "com.example.unapproved",
                ..exact
            };
            assert!(!allowed.matches(&wrong_container));

            let wrong_database = CloudKitContainer {
                database_type: Database::SharedDb,
                ..exact
            };
            assert!(!allowed.matches(&wrong_database));

            let wrong_environment = CloudKitContainer {
                env: cloudkit_proto::request_operation::header::ContainerEnvironment::Sandbox,
                ..exact
            };
            assert!(!allowed.matches(&wrong_environment));
        }
    }

    #[tokio::test]
    async fn cached_read_authentication_rejects_wrong_container_client_and_account() {
        let messages_container = CloudKitContainer {
            database_type: Database::PrivateDb,
            bundleid: "com.apple.imagent",
            containerid: "com.apple.messages.cloud",
            env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
        };
        let open = one_shot_test_open_container(&messages_container);
        open.validate_read_authentication_identity(
            &open.client,
            CloudKitReadAuthenticationContainer::Messages,
        )
        .await
        .unwrap();

        let wrong_container = one_shot_test_open_container(&SEMANTIC_FAKE_CONTAINER);
        assert!(matches!(
            wrong_container
                .validate_read_authentication_identity(
                    &wrong_container.client,
                    CloudKitReadAuthenticationContainer::Messages,
                )
                .await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));

        let other_client = one_shot_test_open_container(&messages_container).client;
        assert!(matches!(
            open.validate_read_authentication_identity(
                &other_client,
                CloudKitReadAuthenticationContainer::Messages,
            )
            .await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));

        let shared = open.shared();
        assert!(matches!(
            shared
                .validate_read_authentication_identity(
                    &shared.client,
                    CloudKitReadAuthenticationContainer::Messages,
                )
                .await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));

        open.client.state.write().await.dsid = "different-dsid".to_owned();
        assert!(matches!(
            open.validate_read_authentication_identity(
                &open.client,
                CloudKitReadAuthenticationContainer::Messages,
            )
            .await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
    }

    static SEMANTIC_FAKE_CONTAINER: CloudKitContainer<'static> = CloudKitContainer {
        database_type: Database::PrivateDb,
        bundleid: "com.apple.MobileSMS",
        containerid: "com.apple.messages.cloud",
        env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
    };

    fn semantic_test_keychain(
        open: &CloudKitOpenContainer<'static, OneShotTestAnisette>,
    ) -> Arc<KeychainClient<OneShotTestAnisette>> {
        let mut keychain_sync = plist::Dictionary::new();
        keychain_sync.insert(
            "escrowProxyUrl".to_owned(),
            Value::String("https://invalid.test/unused".to_owned()),
        );
        let mut config = plist::Dictionary::new();
        config.insert(
            "com.apple.Dataclass.KeychainSync".to_owned(),
            Value::Dictionary(keychain_sync),
        );
        let delegate = MobileMeDelegateResponse {
            tokens: HashMap::new(),
            config,
        };
        let state =
            KeychainClientState::new("test-dsid".to_owned(), "test-adsid".to_owned(), &delegate)
                .expect("test keychain state");

        Arc::new(KeychainClient {
            anisette: open.client.anisette.clone(),
            token_provider: open.client.token_provider.clone(),
            state: DebugRwLock::new(state),
            config: open.client.config.clone(),
            update_state: Box::new(|_| {}),
            container: tokio::sync::Mutex::new(None),
            container_initialization: tokio::sync::Mutex::new(()),
            security_container: tokio::sync::Mutex::new(None),
            security_container_initialization: tokio::sync::Mutex::new(()),
            client: open.client.clone(),
        })
    }

    #[derive(Clone, Default)]
    struct FaithfulSemanticTransport {
        recorded: Arc<StdMutex<Vec<String>>>,
        invocations: Arc<AtomicUsize>,
    }

    fn validate_semantic_request_target(request: &reqwest::Request) -> Result<(), PushError> {
        let url = request.url();
        if request.method() != reqwest::Method::POST
            || url.scheme() != "https"
            || url.host_str() != Some("gateway.icloud.com")
            || url.port_or_known_default() != Some(443)
        {
            return Err(PushError::CloudKitSemanticOperationDenied);
        }
        Ok(())
    }

    impl FaithfulSemanticTransport {
        fn transport(&self) -> Arc<dyn CloudKitTestHttpTransport> {
            let transport = self.clone();
            Arc::new(move |request| {
                let transport = transport.clone();
                Box::pin(async move {
                    transport.invocations.fetch_add(1, Ordering::SeqCst);
                    transport.handle(request)
                }) as CloudKitTestTransportFuture
            })
        }

        fn recorded(&self) -> Vec<String> {
            self.recorded.lock().expect("recorder lock").clone()
        }

        fn invocations(&self) -> usize {
            self.invocations.load(Ordering::SeqCst)
        }

        fn handle(&self, request: RequestBuilder) -> Result<CloudKitBufferedResponse, PushError> {
            let request = request.build()?;
            validate_semantic_request_target(&request)?;
            if request
                .headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok())
                != Some("gzip")
            {
                return Err(PushError::CloudKitSemanticOperationDenied);
            }
            let compressed = request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .ok_or(PushError::CloudKitSemanticOperationDenied)?;
            let decoded = ungzip(compressed)?;
            let frames = undelimit_response(&decoded)?;
            if frames.is_empty() {
                return Err(PushError::CloudKitSemanticOperationDenied);
            }

            let mut responses = Vec::with_capacity(frames.len());
            for frame in frames {
                let operation = cloudkit_proto::RequestOperation::decode(frame.as_slice())?;
                let logical_operation = self.validate_operation(request.url(), &operation)?;
                self.recorded
                    .lock()
                    .expect("recorder lock")
                    .push(logical_operation.to_owned());
                responses.push(self.response_for(&operation, logical_operation)?);
            }

            let mut body = Vec::new();
            for response in responses {
                let encoded = response.encode_to_vec();
                body.extend(encode_uleb128(encoded.len() as u64));
                body.extend(encoded);
            }
            Ok(CloudKitBufferedResponse {
                status: reqwest::StatusCode::OK,
                headers: HeaderMap::new(),
                body,
            })
        }

        fn validate_operation<'a>(
            &self,
            url: &Url,
            operation: &'a cloudkit_proto::RequestOperation,
        ) -> Result<&'static str, PushError> {
            for semantic_operation in SemanticReadOperation::ALL
                .into_iter()
                .filter(|operation| operation.is_warm_semantic_transport())
            {
                if let Ok(logical_operation) = validate_semantic_read_request_operation(
                    semantic_operation,
                    url.as_str(),
                    CloudKitRetrySafety::ReadOnly,
                    operation,
                ) {
                    return Ok(logical_operation);
                }
            }
            Err(PushError::CloudKitSemanticOperationDenied)
        }

        fn response_for(
            &self,
            operation: &cloudkit_proto::RequestOperation,
            logical_operation: &str,
        ) -> Result<ResponseOperation, PushError> {
            let result = Some(cloudkit_proto::response_operation::Result {
                code: Some(cloudkit_proto::response_operation::result::Code::Success as i32),
                ..Default::default()
            });
            let mut response = ResponseOperation {
                response: operation.request.clone(),
                result,
                ..Default::default()
            };
            match logical_operation {
                "record/sync" => {
                    let zone = operation
                        .retrieve_changes_request
                        .as_ref()
                        .and_then(|request| request.zone_identifier.clone())
                        .ok_or(PushError::CloudKitSemanticOperationDenied)?;
                    let identifier = record_identifier(zone, "faithful-fake-chat-record");
                    response.retrieve_changes_response =
                        Some(cloudkit_proto::RetrieveChangesResponse {
                            change: vec![RecordChange {
                                identifier: Some(identifier.clone()),
                                etag: Some("faithful-fake-etag".to_owned()),
                                record_type: Some(record::Type {
                                    name: Some("chatEncryptedv2".to_owned()),
                                }),
                                r#type: Some(1),
                                record: Some(Record {
                                    record_identifier: Some(identifier),
                                    r#type: Some(record::Type {
                                        name: Some("chatEncryptedv2".to_owned()),
                                    }),
                                    ..Default::default()
                                }),
                            }],
                            status: Some(CLOUDKIT_RECORD_CHANGES_STATUS_COMPLETE),
                            ..Default::default()
                        });
                }
                "zone/retrieve" => {
                    response.zone_retrieve_response = Some(cloudkit_proto::ZoneRetrieveResponse {
                        zone_summary: vec![Default::default()],
                    });
                }
                "Cuttlefish/fetchChanges" | "Cuttlefish/fetchRecoverableTLKShares" => {
                    response.function_invoke_response =
                        Some(cloudkit_proto::FunctionInvokeResponse {
                            serialized_result: Some(Vec::new()),
                        });
                }
                _ => return Err(PushError::CloudKitSemanticOperationDenied),
            }
            Ok(response)
        }
    }

    struct SpoofedSemanticWriteOperation;

    impl CloudKitOp for SpoofedSemanticWriteOperation {
        type Response = ();

        fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
            output.record_save_request = Some(Default::default());
        }

        fn retrieve_response(
            _response: &cloudkit_proto::ResponseOperation,
        ) -> Result<Self::Response, PushError> {
            Ok(())
        }

        fn flow_control_key() -> &'static str {
            "SpoofedSemanticWrite"
        }

        fn operation() -> cloudkit_proto::operation::Type {
            cloudkit_proto::operation::Type::RecordRetrieveChangesType
        }

        fn is_fetch() -> bool {
            true
        }

        fn link() -> &'static str {
            "https://gateway.icloud.com/ckdatabase/api/client/record/sync"
        }

        fn retry_safety(&self) -> CloudKitRetrySafety {
            CloudKitRetrySafety::ReadOnly
        }

        fn semantic_read_operation(&self) -> Option<SemanticReadOperation> {
            Some(SemanticReadOperation::FetchRecordChanges)
        }
    }

    struct SpoofedSemanticRoutingOperation;

    impl CloudKitOp for SpoofedSemanticRoutingOperation {
        type Response = Vec<u8>;

        fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
            output.function_invoke_request = Some(cloudkit_proto::FunctionInvokeRequest {
                service: Some("Cuttlefish".to_owned()),
                name: Some("fetchChanges".to_owned()),
                parameters: Some(Vec::new()),
            });
        }

        fn retrieve_response(
            response: &cloudkit_proto::ResponseOperation,
        ) -> Result<Self::Response, PushError> {
            response
                .function_invoke_response
                .as_ref()
                .and_then(|response| response.serialized_result.clone())
                .ok_or(PushError::CloudKitSemanticOperationDenied)
        }

        fn flow_control_key() -> &'static str {
            panic!("not flow")
        }

        fn operation() -> cloudkit_proto::operation::Type {
            cloudkit_proto::operation::Type::FunctionInvokeType
        }

        fn is_fetch() -> bool {
            true
        }

        fn is_flow() -> bool {
            false
        }

        fn is_grouped() -> bool {
            false
        }

        fn tags() -> bool {
            false
        }

        fn link() -> &'static str {
            "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke"
        }

        fn custom_headers(&self) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-cloudkit-functionroutinghint",
                HeaderValue::from_static("Cuttlefish/updateTrust"),
            );
            headers
        }

        fn retry_safety(&self) -> CloudKitRetrySafety {
            CloudKitRetrySafety::ReadOnly
        }

        fn semantic_read_operation(&self) -> Option<SemanticReadOperation> {
            Some(SemanticReadOperation::CuttlefishFetchChanges)
        }
    }

    fn semantic_wire_request<Op: CloudKitOp>(operation: &Op) -> cloudkit_proto::RequestOperation {
        let mut request = cloudkit_proto::RequestOperation {
            request: Some(cloudkit_proto::Operation {
                operation_uuid: Some("AAAAAAAA-BBBB-4CCC-8DDD-000000000001".to_owned()),
                r#type: Some(Op::operation().into()),
                synchronous_mode: None,
                last: Some(true),
            }),
            ..Default::default()
        };
        operation.set_request(&mut request);
        request
    }

    #[test]
    fn production_semantic_wire_validator_accepts_only_the_four_exact_reads() {
        let record_changes = FetchRecordChangesOperation::new(public_zone(), None, &NO_ASSETS);
        assert_eq!(
            validate_semantic_read_request_operation(
                record_changes.semantic_read_operation().unwrap(),
                FetchRecordChangesOperation::link(),
                record_changes.retry_safety(),
                &semantic_wire_request(&record_changes),
            )
            .unwrap(),
            "record/sync"
        );

        let zone = FetchZoneOperation::new(public_zone());
        assert_eq!(
            validate_semantic_read_request_operation(
                zone.semantic_read_operation().unwrap(),
                FetchZoneOperation::link(),
                zone.retry_safety(),
                &semantic_wire_request(&zone),
            )
            .unwrap(),
            "zone/retrieve"
        );

        for (name, semantic_operation, expected) in [
            (
                "fetchChanges",
                SemanticReadOperation::CuttlefishFetchChanges,
                "Cuttlefish/fetchChanges",
            ),
            (
                "fetchRecoverableTLKShares",
                SemanticReadOperation::CuttlefishFetchRecoverableTlkShares,
                "Cuttlefish/fetchRecoverableTLKShares",
            ),
        ] {
            let function =
                FunctionInvokeOperation::new("Cuttlefish".to_owned(), name.to_owned(), Vec::new());
            assert_eq!(function.retry_safety(), CloudKitRetrySafety::ReadOnly);
            assert_eq!(
                validate_semantic_read_request_operation(
                    semantic_operation,
                    FunctionInvokeOperation::link(),
                    function.retry_safety(),
                    &semantic_wire_request(&function),
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn production_semantic_header_validator_pins_exact_function_route() {
        let fetch_changes = FunctionInvokeOperation::new(
            "Cuttlefish".to_owned(),
            "fetchChanges".to_owned(),
            Vec::new(),
        );
        assert!(validate_semantic_read_request_headers(
            SemanticReadOperation::CuttlefishFetchChanges,
            &fetch_changes.custom_headers(),
        )
        .is_ok());

        assert!(matches!(
            validate_semantic_read_request_headers(
                SemanticReadOperation::CuttlefishFetchChanges,
                &SpoofedSemanticRoutingOperation.custom_headers(),
            ),
            Err(PushError::CloudKitSemanticOperationDenied)
        ));

        let mut extra_header = fetch_changes.custom_headers();
        extra_header.insert("x-test-extra", HeaderValue::from_static("denied"));
        assert!(matches!(
            validate_semantic_read_request_headers(
                SemanticReadOperation::CuttlefishFetchChanges,
                &extra_header,
            ),
            Err(PushError::CloudKitSemanticOperationDenied)
        ));
    }

    #[test]
    fn shared_transport_requires_writer_permit_for_every_nonsemantic_operation() {
        assert!(!cloudkit_writer_permit_required(&[
            FetchRecordChangesOperation::new(public_zone(), None, &NO_ASSETS),
        ]));
        assert!(!cloudkit_writer_permit_required(&[
            FetchZoneOperation::new(public_zone()),
        ]));
        assert!(!cloudkit_writer_permit_required(&[
            FunctionInvokeOperation::new(
                "Cuttlefish".to_owned(),
                "fetchChanges".to_owned(),
                Vec::new(),
            ),
        ]));

        assert!(cloudkit_writer_permit_required(&[SaveRecordOperation(
            Default::default()
        ),]));
        assert!(cloudkit_writer_permit_required(&[DeleteRecordOperation(
            Default::default()
        ),]));
        assert!(cloudkit_writer_permit_required(&[
            FunctionInvokeOperation::new(
                "Cuttlefish".to_owned(),
                "updateTrust".to_owned(),
                Vec::new(),
            ),
        ]));

        // A malicious operation can lie about its semantic classification, but
        // the exact serialized-wire validator below still rejects it before HTTP.
        assert!(!cloudkit_writer_permit_required(&[
            SpoofedSemanticWriteOperation,
        ]));
    }

    #[test]
    fn production_semantic_wire_validator_rejects_every_non_allowlisted_payload() {
        let operation = FetchRecordChangesOperation::new(public_zone(), None, &NO_ASSETS);
        let assert_denied = |request: cloudkit_proto::RequestOperation| {
            assert!(matches!(
                validate_semantic_read_request_operation(
                    SemanticReadOperation::FetchRecordChanges,
                    FetchRecordChangesOperation::link(),
                    CloudKitRetrySafety::ReadOnly,
                    &request,
                ),
                Err(PushError::CloudKitSemanticOperationDenied)
            ));
        };

        macro_rules! assert_payload_denied {
            ($field:ident) => {{
                let mut request = semantic_wire_request(&operation);
                request.retrieve_changes_request = None;
                request.$field = Some(Default::default());
                assert_denied(request);
            }};
        }

        assert_payload_denied!(zone_save_request);
        assert_payload_denied!(zone_retrieve_request);
        assert_payload_denied!(zone_delete_request);
        assert_payload_denied!(retrieve_zone_changes_request);
        assert_payload_denied!(record_save_request);
        assert_payload_denied!(record_retrieve_request);
        assert_payload_denied!(record_delete_request);
        assert_payload_denied!(resolve_token_request);
        assert_payload_denied!(query_retrieve_request);
        assert_payload_denied!(asset_upload_token_retrieve_request);
        assert_payload_denied!(create_subscription_request);
        assert_payload_denied!(user_query_request);
        assert_payload_denied!(share_accept_request);
        assert_payload_denied!(share_decline_request);
        assert_payload_denied!(token_registration_request);
        assert_payload_denied!(token_unregistration_request);
        assert_payload_denied!(function_invoke_request);

        let mut no_payload = semantic_wire_request(&operation);
        no_payload.retrieve_changes_request = None;
        assert_denied(no_payload);

        let mut multiple_payloads = semantic_wire_request(&operation);
        multiple_payloads.record_save_request = Some(Default::default());
        assert_denied(multiple_payloads);
    }

    #[test]
    fn production_semantic_wire_validator_rejects_wrong_route_type_and_retry_class() {
        let operation = FetchRecordChangesOperation::new(public_zone(), None, &NO_ASSETS);
        let mut request = semantic_wire_request(&operation);
        let assert_denied =
            |link: &str,
             retry_safety: CloudKitRetrySafety,
             request: &cloudkit_proto::RequestOperation| {
                assert!(matches!(
                    validate_semantic_read_request_operation(
                        SemanticReadOperation::FetchRecordChanges,
                        link,
                        retry_safety,
                        request,
                    ),
                    Err(PushError::CloudKitSemanticOperationDenied)
                ));
            };

        for link in [
            "http://gateway.icloud.com/ckdatabase/api/client/record/sync",
            "https://example.invalid/ckdatabase/api/client/record/sync",
            "https://gateway.icloud.com:444/ckdatabase/api/client/record/sync",
            "https://gateway.icloud.com/ckdatabase/api/client/zone/retrieve",
            "https://gateway.icloud.com/ckdatabase/api/client/record/sync?write=true",
        ] {
            assert_denied(link, CloudKitRetrySafety::ReadOnly, &request);
        }
        assert_denied(
            FetchRecordChangesOperation::link(),
            CloudKitRetrySafety::Never,
            &request,
        );
        assert_denied(
            FetchRecordChangesOperation::link(),
            CloudKitRetrySafety::Idempotent,
            &request,
        );

        request.request.as_mut().unwrap().r#type =
            Some(cloudkit_proto::operation::Type::RecordSaveType.into());
        assert_denied(
            FetchRecordChangesOperation::link(),
            CloudKitRetrySafety::ReadOnly,
            &request,
        );
    }

    #[test]
    fn production_semantic_wire_validator_rejects_other_cuttlefish_names_and_services() {
        for (service, name) in [
            ("Cuttlefish", "updateTrust"),
            ("Cuttlefish", "fetchRecoverableTlkShares"),
            ("Cuttlefish", "fetchChangesAndSave"),
            ("NotCuttlefish", "fetchChanges"),
        ] {
            let function =
                FunctionInvokeOperation::new(service.to_owned(), name.to_owned(), Vec::new());
            let request = semantic_wire_request(&function);
            assert!(matches!(
                validate_semantic_read_request_operation(
                    SemanticReadOperation::CuttlefishFetchChanges,
                    FunctionInvokeOperation::link(),
                    CloudKitRetrySafety::ReadOnly,
                    &request,
                ),
                Err(PushError::CloudKitSemanticOperationDenied)
            ));
            assert_eq!(function.retry_safety(), CloudKitRetrySafety::Never);
        }
    }

    #[test]
    fn ck_app_init_unauthorized_retry_is_bounded_to_two_attempts_and_one_refresh() {
        let mut budget = CkAppInitRetryBudget::default();

        budget.begin_attempt().expect("first request");
        budget.authorize_refresh().expect("one refresh");
        budget.begin_attempt().expect("single retry");

        assert_eq!(budget.attempts, 2);
        assert_eq!(budget.refreshes, 1);
        assert!(matches!(
            budget.authorize_refresh(),
            Err(PushError::UnauthorizedAccountError)
        ));
        assert!(matches!(
            budget.begin_attempt(),
            Err(PushError::UnauthorizedAccountError)
        ));
    }

    #[tokio::test]
    async fn cold_v2_prepare_and_reconcile_never_implicitly_warm_or_mutate() {
        let open = Arc::new(one_shot_test_open_container(&SEMANTIC_FAKE_CONTAINER));
        let keychain = semantic_test_keychain(&open);
        let cloud_messages = CloudMessagesClient::new(open.client.clone(), keychain);
        let transport = FaithfulSemanticTransport::default();
        let operation_uuid = "AAAAAAAA-BBBB-4CCC-8DDD-000000000001";
        let request_identity = CloudKitRequestIdentity::new(
            "11111111-2222-4ABC-8DEF-555555555555".to_owned(),
            vec![operation_uuid.to_owned()],
        )
        .expect("request identity");
        let input = CloudMessageSaveInput {
            local_operation_id: "local-operation".to_owned(),
            server_record_name: "stable-server-record".to_owned(),
            apple_operation_uuid: operation_uuid.to_owned(),
            message: CloudMessage::default(),
        };

        let (lookup, prepare) = with_cloudkit_test_transport(transport.transport(), async {
            let lookup = cloud_messages
                .lookup_message_record("stable-server-record")
                .await;
            let prepare = cloud_messages
                .prepare_message_save_submission(
                    vec![input],
                    request_identity,
                    Duration::from_secs(30),
                )
                .await;
            (lookup, prepare)
        })
        .await;

        assert!(matches!(
            lookup,
            Err(PushError::CloudKitWarmAuthenticationRequired)
        ));
        assert!(matches!(
            prepare,
            Err(PushError::CloudKitWarmAuthenticationRequired)
        ));
        assert!(transport.recorded().is_empty());
    }

    #[tokio::test]
    async fn faithful_fake_transport_exercises_real_warm_semantic_fetch_allowlist() {
        let open = Arc::new(one_shot_test_open_container(&SEMANTIC_FAKE_CONTAINER));
        let keychain = semantic_test_keychain(&open);
        let cloud_messages =
            CloudMessagesClient::new_warm_for_test(open.client.clone(), keychain, open.clone());
        let transport = FaithfulSemanticTransport::default();

        let (page, zone, fetch_changes, recoverable_shares) =
            with_cloudkit_test_transport(transport.transport(), async {
                let page = cloud_messages.sync_chats_page(None, Some(17)).await?;
                let zone = open
                    .perform_semantic_read_only(
                        &CloudKitSession::new(),
                        FetchZoneOperation::new(open.private_zone("chatManateeZone".to_owned())),
                    )
                    .await?;
                let fetch_changes = open
                    .perform_semantic_read_only(
                        &CloudKitSession::new(),
                        FunctionInvokeOperation::new(
                            "Cuttlefish".to_owned(),
                            "fetchChanges".to_owned(),
                            Vec::new(),
                        ),
                    )
                    .await?;
                let recoverable_shares = open
                    .perform_semantic_read_only(
                        &CloudKitSession::new(),
                        FunctionInvokeOperation::new(
                            "Cuttlefish".to_owned(),
                            "fetchRecoverableTLKShares".to_owned(),
                            Vec::new(),
                        ),
                    )
                    .await?;
                Ok::<_, PushError>((page, zone, fetch_changes, recoverable_shares))
            })
            .await
            .expect("faithful semantic reads");

        assert!(page.is_complete());
        assert_eq!(page.next_token, None);
        assert_eq!(page.changes.len(), 1);
        assert_eq!(
            page.changes[0].record_name.as_deref(),
            Some("faithful-fake-chat-record")
        );
        assert_eq!(
            page.changes[0].kind,
            CloudMessageRecordKind::EncryptedUpsert
        );
        assert!(page.changes[0].encrypted_record.is_some());
        assert!(zone.target_zone.is_none());
        assert!(fetch_changes.is_empty());
        assert!(recoverable_shares.is_empty());
        assert_eq!(
            transport.recorded(),
            vec![
                "record/sync".to_owned(),
                "zone/retrieve".to_owned(),
                "Cuttlefish/fetchChanges".to_owned(),
                "Cuttlefish/fetchRecoverableTLKShares".to_owned(),
            ]
        );
        assert_eq!(transport.invocations(), 4);
        assert!(!transport
            .recorded()
            .iter()
            .any(|operation| operation.contains("ckAppInit")));
    }

    #[tokio::test]
    async fn faithful_fake_transport_rejects_spoofed_write_inside_allowed_endpoint() {
        let open = one_shot_test_open_container(&SEMANTIC_FAKE_CONTAINER);
        let transport = FaithfulSemanticTransport::default();
        let result = with_cloudkit_test_transport(transport.transport(), async {
            open.perform_semantic_read_only(&CloudKitSession::new(), SpoofedSemanticWriteOperation)
                .await
        })
        .await;

        assert!(matches!(
            result,
            Err(PushError::CloudKitSemanticOperationDenied)
        ));
        assert!(transport.recorded().is_empty());
        assert_eq!(transport.invocations(), 0);
    }

    #[tokio::test]
    async fn faithful_fake_transport_rejects_spoofed_function_route_before_http() {
        let open = one_shot_test_open_container(&SEMANTIC_FAKE_CONTAINER);
        let transport = FaithfulSemanticTransport::default();
        let result = with_cloudkit_test_transport(transport.transport(), async {
            open.perform_semantic_read_only(
                &CloudKitSession::new(),
                SpoofedSemanticRoutingOperation,
            )
            .await
        })
        .await;

        assert!(matches!(
            result,
            Err(PushError::CloudKitSemanticOperationDenied)
        ));
        assert!(transport.recorded().is_empty());
        assert_eq!(transport.invocations(), 0);
    }

    #[test]
    fn faithful_fake_transport_pins_method_scheme_host_and_port() {
        let client = reqwest::Client::new();
        let allowed = client
            .post("https://gateway.icloud.com/ckdatabase/api/client/record/sync")
            .build()
            .expect("allowed request");
        assert!(validate_semantic_request_target(&allowed).is_ok());

        for request in [
            client
                .get("https://gateway.icloud.com/ckdatabase/api/client/record/sync")
                .build()
                .expect("wrong method"),
            client
                .post("http://gateway.icloud.com/ckdatabase/api/client/record/sync")
                .build()
                .expect("wrong scheme"),
            client
                .post("https://example.invalid/ckdatabase/api/client/record/sync")
                .build()
                .expect("wrong host"),
            client
                .post("https://gateway.icloud.com:444/ckdatabase/api/client/record/sync")
                .build()
                .expect("wrong port"),
        ] {
            assert!(matches!(
                validate_semantic_request_target(&request),
                Err(PushError::CloudKitSemanticOperationDenied)
            ));
        }
    }

    fn assert_one_shot_timeout(
        failure: CloudKitRequestFailure,
        identity: &CloudKitRequestIdentity,
        expected_message: &str,
    ) {
        assert_eq!(failure.request_identity.as_ref(), Some(identity));
        assert!(failure.outcome_may_be_committed);
        assert!(matches!(
            failure.error,
            PushError::IoError(ref source)
                if source.kind() == ErrorKind::TimedOut
                    && source.to_string() == expected_message
        ));
    }

    async fn assert_public_one_shot_status_without_replay<Op: CloudKitOp>(
        operation: Op,
        endpoint: &'static OnceLock<String>,
        status: u16,
        reason: &'static str,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        endpoint.set(format!("http://{address}/status")).unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8192];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains(HTTP_REQUEST_UUID));
            let redirect = if (300..400).contains(&status) {
                format!("Location: http://{address}/replayed\r\n")
            } else {
                String::new()
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\n{redirect}Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();

            tokio::time::timeout(Duration::from_millis(500), listener.accept())
                .await
                .is_ok()
        });

        let container = one_shot_test_container();
        let open = one_shot_test_open_container(&container);
        let identity = CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned()],
        )
        .unwrap();
        let result = open
            .perform_operations_detailed_once_with_identity(
                &CloudKitSession::new(),
                &[operation],
                IsolationLevel::Operation,
                &CloudKitRetryPolicy {
                    max_attempts: 4,
                    request_timeout: Duration::from_secs(2),
                    ..CloudKitRetryPolicy::default()
                },
                identity.clone(),
                one_shot_test_authentication(&open),
            )
            .await;
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("HTTP status {status} unexpectedly succeeded"),
        };
        assert_eq!(failure.request_identity.as_ref(), Some(&identity));
        assert!(failure.outcome_may_be_committed);
        assert!(matches!(
            failure.error,
            PushError::CloudKitHttpError { status: actual, .. } if actual == status
        ));
        assert!(
            !server.await.unwrap(),
            "one-shot status request was replayed"
        );
    }

    #[test]
    fn persisted_request_identity_preserves_canonical_uuids() {
        let identity = CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned(), OPERATION_UUID_B.to_owned()],
        )
        .unwrap();

        assert_eq!(identity.http_request_uuid(), HTTP_REQUEST_UUID);
        assert_eq!(
            identity.operation_uuids(),
            [OPERATION_UUID_A.to_owned(), OPERATION_UUID_B.to_owned()]
        );
    }

    #[test]
    fn persisted_request_identity_rejects_noncanonical_or_malformed_uuids() {
        assert!(CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_ascii_lowercase(),
            vec![OPERATION_UUID_A.to_owned()],
        )
        .is_err());
        assert!(CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec!["not-a-uuid".to_owned()],
        )
        .is_err());
    }

    #[test]
    fn persisted_request_identity_rejects_duplicate_operation_uuids() {
        assert!(CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned(), OPERATION_UUID_A.to_owned()],
        )
        .is_err());
    }

    #[test]
    fn persisted_request_identity_rejects_operation_count_mismatch() {
        let identity = CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned()],
        )
        .unwrap();

        assert!(identity.validate_operation_count(2).is_err());
    }

    fn response_with_operation_uuid(operation_uuid: Option<&str>) -> ResponseOperation {
        ResponseOperation {
            response: Some(cloudkit_proto::Operation {
                operation_uuid: operation_uuid.map(str::to_owned),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn response_identity_validation_accepts_only_requested_operation_uuids() {
        let identity = CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned(), OPERATION_UUID_B.to_owned()],
        )
        .unwrap();
        let responses = [
            response_with_operation_uuid(Some(OPERATION_UUID_B)),
            response_with_operation_uuid(Some(OPERATION_UUID_A)),
        ];

        assert!(validate_cloudkit_response_identities(&identity, &responses).is_ok());
    }

    #[test]
    fn response_identity_validation_rejects_missing_or_unexpected_uuids() {
        let identity = CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned()],
        )
        .unwrap();

        assert!(validate_cloudkit_response_identities(
            &identity,
            &[response_with_operation_uuid(None)],
        )
        .is_err());
        assert!(validate_cloudkit_response_identities(
            &identity,
            &[response_with_operation_uuid(Some(OPERATION_UUID_B))],
        )
        .is_err());
        assert!(validate_cloudkit_response_identities(&identity, &[]).is_err());
        assert!(validate_cloudkit_response_identities(
            &identity,
            &[
                response_with_operation_uuid(Some(OPERATION_UUID_A)),
                response_with_operation_uuid(Some(OPERATION_UUID_A)),
            ],
        )
        .is_err());
    }

    #[test]
    fn operation_headers_cannot_override_identity_scope_or_authentication() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-cloudkit-partition",
            HeaderValue::from_static("production"),
        );
        assert!(validate_cloudkit_operation_headers(&headers).is_ok());

        for reserved in [
            "x-apple-request-uuid",
            "x-apple-operation-group-id",
            "x-apple-operation-id",
            "x-cloudkit-userid",
            "x-cloudkit-authtoken",
            "x-cloudkit-bundleid",
            "x-cloudkit-containerid",
            "x-cloudkit-databasescope",
            "x-cloudkit-environment",
            "x-mme-client-info",
        ] {
            let mut attempted_override = HeaderMap::new();
            attempted_override.insert(
                HeaderName::from_static(reserved),
                HeaderValue::from_static("override"),
            );
            assert!(validate_cloudkit_operation_headers(&attempted_override).is_err());
        }
    }

    #[test]
    fn anisette_header_conversion_rejects_malformed_names_and_values() {
        assert!(cloudkit_anisette_header_map(&HashMap::from([(
            "bad header".to_owned(),
            "value".to_owned(),
        )]))
        .is_err());
        assert!(cloudkit_anisette_header_map(&HashMap::from([(
            "x-test".to_owned(),
            "bad\nvalue".to_owned(),
        )]))
        .is_err());
    }

    #[tokio::test]
    async fn public_one_shot_does_not_redirect_refresh_or_retry_http_failures() {
        assert_public_one_shot_status_without_replay(
            RedirectOperation,
            &REDIRECT_ENDPOINT,
            307,
            "Temporary Redirect",
        )
        .await;
        assert_public_one_shot_status_without_replay(
            UnauthorizedOperation,
            &UNAUTHORIZED_ENDPOINT,
            401,
            "Unauthorized",
        )
        .await;
        assert_public_one_shot_status_without_replay(
            ServerErrorOperation,
            &SERVER_ERROR_ENDPOINT,
            500,
            "Internal Server Error",
        )
        .await;
    }

    #[tokio::test]
    async fn public_one_shot_times_out_before_headers_without_replay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        BEFORE_HEADERS_ENDPOINT
            .set(format!("http://{address}/before-headers"))
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_complete_http_headers(&mut socket).await;
            assert!(request.contains(HTTP_REQUEST_UUID));

            let replay = tokio::time::timeout(Duration::from_millis(900), listener.accept()).await;
            drop(socket);
            replay.is_ok()
        });

        let container = one_shot_test_container();
        let open = one_shot_test_open_container(&container);
        let identity = CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned()],
        )
        .unwrap();
        let policy = CloudKitRetryPolicy {
            max_attempts: 4,
            request_timeout: Duration::from_millis(400),
            ..CloudKitRetryPolicy::default()
        };
        let result = open
            .perform_operations_detailed_once_with_identity(
                &CloudKitSession::new(),
                &[BeforeHeadersOperation],
                IsolationLevel::Operation,
                &policy,
                identity.clone(),
                one_shot_test_authentication(&open),
            )
            .await;
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("one-shot request unexpectedly completed before its deadline"),
        };

        assert_one_shot_timeout(
            failure,
            &identity,
            "CloudKit one-shot operation timed out before receiving response headers",
        );
        assert!(!server.await.unwrap(), "one-shot request was replayed");
    }

    #[tokio::test]
    async fn public_one_shot_shares_one_deadline_across_headers_and_body() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        SHARED_BUDGET_ENDPOINT
            .set(format!("http://{address}/shared-budget"))
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_complete_http_headers(&mut socket).await;
            assert!(request.contains(HTTP_REQUEST_UUID));

            tokio::time::sleep(Duration::from_millis(350)).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            socket.flush().await.unwrap();

            tokio::time::sleep(Duration::from_millis(700)).await;
            let _ = socket.write_all(b"body").await;
            let replay = tokio::time::timeout(Duration::from_millis(800), listener.accept()).await;
            replay.is_ok()
        });

        let container = one_shot_test_container();
        let open = one_shot_test_open_container(&container);
        let identity = CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned()],
        )
        .unwrap();
        let policy = CloudKitRetryPolicy {
            max_attempts: 4,
            request_timeout: Duration::from_millis(800),
            ..CloudKitRetryPolicy::default()
        };
        let result = open
            .perform_operations_detailed_once_with_identity(
                &CloudKitSession::new(),
                &[SharedBudgetOperation],
                IsolationLevel::Operation,
                &policy,
                identity.clone(),
                one_shot_test_authentication(&open),
            )
            .await;
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("one-shot request unexpectedly completed within its shared budget"),
        };

        assert_one_shot_timeout(
            failure,
            &identity,
            "CloudKit one-shot operation timed out while reading response body",
        );
        assert!(!server.await.unwrap(), "one-shot request was replayed");
    }

    #[tokio::test]
    async fn public_one_shot_marks_dropped_response_unknown_without_replay() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        DROPPED_RESPONSE_ENDPOINT
            .set(format!("http://{address}/dropped-response"))
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8192];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains(HTTP_REQUEST_UUID));
            drop(socket);

            tokio::time::timeout(Duration::from_millis(500), listener.accept())
                .await
                .is_ok()
        });

        let container = one_shot_test_container();
        let open = one_shot_test_open_container(&container);
        let identity = CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned()],
        )
        .unwrap();
        let result = open
            .perform_operations_detailed_once_with_identity(
                &CloudKitSession::new(),
                &[DroppedResponseOperation],
                IsolationLevel::Operation,
                &CloudKitRetryPolicy {
                    max_attempts: 4,
                    request_timeout: Duration::from_secs(2),
                    ..CloudKitRetryPolicy::default()
                },
                identity.clone(),
                one_shot_test_authentication(&open),
            )
            .await;
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("dropped response unexpectedly succeeded"),
        };

        assert_eq!(failure.request_identity.as_ref(), Some(&identity));
        assert!(failure.outcome_may_be_committed);
        assert!(!server.await.unwrap(), "one-shot request was replayed");
    }

    #[tokio::test]
    async fn public_one_shot_rejects_invalid_timeout_before_submission() {
        let container = one_shot_test_container();
        let open = one_shot_test_open_container(&container);
        let identity = CloudKitRequestIdentity::new(
            HTTP_REQUEST_UUID.to_owned(),
            vec![OPERATION_UUID_A.to_owned()],
        )
        .unwrap();

        for request_timeout in [
            Duration::ZERO,
            CLOUDKIT_MAX_ONE_SHOT_REQUEST_TIMEOUT + Duration::from_millis(1),
        ] {
            let result = open
                .perform_operations_detailed_once_with_identity(
                    &CloudKitSession::new(),
                    &[BeforeHeadersOperation],
                    IsolationLevel::Operation,
                    &CloudKitRetryPolicy {
                        request_timeout,
                        ..CloudKitRetryPolicy::default()
                    },
                    identity.clone(),
                    one_shot_test_authentication(&open),
                )
                .await;
            let failure = match result {
                Err(failure) => failure,
                Ok(_) => panic!("invalid timeout unexpectedly reached submission"),
            };
            assert_eq!(failure.request_identity.as_ref(), Some(&identity));
            assert!(!failure.outcome_may_be_committed);
        }
    }

    #[test]
    fn record_name_allocation_is_random_and_reuses_a_durable_mapping() {
        let first = allocate_or_reuse_record_name(None).unwrap();
        let second = allocate_or_reuse_record_name(None).unwrap();

        assert!(first.requires_persistence());
        assert!(second.requires_persistence());
        assert_ne!(first.record_name(), second.record_name());

        let reused = allocate_or_reuse_record_name(Some(first.record_name())).unwrap();
        assert!(!reused.requires_persistence());
        assert_eq!(reused.record_name(), first.record_name());
    }

    #[test]
    fn empty_record_mapping_is_rejected_instead_of_silently_reallocated() {
        assert!(allocate_or_reuse_record_name(Some("")).is_err());
    }

    #[test]
    fn semantic_pcs_lookup_cannot_select_missing_zone_creation() {
        assert_eq!(
            ZoneEncryptionConfigAccess::LookupOnly.missing_zone_action(),
            MissingZoneAction::ReturnError
        );
        assert_eq!(
            ZoneEncryptionConfigAccess::AllowCreate.missing_zone_action(),
            MissingZoneAction::CreateAndFetch
        );
    }

    #[test]
    fn semantic_transport_allowlist_is_closed_complete_and_path_pinned() {
        assert_eq!(
            SemanticReadOperation::ALL,
            [
                SemanticReadOperation::CkAppInit,
                SemanticReadOperation::FetchRecordChanges,
                SemanticReadOperation::FetchZone,
                SemanticReadOperation::CuttlefishFetchChanges,
                SemanticReadOperation::CuttlefishFetchRecoverableTlkShares,
            ]
        );
        assert!(!SemanticReadOperation::CkAppInit.is_warm_semantic_transport());
        assert_eq!(
            FetchRecordChangesOperation::link(),
            "https://gateway.icloud.com/ckdatabase/api/client/record/sync"
        );
        assert_eq!(
            FetchZoneOperation::link(),
            "https://gateway.icloud.com/ckdatabase/api/client/zone/retrieve"
        );

        assert_eq!(
            record_semantic_read_operations(&[FetchRecordChangesOperation::new(
                public_zone(),
                None,
                &NO_ASSETS,
            )])
            .unwrap(),
            vec![SemanticReadOperation::FetchRecordChanges]
        );
        assert_eq!(
            record_semantic_read_operations(&[FetchZoneOperation::new(public_zone())]).unwrap(),
            vec![SemanticReadOperation::FetchZone]
        );
        assert_eq!(
            record_semantic_read_operations(&[FunctionInvokeOperation::new(
                "Cuttlefish".to_owned(),
                "fetchChanges".to_owned(),
                Vec::new(),
            )])
            .unwrap(),
            vec![SemanticReadOperation::CuttlefishFetchChanges]
        );
        assert_eq!(
            record_semantic_read_operations(&[FunctionInvokeOperation::new(
                "Cuttlefish".to_owned(),
                "fetchRecoverableTLKShares".to_owned(),
                Vec::new(),
            )])
            .unwrap(),
            vec![SemanticReadOperation::CuttlefishFetchRecoverableTlkShares]
        );
    }

    #[test]
    fn semantic_transport_rejects_every_content_key_and_trust_mutation() {
        assert!(record_semantic_read_operations(&[ZoneSaveOperation(Default::default())]).is_err());
        assert!(
            record_semantic_read_operations(&[ZoneDeleteOperation(Default::default())]).is_err()
        );
        assert!(
            record_semantic_read_operations(&[SaveRecordOperation(Default::default())]).is_err()
        );
        assert!(
            record_semantic_read_operations(&[DeleteRecordOperation(Default::default())]).is_err()
        );
        assert!(record_semantic_read_operations(&[
            CreateSubscriptionOperation(Default::default())
        ])
        .is_err());
        assert!(record_semantic_read_operations(&[FetchRecordOperation::new(
            &NO_ASSETS,
            record_identifier(public_zone(), "not-allowlisted"),
        )])
        .is_err());

        for method in ["updateTrust", "reset", "joinWithVoucher"] {
            assert!(
                record_semantic_read_operations(&[FunctionInvokeOperation::new(
                    "Cuttlefish".to_owned(),
                    method.to_owned(),
                    Vec::new(),
                )])
                .is_err()
            );
        }

        for prerequisite in [
            PushError::NotInClique,
            PushError::MasterKeyNotFound,
            PushError::ShareKeyNotFound("sentinel-service".to_owned()),
        ] {
            assert!(matches!(
                prerequisite,
                PushError::NotInClique
                    | PushError::MasterKeyNotFound
                    | PushError::ShareKeyNotFound(_)
            ));
            assert_eq!(
                ZoneEncryptionConfigAccess::LookupOnly.missing_zone_action(),
                MissingZoneAction::ReturnError
            );
        }
    }

    #[test]
    fn change_token_expiry_survives_redaction_as_a_content_free_signal() {
        let result = cloudkit_proto::response_operation::Result {
            code: Some(cloudkit_proto::response_operation::result::Code::Failure as i32),
            error: Some(cloudkit_proto::response_operation::result::Error {
                error_description: Some(".changeTokenExpired".to_owned()),
                error_key: Some("SENTINEL_MESSAGE_TEXT_DO_NOT_EXPOSE".to_owned()),
                error_internal: Some("SENTINEL_DSID_AND_TOKEN".to_owned()),
                extension_error: Some(
                    cloudkit_proto::response_operation::result::error::Extension {
                        extension_name: Some("SENTINEL_PEER_AND_KEY_ID".to_owned()),
                        extension_payload: Some(b"SENTINEL_KEY_AND_CIPHERTEXT_BYTES".to_vec()),
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }),
        };

        assert!(is_change_token_expired_result(&result));
        let error = content_safe_cloudkit_error(&result);
        assert!(matches!(error, PushError::CloudKitChangeTokenExpired));
        let formatted = format!("{error:?} {error}");
        for sentinel in [
            "SENTINEL_MESSAGE_TEXT_DO_NOT_EXPOSE",
            "SENTINEL_DSID_AND_TOKEN",
            "SENTINEL_PEER_AND_KEY_ID",
            "SENTINEL_KEY_AND_CIPHERTEXT_BYTES",
        ] {
            assert!(!formatted.contains(sentinel));
        }
    }

    #[test]
    fn fallible_save_builder_rejects_missing_pcs_key_without_panicking() {
        let zone = public_zone();
        let key = PCSZoneConfig {
            identifier: zone.clone(),
            zone_keys: vec![],
            zone_protection_tag: None,
            default_record_keys: vec![],
            record_prot_tag: None,
            zone_pcs_key: vec![],
            zone_roll_count: 0,
            record_roll_count: 0,
        };

        let result = SaveRecordOperation::try_new(
            record_identifier(zone, "create-only-fixture"),
            ZoneUpdatePlugin {
                zone_update_data: vec![],
            },
            Some(&key),
            false,
        );

        assert!(result.is_err());
    }

    #[test]
    fn save_builder_encodes_create_only_wire_semantics() {
        let operation = SaveRecordOperation::try_new(
            record_identifier(public_zone(), "create-only-record"),
            ZoneUpdatePlugin {
                zone_update_data: vec![],
            },
            None,
            false,
        )
        .unwrap();

        assert_eq!(operation.0.save_semantics, Some(2));
        assert!(operation.0.record_protection_info_tag.is_none());
    }

    #[test]
    fn fetched_record_identity_must_match_the_exact_requested_name() {
        let response = ResponseOperation {
            record_retrieve_response: Some(cloudkit_proto::RecordRetrieveResponse {
                record: Some(Record {
                    record_identifier: Some(record_identifier(public_zone(), "returned-record")),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let fetched = FetchRecordOperation::retrieve_response(&response).unwrap();

        fetched.verify_id("returned-record").unwrap();
        assert!(fetched.verify_id("requested-record").is_err());
    }

    #[test]
    fn pcs_record_validation_rejects_missing_identity_key_and_oversized_prefix() {
        let zone = public_zone();
        let keys = PCSZoneConfig {
            identifier: zone.clone(),
            zone_keys: vec![],
            zone_protection_tag: None,
            default_record_keys: vec![PCSKey::random()],
            record_prot_tag: None,
            zone_pcs_key: vec![],
            zone_roll_count: 0,
            record_roll_count: 0,
        };

        assert!(pcs_keys_for_record(&Record::default(), &keys).is_err());

        let missing_key = Record {
            record_identifier: Some(record_identifier(zone.clone(), "missing-pcs-key")),
            ..Default::default()
        };
        assert!(pcs_keys_for_record(&missing_key, &keys).is_err());

        let oversized_prefix = Record {
            record_identifier: Some(record_identifier(zone.clone(), "oversized-pcs-prefix")),
            pcs_key: Some(vec![0; 1024]),
            ..Default::default()
        };
        assert!(pcs_keys_for_record(&oversized_prefix, &keys).is_err());

        let sentinel = "SENTINEL_MALFORMED_RECORD_PROTECTION_DO_NOT_EXPOSE";
        let malformed_protection = Record {
            record_identifier: Some(record_identifier(zone, "malformed-protection")),
            protection_info: Some(ProtectionInfo {
                protection_info: Some(sentinel.as_bytes().to_vec()),
                protection_info_tag: Some("SENTINEL_PROTECTION_TAG".to_owned()),
            }),
            ..Default::default()
        };
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pcs_keys_for_record(&malformed_protection, &keys)
        }));
        let error =
            match checked.expect("malformed record protection must return rather than panic") {
                Err(error) => error,
                Ok(_) => panic!("malformed record protection unexpectedly decoded"),
            };
        assert!(matches!(error, PushError::BadMsg));
        assert!(!format!("{error:?}").contains(sentinel));
    }

    #[test]
    fn incomplete_page_rejects_repeated_continuation_token() {
        let token = [1, 2, 3];
        let error = ensure_cloudkit_continuation_progress(
            false,
            Some(token.as_slice()),
            Some(token.as_slice()),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            PushError::CloudKitProtocolError(CloudKitProtocolError::ContinuationTokenNoProgress)
        ));
    }

    #[test]
    fn incomplete_page_rejects_missing_continuation_progress() {
        let error = ensure_cloudkit_continuation_progress(false, None, None).unwrap_err();

        assert!(matches!(
            error,
            PushError::CloudKitProtocolError(CloudKitProtocolError::ContinuationTokenNoProgress)
        ));
    }

    #[test]
    fn incomplete_page_rejects_multi_token_cycle() {
        let token_a = [1, 2, 3];
        let token_b = [4, 5, 6];
        let mut seen = HashSet::from([sha256(&token_a)]);

        remember_incomplete_continuation_token(false, Some(&token_b), &mut seen).unwrap();
        let error =
            remember_incomplete_continuation_token(false, Some(&token_a), &mut seen).unwrap_err();

        assert!(matches!(
            error,
            PushError::CloudKitProtocolError(CloudKitProtocolError::ContinuationTokenNoProgress)
        ));
    }

    #[test]
    fn record_change_page_rejects_server_count_overrun() {
        let changes = vec![RecordChange::default(); 201];

        assert!(validate_record_change_page_size(&changes, 200).is_err());
    }

    #[test]
    fn record_change_page_rejects_oversized_record_before_mapping() {
        let changes = vec![RecordChange {
            etag: Some("x".repeat(CLOUDKIT_MAX_RECORD_CHANGE_BYTES + 1)),
            ..Default::default()
        }];

        assert!(validate_record_change_page_size(&changes, 1).is_err());
    }

    #[test]
    fn record_change_page_rejects_oversized_aggregate_before_mapping() {
        let changes = (0..4)
            .map(|_| RecordChange {
                etag: Some("x".repeat(6 * 1024 * 1024)),
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert!(validate_record_change_page_size(&changes, 4).is_err());
    }

    #[test]
    fn complete_or_advancing_page_passes_continuation_guard() {
        let previous = [1, 2, 3];
        let next = [4, 5, 6];

        assert!(ensure_cloudkit_continuation_progress(
            true,
            Some(previous.as_slice()),
            Some(previous.as_slice()),
        )
        .is_ok());
        assert!(ensure_cloudkit_continuation_progress(
            false,
            Some(previous.as_slice()),
            Some(next.as_slice()),
        )
        .is_ok());
    }

    #[test]
    fn empirical_record_and_zone_completion_statuses_are_explicit() {
        assert!(CloudKitRecordChangePage {
            assets: Vec::new(),
            changes: Vec::new(),
            next_token: None,
            status: CLOUDKIT_RECORD_CHANGES_STATUS_COMPLETE,
        }
        .is_complete());
        assert!(!CloudKitRecordChangePage {
            assets: Vec::new(),
            changes: Vec::new(),
            next_token: None,
            status: CLOUDKIT_ZONE_CHANGES_STATUS_COMPLETE,
        }
        .is_complete());

        assert!(CloudKitZoneChangePage {
            changes: Vec::new(),
            next_token: None,
            status: CLOUDKIT_ZONE_CHANGES_STATUS_COMPLETE,
        }
        .is_complete());
        assert!(!CloudKitZoneChangePage {
            changes: Vec::new(),
            next_token: None,
            status: CLOUDKIT_RECORD_CHANGES_STATUS_COMPLETE,
        }
        .is_complete());
    }

    #[test]
    fn record_change_request_preserves_token_and_empirical_change_selector() {
        let token = vec![7, 8, 9];
        let request = FetchRecordChangesOperation::new_with_limit(
            cloudkit_proto::RecordZoneIdentifier::default(),
            Some(token.clone()),
            &NO_ASSETS,
            0,
        );

        assert_eq!(request.0.sync_continuation_token, Some(token));
        assert_eq!(
            request.0.requested_changes_types,
            Some(CLOUDKIT_RECORD_CHANGES_REQUEST_ALL)
        );
        assert_eq!(request.0.max_changes, Some(1));
    }

    #[test]
    fn response_header_preserves_bundled_assets_across_wire_roundtrip() {
        let mut response = ResponseOperation::default();
        response
            .header
            .get_or_insert_default()
            .bundled
            .push(AssetGetResponse {
                asset_id: Some("asset-fixture".to_string()),
                ..Default::default()
            });
        response.retrieve_changes_response = Some(Default::default());

        let encoded = response.encode_to_vec();
        let decoded = ResponseOperation::decode(encoded.as_slice()).unwrap();
        let (assets, _) = FetchRecordChangesOperation::retrieve_response(&decoded).unwrap();

        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].asset_id.as_deref(), Some("asset-fixture"));
    }

    #[test]
    fn retry_after_takes_precedence_over_exponential_backoff_cap() {
        let policy = CloudKitRetryPolicy {
            max_delay: Duration::from_secs(5),
            max_server_internal_delay: Duration::from_secs(15 * 60),
            ..CloudKitRetryPolicy::default()
        };

        assert_eq!(
            retry_delay(&policy, 1, Some(Duration::from_secs(90))),
            Some(Duration::from_secs(90)),
        );
    }

    #[test]
    fn long_retry_after_is_deferred_to_the_durable_caller_without_shortening() {
        let policy = CloudKitRetryPolicy {
            max_delay: Duration::from_secs(5),
            max_server_internal_delay: Duration::from_secs(120),
            ..CloudKitRetryPolicy::default()
        };

        assert_eq!(
            retry_delay(&policy, 1, Some(Duration::from_secs(300))),
            None
        );
    }

    #[test]
    fn http_failures_are_classified_for_durable_retry_policy() {
        assert_eq!(
            classify_cloudkit_http_failure(reqwest::StatusCode::UNAUTHORIZED),
            CloudKitFailureClass::Authentication
        );
        assert_eq!(
            classify_cloudkit_http_failure(reqwest::StatusCode::TOO_MANY_REQUESTS),
            CloudKitFailureClass::Throttled
        );
        assert_eq!(
            classify_cloudkit_http_failure(reqwest::StatusCode::SERVICE_UNAVAILABLE),
            CloudKitFailureClass::TransientServer
        );
        assert_eq!(
            classify_cloudkit_http_failure(reqwest::StatusCode::BAD_REQUEST),
            CloudKitFailureClass::Permanent
        );
    }

    #[test]
    fn delimited_response_rejects_truncated_frames() {
        let mut response = encode_uleb128(4);
        response.extend_from_slice(&[1, 2]);

        assert!(undelimit_response(&response).is_err());
    }

    #[test]
    fn delimited_response_rejects_oversized_frames_before_allocation() {
        let response = encode_uleb128((CLOUDKIT_MAX_RESPONSE_FRAME_BYTES + 1) as u64);

        assert!(undelimit_response(&response).is_err());
    }

    #[test]
    fn cloudkit_errors_are_redacted_without_losing_retry_metadata() {
        let original = cloudkit_proto::response_operation::Result {
            code: Some(cloudkit_proto::response_operation::result::Code::Failure as i32),
            error: Some(cloudkit_proto::response_operation::result::Error {
                retry_after_seconds: Some(42),
                error_description: Some("private record details".to_string()),
                error_key: Some("private-key".to_string()),
                error_internal: Some("private-internal".to_string()),
                ..Default::default()
            }),
        };

        let redacted = redact_cloudkit_result(original);
        let error = redacted.error.unwrap();
        assert_eq!(error.retry_after_seconds, Some(42));
        assert!(error.error_description.is_none());
        assert!(error.error_key.is_none());
        assert!(error.error_internal.is_none());
    }
}
