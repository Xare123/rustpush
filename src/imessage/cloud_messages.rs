use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::future::Future;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::cloud_messages::cloudmessagesp::{
    ChatProto, MessageProto, MessageProto2, MessageProto3, MessageProto4,
};
use crate::cloudkit::{
    pcs_keys_for_record, record_identifier, CloudKitBatchResponse, CloudKitFailureClass,
    CloudKitOpenContainer, CloudKitPreparedAuthentication, CloudKitRequestFailure,
    CloudKitRequestIdentity, CloudKitRetryPolicy, CloudKitSession, CloudKitUploadRequest,
    DeleteRecordOperation, FetchRecordChangesOperation, FetchRecordOperation, FetchedRecords,
    QueryRecordOperation, SaveRecordOperation, ZoneDeleteOperation, ALL_ASSETS,
    CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE, CLOUDKIT_MAX_OPERATIONS_PER_REQUEST, NO_ASSETS,
};
use crate::mmcs::{prepare_put_v2, PreparedPut};
use crate::pcs::{get_boundary_key, PCSKey, PCSService};
use crate::util::DebugMutex;
use backon::{ConstantBuilder, Retryable};
use bitflags::bitflags;
use cloudkit_derive::CloudKitRecord;
use cloudkit_proto::request_operation::header::IsolationLevel;
use cloudkit_proto::retrieve_changes_response::RecordChange;
use cloudkit_proto::sealed::PlistKind;
use cloudkit_proto::RecordIdentifier;
use cloudkit_proto::{
    base64_encode, Asset, CloudKitBytes, CloudKitBytesKind, CloudKitEncryptedValue, CloudKitRecord,
    Date, Record, RecordZoneIdentifier,
};
use hkdf::Hkdf;
use log::{info, warn};
use omnisette::AnisetteProvider;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::PKey;
use openssl::sha::sha256;
use openssl::sign::Signer;
use plist::{Data, Value};
use prost::Message;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::keychain::KeychainClient;
use crate::util::{
    base64_decode, bin_deserialize, bin_deserialize_opt_vec, bin_serialize, bin_serialize_opt_vec,
    coder_encode_flattened, decode_hex, encode_hex, gzip, plist_to_bin, proto_deserialize_opt,
    proto_serialize_opt, ungzip, NSAttributedString, NSDictionaryTypedCoder, NSNumber, NSString,
    StreamTypedCoder,
};
use crate::{
    cloudkit::{CloudKitClient, CloudKitContainer, CloudKitReadAuthenticationContainer},
    cloudkit_operation_gate::{with_cloudkit_writer_operation, CloudKitReadAuthenticationPermit},
    PushError,
};
use crate::{Attachment, AttachmentType, FileContainer};
use cloudkit_proto::CloudKitEncryptor;

pub const MESSAGES_SERVICE: PCSService = PCSService {
    name: "Messages3",
    view_hint: "Engram",
    zone: "Engram",
    r#type: 55,
    keychain_type: 55,
    v2: false,
    global_record: true,
};

// Legacy sync runs one page at a time from a short-lived Flutter worker.  The
// lower HTTP layer bounds request I/O, but token/keychain/header preparation
// happens outside that timeout and a server-directed retry can otherwise keep
// the worker alive indefinitely.  A timed-out read is safe to cancel because
// the caller persists its continuation token only after applying the page.
const LEGACY_CLOUDKIT_PAGE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

async fn legacy_cloudkit_page_with_deadline<T, F>(
    deadline: Duration,
    operation: F,
) -> Result<T, PushError>
where
    F: Future<Output = Result<T, PushError>>,
{
    tokio::time::timeout(deadline, operation)
        .await
        .map_err(|_| {
            PushError::IoError(std::io::Error::new(
                ErrorKind::TimedOut,
                "Legacy CloudKit page timed out before cursor commit",
            ))
        })?
}

pub mod cloudmessagesp {
    use cloudkit_proto::{sealed::ProtoKind, CloudKitBytesKind};

    include!(concat!(env!("OUT_DIR"), "/cloudmessagesp.rs"));

    impl CloudKitBytesKind for MessageProto {
        type Kind = ProtoKind;
    }

    impl CloudKitBytesKind for MessageProto3 {
        type Kind = ProtoKind;
    }

    impl CloudKitBytesKind for MessageProto2 {
        type Kind = ProtoKind;
    }

    impl CloudKitBytesKind for MessageProto4 {
        type Kind = ProtoKind;
    }

    impl CloudKitBytesKind for ChatProto {
        type Kind = ProtoKind;
    }
}

const MESSAGES_CONTAINER: CloudKitContainer = CloudKitContainer {
    database_type: cloudkit_proto::request_operation::header::Database::PrivateDb,
    bundleid: "com.apple.imagent",
    containerid: "com.apple.messages.cloud",
    env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
};

const RAW_ONLY_RECORD_TYPE: &str = "__cloud_sync_raw_only__";

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct MessageFlags: i64 {
        const IS_FINISHED               = 1 << 0; // this one probably, although there are some unset in db, all are set on local db
        const IS_EMOTE                  = 1 << 1;
        const IS_FROM_ME                = 1 << 2;
        const IS_EMPTY                  = 1 << 3;
        const IS_DELAYED                = 1 << 5;
        const IS_AUTO_REPLY             = 1 << 6;
        const IS_PREPARED               = 1 << 11;
        const IS_DELIVERED              = 1 << 12;
        const IS_READ                   = 1 << 13;
        const IS_SYSTEM_MESSAGE         = 1 << 14;
        const IS_SENT                   = 1 << 15; // controls progress bar, whether sending is complete
        const HAS_DD_RESULTS            = 1 << 16;
        const IS_SERVICE_MESSAGE        = 1 << 17;
        const IS_FORWARD                = 1 << 18;
        const WAS_DOWNGRADED            = 1 << 19;
        const WAS_DATA_DETECTED         = 1 << 20;
        const IS_AUDIO_MESSAGE          = 1 << 21;
        const IS_PLAYED                 = 1 << 22;
        const IS_EXPIRABLE              = 1 << 24;
        const MESSAGE_SOURCE            = 1 << 25;
        const IS_CORRUPT                = 1 << 26;
        const IS_SPAM                   = 1 << 27;
        const HAS_UNKNOWN_MENTION       = 1 << 28;
        const IS_STEWIE                 = 1 << 33;
        const WAS_DELIVERED_QUIETLY     = 1 << 34;
        const DID_NOTIFY_RECIPIENT      = 1 << 35;
        const WAS_DETONATED             = 1 << 36;
        const IS_KT_VERIFIED            = 1 << 37;
        const IS_CRITICAL               = 1 << 38;
        const IS_SOS                    = 1 << 39;
        const IS_PENDING_SATELLITE_SEND = 1 << 41;
        const NEEDS_RELAY               = 1 << 42;
        const SENT_OR_RECEIVED_OFF_GRID = 1 << 43;
    }
}

// gp and gpid (group photo and group photo id)

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CloudParticipant {
    #[serde(rename = "FZPersonID")]
    pub uri: String,
}
impl CloudKitBytesKind for CloudParticipant {
    type Kind = PlistKind;
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CloudProp001 {
    #[serde(rename = "st")]
    pub syndication_type: u32, // guess
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MessageEdit {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub t: Vec<u8>, // this is a streamtyped
    pub d: f64,
    pub bcg: Option<String>, // uuid, refers to something
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MessageEditRange {
    pub lo: u32,
    pub le: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MessageSummaryInfo {
    pub ams: Option<String>,
    #[serde(
        serialize_with = "bin_serialize_opt_vec",
        deserialize_with = "bin_deserialize_opt_vec",
        default
    )]
    pub ampt: Option<Vec<u8>>, // am part (full text part of ams)
    pub amc: Option<u32>,
    pub amb: Option<String>, // balloon id
    pub amd: Option<String>, // GamePigeon
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub ec: HashMap<String, Vec<MessageEdit>>, // edit text
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ep: Vec<u32>, // edit part
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub otr: HashMap<String, MessageEditRange>, // edit range maybe?
    pub ust: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rp: Vec<u32>, // retracted parts
    pub hbr: Option<bool>,
    pub oui: Option<String>,
    pub osn: Option<String>, // service (SMS)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub euh: Vec<String>, // list of handles
}

impl CloudKitBytesKind for CloudProp001 {
    type Kind = PlistKind;
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CloudProp {
    #[serde(rename = "GPUFC")]
    pub gpufc: Option<u32>, // 2
    pub pv: Option<u32>,
    pub number_of_times_respondedto_thread: Option<u32>,
    #[serde(rename = "shouldForceToSMS")]
    pub should_force_to_sms: Option<bool>,
    pub last_seen_message_guid: Option<String>,
    pub message_handshake_state: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_group_identifiers: Vec<String>,
    pub group_photo_guid: Option<String>,
    #[serde(rename = "LSMD")]
    pub last_modification_date: Option<plist::Date>, // not actually optional, just to get around default trait
}
impl CloudKitBytesKind for CloudProp {
    type Kind = PlistKind;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GZipWrapper<T>(pub T);

impl<T: CloudKitBytes> CloudKitBytes for GZipWrapper<T> {
    fn from_bytes(v: Vec<u8>) -> Self {
        Self(T::from_bytes(ungzip(&v).expect("ungzip fialed")))
    }
    fn to_bytes(&self) -> Vec<u8> {
        gzip(&self.0.to_bytes()).expect("gzip fialed")
    }
}

impl<T> Deref for GZipWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for GZipWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(CloudKitRecord, Debug, Default, Clone, Serialize, Deserialize)]
#[cloudkit_record(type = "chatEncryptedv2", encrypted)]
pub struct CloudChat {
    #[cloudkit(rename = "stl")]
    pub style: i64, // 45 for normal chats, 43 for group
    #[cloudkit(rename = "filt")]
    pub is_filtered: i64,
    #[cloudkit(rename = "sqry")]
    pub successful_query: i64,
    #[cloudkit(rename = "ste")]
    pub state: i64, // 3 usually
    #[cloudkit(rename = "cid")]
    pub chat_identifier: String,
    #[cloudkit(rename = "gid")]
    pub group_id: String,
    #[cloudkit(rename = "svc")]
    pub service_name: String,
    #[cloudkit(rename = "ogid")]
    pub original_group_id: String,
    #[cloudkit(rename = "prop")]
    pub properties: Option<CloudProp>,
    #[cloudkit(rename = "ptcpts")]
    pub participants: Vec<CloudParticipant>,
    pub prop001: CloudProp001,
    #[cloudkit(rename = "rwm")]
    pub last_read_message_timestamp: i64,
    #[cloudkit(rename = "lah")]
    pub last_addressed_handle: String,
    pub guid: String,
    #[cloudkit(rename = "name")]
    pub display_name: Option<String>,
    #[serde(
        default,
        serialize_with = "proto_serialize_opt_gzip",
        deserialize_with = "proto_deserialize_opt_gzip"
    )]
    pub proto001: Option<GZipWrapper<ChatProto>>,
    #[cloudkit(rename = "gpid")]
    pub group_photo_guid: Option<String>,
    #[serde(
        default,
        serialize_with = "proto_serialize_opt",
        deserialize_with = "proto_deserialize_opt"
    )]
    #[cloudkit(rename = "gp")]
    pub group_photo: Option<Asset>,
}

pub fn proto_deserialize_opt_gzip<'de, D, T>(d: D) -> Result<Option<GZipWrapper<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Message + Default,
{
    use serde::de::Error;
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(if let Some(s) = s {
        Some(GZipWrapper(
            T::decode(&mut Cursor::new(s.as_ref())).map_err(Error::custom)?,
        ))
    } else {
        None
    })
}

pub fn proto_serialize_opt_gzip<S, T>(x: &Option<GZipWrapper<T>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Message,
{
    x.as_ref()
        .map(|a| Data::new(a.encode_to_vec()))
        .serialize(s)
}

#[derive(CloudKitRecord, Debug, Default, Clone)]
#[cloudkit_record(type = "MessagesSummary")]
pub struct CloudMessageSummary {
    #[cloudkit(rename = "MessageEncryptedV3")]
    pub messages_summary: Vec<i64>,
    #[cloudkit(rename = "chatEncryptedv2")]
    pub chat_summary: Vec<i64>,
    #[cloudkit(rename = "attachment")]
    pub attachment_summary: Vec<i64>,
}

impl CloudMessageSummary {
    fn merge(mut self, other: Self) -> Self {
        self.attachment_summary.extend(other.attachment_summary);
        self.chat_summary.extend(other.chat_summary);
        self.messages_summary.extend(other.messages_summary);
        self
    }
}

#[derive(CloudKitRecord, Debug, Default, Clone)]
#[cloudkit_record(type = "MessageEncryptedV3", encrypted)]
pub struct CloudMessage {
    #[cloudkit(unencrypted)]
    pub utm: Option<SystemTime>, // option for default
    #[cloudkit(rename = "msgType", unencrypted)]
    pub r#type: i64,
    #[cloudkit(rename = "eCode", unencrypted)]
    pub error: i64,
    #[cloudkit(rename = "chatID")]
    pub chat_id: String,
    pub sender: String,
    pub time: i64, // ns since apple epoch
    #[cloudkit(rename = "msgProto2")]
    pub msg_proto_2: Option<GZipWrapper<MessageProto2>>, // always empty afaict??
    #[cloudkit(rename = "dcId")]
    pub destination_caller_id: String,
    #[cloudkit(rename = "msgProto")]
    pub msg_proto: GZipWrapper<MessageProto>,
    pub flags: MessageFlags, // unk
    pub guid: String,
    #[cloudkit(rename = "msgProto3")]
    pub msg_proto_3: Option<GZipWrapper<MessageProto3>>,
    #[cloudkit(rename = "svc")]
    pub service: String,
    #[cloudkit(rename = "msgProto4")]
    pub msg_proto_4: Option<GZipWrapper<MessageProto4>>,
}

impl CloudKitEncryptedValue for MessageFlags {
    fn from_value_encrypted(
        value: &cloudkit_proto::record::field::Value,
        encryptor: &impl CloudKitEncryptor,
        field_name: &str,
    ) -> Option<Self>
    where
        Self: Sized,
    {
        i64::from_value_encrypted(value, encryptor, field_name)
            .map(|v| MessageFlags::from_bits_truncate(v))
    }

    fn to_value_encrypted(
        &self,
        encryptor: &impl CloudKitEncryptor,
        field_name: &str,
    ) -> Option<cloudkit_proto::record::field::Value> {
        self.bits().to_value_encrypted(encryptor, field_name)
    }
}

// a generic "apple has no schema" type. They really don't.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum NumOrString {
    Num(u32),
    String(String),
    Bool(bool),
}
impl Default for NumOrString {
    fn default() -> Self {
        Self::Num(0)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct MMCSAttachmentMeta {
    // MMCS attachments
    pub mmcs_signature_hex: Option<String>,
    pub mmcs_owner: Option<String>,
    pub mmcs_url: Option<String>,
    pub decryption_key: Option<String>,

    // inline attachments
    pub inline_attachment: Option<String>,
    pub message_part: Option<String>,

    pub file_size: Option<NumOrString>,
    pub uti_type: Option<String>,
    pub mime_type: Option<String>,
    pub name: Option<String>,
}

impl Into<Option<MMCSAttachmentMeta>> for &Attachment {
    fn into(self) -> Option<MMCSAttachmentMeta> {
        match &self.a_type {
            AttachmentType::Inline(_inline) => Some(MMCSAttachmentMeta {
                mmcs_signature_hex: None,
                decryption_key: None,
                mmcs_owner: None,
                mmcs_url: None,

                inline_attachment: Some("ia-0".to_string()),
                message_part: Some("0".to_string()),

                file_size: Some(NumOrString::Num(_inline.len() as u32)),
                uti_type: Some(self.uti_type.clone()),
                mime_type: Some(self.mime.clone()),
                name: Some(self.name.clone()),
            }),
            AttachmentType::MMCS(mmcs) => Some(MMCSAttachmentMeta {
                mmcs_signature_hex: Some(encode_hex(&mmcs.signature)),
                decryption_key: Some(encode_hex(&mmcs.key)),
                mmcs_owner: Some(mmcs.object.clone()),
                mmcs_url: Some(mmcs.url.clone()),

                inline_attachment: None,
                message_part: None,

                file_size: Some(NumOrString::Num(mmcs.size as u32)),
                uti_type: Some(self.uti_type.clone()),
                mime_type: Some(self.mime.clone()),
                name: Some(self.name.clone()),
            }),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AttachmentMetaExtra {
    #[serde(rename = "pgens")]
    pub preview_generation_state: Option<NumOrString>, // set to 1
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AttachmentMeta {
    #[serde(rename = "mimet")]
    pub mime_type: Option<String>,
    // yes, these dates can be negative
    #[serde(rename = "sdt")]
    pub start_date: i64,
    // yes, this can be negative, i think apple is trolling...
    #[serde(rename = "tb")]
    pub total_bytes: i64,
    #[serde(rename = "st")]
    pub transfer_state: i32,
    #[serde(rename = "is")]
    pub is_sticker: bool,
    #[serde(rename = "aguid")]
    pub guid: String,
    #[serde(rename = "ha")]
    pub hide_attachment: bool,
    #[serde(rename = "ui")]
    pub user_info: Option<MMCSAttachmentMeta>,
    #[serde(rename = "fn")]
    pub filename: Option<String>, //path
    #[serde(rename = "aui")]
    pub extras: Option<AttachmentMetaExtra>,
    #[serde(rename = "ig")]
    pub is_outgoing: bool,
    #[serde(rename = "tn")]
    pub transfer_name: Option<String>,
    #[serde(rename = "vers")]
    pub version: i32, // set to 1
    #[serde(rename = "t")]
    pub uti: Option<String>, // uti type
    #[serde(rename = "cdt")]
    pub created_date: i64,
    pub pathc: Option<String>, // also transfer name
    #[serde(rename = "mdh")]
    pub md5: Option<String>, // first 8 bytes of md5 hash of file
}
impl CloudKitBytesKind for AttachmentMeta {
    type Kind = PlistKind;
}

#[derive(CloudKitRecord, Debug, Default, Clone)]
#[cloudkit_record(type = "attachment", encrypted)]
pub struct CloudAttachment {
    pub cm: GZipWrapper<AttachmentMeta>,
    pub lqa: Asset,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CloudMessageRecordSystemFields {
    pub etag: Option<String>,
    pub created_at: Option<f64>,
    pub modified_at: Option<f64>,
    pub permission: Option<u32>,
}

impl CloudMessageRecordSystemFields {
    fn from_record(record: &Record, change_etag: Option<&str>) -> Self {
        Self {
            etag: change_etag
                .map(ToOwned::to_owned)
                .or_else(|| record.etag.clone()),
            created_at: record
                .time_statistics
                .as_ref()
                .and_then(|statistics| statistics.creation.as_ref())
                .and_then(|date| date.time),
            modified_at: record
                .time_statistics
                .as_ref()
                .and_then(|statistics| statistics.modification.as_ref())
                .and_then(|date| date.time),
            permission: record.permission,
        }
    }
}

#[cfg(test)]
mod cloud_message_page_tests {
    use super::*;

    #[tokio::test]
    async fn legacy_page_deadline_preserves_timeout_as_retryable_io_failure() {
        let result = legacy_cloudkit_page_with_deadline(Duration::from_millis(1), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok::<_, PushError>(())
        })
        .await;

        let PushError::IoError(error) = result.expect_err("operation must time out") else {
            panic!("timeout must remain an I/O failure");
        };
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(error.to_string().contains("before cursor commit"));
    }

    #[tokio::test]
    async fn legacy_page_deadline_returns_completed_page() {
        let result = legacy_cloudkit_page_with_deadline(Duration::from_secs(1), async {
            Ok::<_, PushError>("page")
        })
        .await;

        assert_eq!(result.expect("completed page"), "page");
    }

    fn fixture_identifier(name: &str) -> RecordIdentifier {
        RecordIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(name.to_string()),
                r#type: Some(cloudkit_proto::identifier::Type::Record as i32),
            }),
            zone_identifier: None,
        }
    }

    #[test]
    fn ordered_page_preserves_upsert_then_tombstone_and_system_metadata() {
        let changes = vec![
            RecordChange {
                identifier: Some(fixture_identifier("fixture-upsert")),
                etag: Some("etag-upsert".to_string()),
                record_type: Some(cloudkit_proto::record::Type {
                    name: Some("FixtureRecord".to_string()),
                }),
                r#type: Some(1),
                record: Some(Record {
                    etag: Some("record-etag".to_string()),
                    record_identifier: Some(fixture_identifier("fixture-upsert")),
                    r#type: Some(cloudkit_proto::record::Type {
                        name: Some("FixtureRecord".to_string()),
                    }),
                    permission: Some(7),
                    ..Default::default()
                }),
            },
            RecordChange {
                identifier: Some(fixture_identifier("fixture-delete")),
                etag: Some("etag-delete".to_string()),
                record_type: Some(cloudkit_proto::record::Type {
                    name: Some("FixtureRecord".to_string()),
                }),
                r#type: Some(3),
                record: None,
            },
        ];

        let mapped = map_ordered_page_changes(changes, "FixtureRecord");

        assert_eq!(mapped.len(), 2);
        assert_eq!(mapped[0].record_name.as_deref(), Some("fixture-upsert"));
        assert!(matches!(
            mapped[0].kind,
            CloudMessageRecordKind::EncryptedUpsert
        ));
        assert!(mapped[0].encrypted_record.is_some());
        assert!(mapped[0].tombstone_payload.is_none());
        assert_eq!(
            mapped[0]
                .system_fields
                .as_ref()
                .and_then(|fields| fields.etag.as_deref()),
            Some("etag-upsert"),
        );
        assert_eq!(
            mapped[0]
                .system_fields
                .as_ref()
                .and_then(|fields| fields.permission),
            Some(7),
        );

        assert_eq!(mapped[1].record_name.as_deref(), Some("fixture-delete"));
        assert!(matches!(mapped[1].kind, CloudMessageRecordKind::Tombstone));
        assert!(mapped[1].encrypted_record.is_none());
        assert!(mapped[1].tombstone_payload.is_some());
    }

    #[test]
    fn unexpected_record_type_is_retained_but_not_decoded() {
        let changes = vec![RecordChange {
            identifier: Some(fixture_identifier("fixture-unknown")),
            etag: None,
            record_type: Some(cloudkit_proto::record::Type {
                name: Some("FutureRecordType".to_string()),
            }),
            r#type: Some(1),
            record: Some(Record {
                record_identifier: Some(fixture_identifier("fixture-unknown")),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some("FutureRecordType".to_string()),
                }),
                ..Default::default()
            }),
        }];

        let mapped = map_ordered_page_changes(changes, "FixtureRecord");

        assert!(matches!(
            mapped[0].kind,
            CloudMessageRecordKind::UnsupportedRecordType
        ));
        assert!(mapped[0].encrypted_record.is_some());
    }

    #[test]
    fn ordered_page_accepts_omitted_redundant_inner_record_identifier() {
        let changes = vec![RecordChange {
            identifier: Some(fixture_identifier("fixture-outer-only")),
            etag: Some("etag-outer-only".to_string()),
            record_type: Some(cloudkit_proto::record::Type {
                name: Some("FixtureRecord".to_string()),
            }),
            r#type: Some(1),
            record: Some(Record {
                record_identifier: None,
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some("FixtureRecord".to_string()),
                }),
                ..Default::default()
            }),
        }];

        let mapped = map_ordered_page_changes(changes, "FixtureRecord");

        assert_eq!(mapped[0].record_name.as_deref(), Some("fixture-outer-only"));
        assert!(matches!(
            mapped[0].kind,
            CloudMessageRecordKind::EncryptedUpsert
        ));
        assert!(mapped[0].encrypted_record.is_some());
    }

    #[test]
    fn modified_change_type_with_record_is_an_upsert() {
        let changes = vec![RecordChange {
            identifier: Some(fixture_identifier("fixture-modified")),
            etag: None,
            record_type: Some(cloudkit_proto::record::Type {
                name: Some("FixtureRecord".to_string()),
            }),
            r#type: Some(2),
            record: Some(Record {
                record_identifier: Some(fixture_identifier("fixture-modified")),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some("FixtureRecord".to_string()),
                }),
                ..Default::default()
            }),
        }];

        let mapped = map_ordered_page_changes(changes, "FixtureRecord");

        assert!(matches!(
            mapped[0].kind,
            CloudMessageRecordKind::EncryptedUpsert
        ));
        assert!(mapped[0].encrypted_record.is_some());
        assert!(mapped[0].tombstone_payload.is_none());
    }

    #[test]
    fn present_malformed_inner_record_identifier_is_quarantined() {
        let changes = vec![RecordChange {
            identifier: Some(fixture_identifier("fixture-outer")),
            etag: None,
            record_type: Some(cloudkit_proto::record::Type {
                name: Some("FixtureRecord".to_string()),
            }),
            r#type: Some(1),
            record: Some(Record {
                record_identifier: Some(RecordIdentifier {
                    value: None,
                    zone_identifier: None,
                }),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some("FixtureRecord".to_string()),
                }),
                ..Default::default()
            }),
        }];

        let mapped = map_ordered_page_changes(changes, "FixtureRecord");

        assert!(matches!(
            mapped[0].kind,
            CloudMessageRecordKind::MalformedMetadata
        ));
    }

    #[test]
    fn malformed_field_metadata_is_quarantined_without_decoding() {
        let changes = vec![RecordChange {
            identifier: Some(fixture_identifier("fixture-malformed")),
            etag: None,
            record_type: Some(cloudkit_proto::record::Type {
                name: Some("FixtureRecord".to_string()),
            }),
            r#type: Some(1),
            record: Some(Record {
                record_identifier: Some(fixture_identifier("fixture-malformed")),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some("FixtureRecord".to_string()),
                }),
                record_field: vec![cloudkit_proto::record::Field {
                    identifier: None,
                    value: None,
                }],
                ..Default::default()
            }),
        }];

        let mapped = map_ordered_page_changes(changes, "FixtureRecord");

        assert!(matches!(
            mapped[0].kind,
            CloudMessageRecordKind::MalformedMetadata
        ));
        assert!(mapped[0].encrypted_record.is_some());
    }

    #[test]
    fn mismatched_record_identity_is_quarantined_without_decoding() {
        let changes = vec![RecordChange {
            identifier: Some(fixture_identifier("outer-record")),
            etag: None,
            record_type: Some(cloudkit_proto::record::Type {
                name: Some("FixtureRecord".to_string()),
            }),
            r#type: Some(1),
            record: Some(Record {
                record_identifier: Some(fixture_identifier("different-inner-record")),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some("FixtureRecord".to_string()),
                }),
                ..Default::default()
            }),
        }];

        let mapped = map_ordered_page_changes(changes, "FixtureRecord");

        assert!(matches!(
            mapped[0].kind,
            CloudMessageRecordKind::MalformedMetadata
        ));
        assert!(mapped[0].encrypted_record.is_some());
    }

    #[test]
    fn contradictory_change_shape_is_quarantined_without_decoding() {
        let changes = vec![RecordChange {
            identifier: Some(fixture_identifier("fixture-contradictory")),
            etag: None,
            record_type: Some(cloudkit_proto::record::Type {
                name: Some("FixtureRecord".to_string()),
            }),
            r#type: Some(3),
            record: Some(Record {
                record_identifier: Some(fixture_identifier("fixture-contradictory")),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some("FixtureRecord".to_string()),
                }),
                ..Default::default()
            }),
        }];

        let mapped = map_ordered_page_changes(changes, "FixtureRecord");

        assert!(matches!(
            mapped[0].kind,
            CloudMessageRecordKind::MalformedMetadata
        ));
        assert!(mapped[0].encrypted_record.is_some());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudMessageRecordKind {
    EncryptedUpsert,
    Tombstone,
    UnsupportedRecordType,
    MalformedMetadata,
}

#[derive(Debug)]
pub struct CloudMessageRecordPageChange {
    pub record_name: Option<String>,
    pub record_type: Option<String>,
    pub change_type: Option<i32>,
    pub system_fields: Option<CloudMessageRecordSystemFields>,
    /// The original server record. Message fields remain in their CloudKit/PCS
    /// encrypted representation and can be durably journaled before apply.
    pub encrypted_record: Option<Vec<u8>>,
    /// The original change envelope for a deletion. This preserves Apple
    /// tombstone metadata without inventing a local delete.
    pub tombstone_payload: Option<Vec<u8>>,
    pub kind: CloudMessageRecordKind,
}

pub struct CloudMessageRecordPage {
    pub changes: Vec<CloudMessageRecordPageChange>,
    pub next_token: Option<Vec<u8>>,
    pub status: i32,
}

impl CloudMessageRecordPage {
    pub fn is_complete(&self) -> bool {
        self.status == 3
    }
}

fn record_identifier_name(identifier: Option<&RecordIdentifier>) -> Option<&str> {
    identifier
        .and_then(|identifier| identifier.value.as_ref())
        .and_then(|identifier| identifier.name.as_deref())
        .filter(|name| !name.is_empty())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloudMessageMetadataFailure {
    OuterIdentifierMissing,
    UpsertRecordMissing,
    TombstoneRecordPresent,
    UnsupportedChangeShape,
    InnerIdentifierMalformed,
    InnerIdentifierMismatch,
    NestedRecordTypeMissing,
    NestedRecordTypeMismatch,
    FieldIdentifierMissing,
    InvariantResolvedTypeMissing,
}

#[derive(Default)]
struct CloudMessageMetadataFailureCounts {
    outer_identifier_missing: usize,
    upsert_record_missing: usize,
    tombstone_record_present: usize,
    unsupported_change_shape: usize,
    inner_identifier_malformed: usize,
    inner_identifier_mismatch: usize,
    nested_record_type_missing: usize,
    nested_record_type_mismatch: usize,
    field_identifier_missing: usize,
    invariant_resolved_type_missing: usize,
}

impl CloudMessageMetadataFailureCounts {
    fn record(&mut self, failure: CloudMessageMetadataFailure) {
        match failure {
            CloudMessageMetadataFailure::OuterIdentifierMissing => {
                self.outer_identifier_missing += 1;
            }
            CloudMessageMetadataFailure::UpsertRecordMissing => {
                self.upsert_record_missing += 1;
            }
            CloudMessageMetadataFailure::TombstoneRecordPresent => {
                self.tombstone_record_present += 1;
            }
            CloudMessageMetadataFailure::UnsupportedChangeShape => {
                self.unsupported_change_shape += 1;
            }
            CloudMessageMetadataFailure::InnerIdentifierMalformed => {
                self.inner_identifier_malformed += 1;
            }
            CloudMessageMetadataFailure::InnerIdentifierMismatch => {
                self.inner_identifier_mismatch += 1;
            }
            CloudMessageMetadataFailure::NestedRecordTypeMissing => {
                self.nested_record_type_missing += 1;
            }
            CloudMessageMetadataFailure::NestedRecordTypeMismatch => {
                self.nested_record_type_mismatch += 1;
            }
            CloudMessageMetadataFailure::FieldIdentifierMissing => {
                self.field_identifier_missing += 1;
            }
            CloudMessageMetadataFailure::InvariantResolvedTypeMissing => {
                self.invariant_resolved_type_missing += 1;
            }
        }
    }

    fn total(&self) -> usize {
        self.outer_identifier_missing
            + self.upsert_record_missing
            + self.tombstone_record_present
            + self.unsupported_change_shape
            + self.inner_identifier_malformed
            + self.inner_identifier_mismatch
            + self.nested_record_type_missing
            + self.nested_record_type_mismatch
            + self.field_identifier_missing
            + self.invariant_resolved_type_missing
    }
}

fn format_metadata_failure_counts(counts: &CloudMessageMetadataFailureCounts) -> String {
    format!(
        "CloudKit V2 structural metadata counts outer_missing={} upsert_record_missing={} tombstone_record_present={} shape_unsupported={} inner_malformed={} inner_mismatch={} nested_type_missing={} nested_type_mismatch={} field_identifier_missing={} invariant_resolved_type_missing={}",
        counts.outer_identifier_missing,
        counts.upsert_record_missing,
        counts.tombstone_record_present,
        counts.unsupported_change_shape,
        counts.inner_identifier_malformed,
        counts.inner_identifier_mismatch,
        counts.nested_record_type_missing,
        counts.nested_record_type_mismatch,
        counts.field_identifier_missing,
        counts.invariant_resolved_type_missing,
    )
}

fn change_shape_failure(
    change_type: Option<i32>,
    has_record: bool,
) -> Option<CloudMessageMetadataFailure> {
    match (change_type, has_record) {
        (Some(1 | 2), false) => Some(CloudMessageMetadataFailure::UpsertRecordMissing),
        (Some(3), true) => Some(CloudMessageMetadataFailure::TombstoneRecordPresent),
        (Some(1 | 2), true) | (Some(3), false) | (None, _) => None,
        (Some(_), _) => Some(CloudMessageMetadataFailure::UnsupportedChangeShape),
    }
}

#[cfg(test)]
mod cloud_message_metadata_diagnostic_tests {
    use super::*;

    #[test]
    fn distinguishes_change_shape_failures() {
        assert_eq!(
            change_shape_failure(Some(1), false),
            Some(CloudMessageMetadataFailure::UpsertRecordMissing)
        );
        assert_eq!(
            change_shape_failure(Some(2), false),
            Some(CloudMessageMetadataFailure::UpsertRecordMissing)
        );
        assert_eq!(
            change_shape_failure(Some(3), true),
            Some(CloudMessageMetadataFailure::TombstoneRecordPresent)
        );
        assert_eq!(
            change_shape_failure(Some(7), true),
            Some(CloudMessageMetadataFailure::UnsupportedChangeShape)
        );
        assert_eq!(change_shape_failure(Some(1), true), None);
        assert_eq!(change_shape_failure(Some(2), true), None);
        assert_eq!(change_shape_failure(Some(3), false), None);
        assert_eq!(change_shape_failure(None, true), None);
    }

    #[test]
    fn diagnostic_format_contains_only_fixed_labels_and_counts() {
        let mut counts = CloudMessageMetadataFailureCounts::default();
        for failure in [
            CloudMessageMetadataFailure::OuterIdentifierMissing,
            CloudMessageMetadataFailure::UpsertRecordMissing,
            CloudMessageMetadataFailure::TombstoneRecordPresent,
            CloudMessageMetadataFailure::UnsupportedChangeShape,
            CloudMessageMetadataFailure::InnerIdentifierMalformed,
            CloudMessageMetadataFailure::InnerIdentifierMismatch,
            CloudMessageMetadataFailure::NestedRecordTypeMissing,
            CloudMessageMetadataFailure::NestedRecordTypeMismatch,
            CloudMessageMetadataFailure::FieldIdentifierMissing,
            CloudMessageMetadataFailure::InvariantResolvedTypeMissing,
        ] {
            counts.record(failure);
        }

        assert_eq!(
            format_metadata_failure_counts(&counts),
            "CloudKit V2 structural metadata counts outer_missing=1 upsert_record_missing=1 tombstone_record_present=1 shape_unsupported=1 inner_malformed=1 inner_mismatch=1 nested_type_missing=1 nested_type_mismatch=1 field_identifier_missing=1 invariant_resolved_type_missing=1"
        );
    }
}

fn record_metadata_failure(
    record: &Record,
    change_record_name: Option<&str>,
    change_record_type: Option<&str>,
) -> Option<CloudMessageMetadataFailure> {
    let Some(change_record_name) = change_record_name else {
        return Some(CloudMessageMetadataFailure::OuterIdentifierMissing);
    };
    // RetrieveChanges already binds the record to the outer change
    // identifier. Apple may omit the redundant identifier inside the nested
    // Record, so require equality only when that inner field is present. A
    // present-but-malformed or mismatched inner identifier still fails closed.
    if let Some(inner_identifier) = record.record_identifier.as_ref() {
        let Some(inner_record_name) = record_identifier_name(Some(inner_identifier)) else {
            return Some(CloudMessageMetadataFailure::InnerIdentifierMalformed);
        };
        if inner_record_name != change_record_name {
            return Some(CloudMessageMetadataFailure::InnerIdentifierMismatch);
        }
    }

    let Some(record_type) = record
        .r#type
        .as_ref()
        .and_then(|record_type| record_type.name.as_deref())
        .filter(|record_type| !record_type.is_empty())
    else {
        return Some(CloudMessageMetadataFailure::NestedRecordTypeMissing);
    };
    if change_record_type.is_some_and(|change_record_type| change_record_type != record_type) {
        return Some(CloudMessageMetadataFailure::NestedRecordTypeMismatch);
    }

    if record.record_field.iter().any(|field| {
        field
            .identifier
            .as_ref()
            .and_then(|identifier| identifier.name.as_deref())
            .is_none_or(str::is_empty)
    }) {
        return Some(CloudMessageMetadataFailure::FieldIdentifierMissing);
    }

    None
}

fn map_ordered_page_changes(
    changes: Vec<RecordChange>,
    expected_record_type: &str,
) -> Vec<CloudMessageRecordPageChange> {
    let mut metadata_failures = CloudMessageMetadataFailureCounts::default();
    let mapped = changes
        .into_iter()
        .map(|change| {
            let record_name =
                record_identifier_name(change.identifier.as_ref()).map(ToOwned::to_owned);
            let record_type = change
                .record_type
                .as_ref()
                .and_then(|record_type| record_type.name.clone())
                .filter(|record_type| !record_type.is_empty())
                .or_else(|| {
                    change
                        .record
                        .as_ref()
                        .and_then(|record| record.r#type.as_ref())
                        .and_then(|record_type| record_type.name.clone())
                        .filter(|record_type| !record_type.is_empty())
                });
            let system_fields = change.record.as_ref().map(|record| {
                CloudMessageRecordSystemFields::from_record(record, change.etag.as_deref())
            });
            let encrypted_record = change.record.as_ref().map(Message::encode_to_vec);
            let tombstone_payload = change.record.is_none().then(|| change.encode_to_vec());

            let change_shape_failure = change_shape_failure(change.r#type, change.record.is_some());
            let metadata_failure = if record_name.is_none() {
                Some(CloudMessageMetadataFailure::OuterIdentifierMissing)
            } else if change_shape_failure.is_some() {
                change_shape_failure
            } else if let Some(record) = change.record.as_ref() {
                record_metadata_failure(
                    record,
                    record_name.as_deref(),
                    change
                        .record_type
                        .as_ref()
                        .and_then(|record_type| record_type.name.as_deref()),
                )
                .or_else(|| {
                    record_type
                        .is_none()
                        .then_some(CloudMessageMetadataFailure::InvariantResolvedTypeMissing)
                })
            } else {
                None
            };
            if let Some(failure) = metadata_failure {
                metadata_failures.record(failure);
            }

            let kind = if metadata_failure.is_some() {
                CloudMessageRecordKind::MalformedMetadata
            } else if change.record.is_some() {
                match record_type.as_deref() {
                    Some(record_type) if record_type == expected_record_type => {
                        CloudMessageRecordKind::EncryptedUpsert
                    }
                    Some(_) => CloudMessageRecordKind::UnsupportedRecordType,
                    None => {
                        // Accounted for as InvariantResolvedTypeMissing above.
                        debug_assert!(false, "missing resolved record type was not classified");
                        CloudMessageRecordKind::MalformedMetadata
                    }
                }
            } else {
                CloudMessageRecordKind::Tombstone
            };

            CloudMessageRecordPageChange {
                record_name,
                record_type,
                change_type: change.r#type,
                system_fields,
                encrypted_record,
                tombstone_payload,
                kind,
            }
        })
        .collect();

    if metadata_failures.total() > 0 {
        // Content-free canary diagnostic. Counts and fixed categories only:
        // never include record names, types, field names, payloads, or tokens.
        warn!("{}", format_metadata_failure_counts(&metadata_failures));
    }

    mapped
}

/// The redacted result of one prepared message save. The native caller gets
/// durable correlation data and CloudKit's retry classification, but never a
/// raw CloudKit record or a `PushError` that could contain response payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudMessagesSaveFailureScope {
    Request,
    Operation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudMessagesSaveResult {
    Succeeded,
    /// The request crossed the remote-submission ambiguity boundary but no
    /// trustworthy per-operation response proved what Apple committed. A
    /// durable caller must reconcile this stable record name and payload; it
    /// must not replay the create as an ordinary retry.
    UnknownOutcome {
        failure_class: Option<CloudKitFailureClass>,
        retry_after: Option<Duration>,
    },
    Failed {
        scope: CloudMessagesSaveFailureScope,
        failure_class: Option<CloudKitFailureClass>,
        retry_after: Option<Duration>,
    },
}

/// Protected reconciliation result for one stable message record name.
/// Message contents never cross the native bridge; the caller compares them
/// inside Rust and receives only the disposition and retry classification.
#[derive(Debug)]
pub enum CloudMessageRecordLookup {
    Found(CloudMessage),
    NotFound,
    Unresolved {
        failure_class: Option<CloudKitFailureClass>,
        retry_after: Option<Duration>,
    },
}

fn is_cloudkit_record_not_found(error: &PushError) -> bool {
    let PushError::CloudKitError(result) = error else {
        return false;
    };
    result
        .error
        .as_ref()
        .and_then(|error| error.server_error.as_ref())
        .and_then(|error| error.r#type)
        .and_then(|code| {
            cloudkit_proto::response_operation::result::error::server::Code::try_from(code).ok()
        })
        == Some(cloudkit_proto::response_operation::result::error::server::Code::NotFound)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudMessagesSaveOutcome {
    pub local_operation_id: String,
    pub apple_operation_uuid: String,
    pub result: CloudMessagesSaveResult,
}

/// Native-only input for one V2 message save. The Apple CloudKit record name
/// is intentionally distinct from the local durable operation correlation ID.
/// The former is used only to build the native save operation; only the latter
/// is retained in the prepared owner and returned in outcomes.
pub struct CloudMessageSaveInput {
    pub local_operation_id: String,
    pub server_record_name: String,
    /// The exact persisted Apple operation UUID bound to this local operation.
    /// Preparation rejects positional reordering against the request identity.
    pub apple_operation_uuid: String,
    pub message: CloudMessage,
}

/// Non-forgeable native binding to the exact general Messages container that
/// completed writer preparation. User-ID equality is insufficient because a
/// same-account container replacement can carry different prepared
/// authentication or PCS cache state.
pub struct CloudMessagesWriterPreparationBinding<P: AnisetteProvider> {
    container: Arc<CloudKitOpenContainer<'static, P>>,
}

impl<P: AnisetteProvider> CloudMessagesWriterPreparationBinding<P> {
    pub fn container_scoped_user_id(&self) -> &str {
        &self.container.user_id
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(container: Arc<CloudKitOpenContainer<'static, P>>) -> Self {
        Self { container }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudMessagesSaveConsumeError {
    CorrelationMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloudMessagesSaveMode {
    /// Existing mapped-record updates are intentionally unsupported until
    /// predecessor ETag binding is fixture-proven and durably persisted.
    CreateOnly,
}

impl CloudMessagesSaveMode {
    const fn update_flag(self) -> bool {
        match self {
            Self::CreateOnly => false,
        }
    }
}

/// A native, single-use owner for one message-only CloudKit save request.
///
/// This intentionally has no `Clone` implementation. Once `consume_once` is
/// called, the authentication, request identity, and operations are moved
/// into the no-replay CloudKit primitive together. The caller cannot recreate
/// or submit the same prepared request through this value.
pub struct CloudMessagesPreparedSaveSubmission<P: AnisetteProvider> {
    container: Arc<CloudKitOpenContainer<'static, P>>,
    session: CloudKitSession,
    request_identity: CloudKitRequestIdentity,
    prepared_authentication: CloudKitPreparedAuthentication<P>,
    operations: Vec<SaveRecordOperation>,
    local_operation_ids: Vec<String>,
    retry_policy: CloudKitRetryPolicy,
}

impl<P: AnisetteProvider> CloudMessagesPreparedSaveSubmission<P> {
    /// Consumes this owner exactly once through the identified, no-replay
    /// CloudKit operation. Request-level failures are converted into one
    /// redacted outcome per local record so the durable caller retains the
    /// local-ID/Apple-operation-ID correlation even when no response arrives.
    pub async fn consume_once(
        self,
    ) -> Result<Vec<CloudMessagesSaveOutcome>, CloudMessagesSaveConsumeError> {
        let Self {
            container,
            session,
            request_identity,
            prepared_authentication,
            operations,
            local_operation_ids,
            retry_policy,
        } = self;

        let expected_request_identity = request_identity.clone();
        let operation_uuids = expected_request_identity.operation_uuids().to_vec();
        if operation_uuids.len() != local_operation_ids.len()
            || operations.len() != local_operation_ids.len()
        {
            return Err(CloudMessagesSaveConsumeError::CorrelationMismatch);
        }
        // Retain only the redacted durable correlation needed to fail closed
        // if Apple's response is malformed. Once the request is submitted, a
        // response-identity or response-shape mismatch cannot prove that the
        // corresponding create did not commit, so it must never become an
        // ordinary retryable failure.
        let correlation_fallback = local_operation_ids
            .iter()
            .cloned()
            .zip(operation_uuids.iter().cloned())
            .collect::<Vec<_>>();
        let response = container
            .perform_operations_detailed_once_with_identity(
                &session,
                &operations,
                IsolationLevel::Operation,
                &retry_policy,
                request_identity,
                prepared_authentication,
            )
            .await;

        let mapped = match response {
            Ok(response) => redacted_batch_response_outcomes(
                local_operation_ids,
                &expected_request_identity,
                response,
            ),
            Err(failure) => redacted_request_failure_outcomes(
                local_operation_ids,
                &expected_request_identity,
                failure,
            ),
        };
        match mapped {
            Ok(outcomes) => Ok(outcomes),
            Err(CloudMessagesSaveConsumeError::CorrelationMismatch) => Ok(correlation_fallback
                .into_iter()
                .map(
                    |(local_operation_id, apple_operation_uuid)| CloudMessagesSaveOutcome {
                        local_operation_id,
                        apple_operation_uuid,
                        result: CloudMessagesSaveResult::UnknownOutcome {
                            failure_class: Some(CloudKitFailureClass::Unknown),
                            retry_after: None,
                        },
                    },
                )
                .collect()),
        }
    }
}

fn redacted_batch_response_outcomes(
    local_operation_ids: Vec<String>,
    expected_request_identity: &CloudKitRequestIdentity,
    response: CloudKitBatchResponse<Option<Record>>,
) -> Result<Vec<CloudMessagesSaveOutcome>, CloudMessagesSaveConsumeError> {
    if response.request_identity != *expected_request_identity {
        return Err(CloudMessagesSaveConsumeError::CorrelationMismatch);
    }

    let operation_uuids = expected_request_identity.operation_uuids().to_vec();
    if local_operation_ids.len() != operation_uuids.len()
        || response.outcomes.len() != local_operation_ids.len()
    {
        return Err(CloudMessagesSaveConsumeError::CorrelationMismatch);
    }

    let mut outcomes_by_index = (0..local_operation_ids.len())
        .map(|_| None)
        .collect::<Vec<_>>();
    for outcome in response.outcomes {
        let request_index = outcome.request_index;
        if request_index >= outcomes_by_index.len() || outcomes_by_index[request_index].is_some() {
            return Err(CloudMessagesSaveConsumeError::CorrelationMismatch);
        }
        outcomes_by_index[request_index] = Some(outcome);
    }

    local_operation_ids
        .into_iter()
        .zip(operation_uuids)
        .enumerate()
        .map(
            |(request_index, (local_operation_id, apple_operation_uuid))| {
                let outcome = outcomes_by_index[request_index]
                    .take()
                    .ok_or(CloudMessagesSaveConsumeError::CorrelationMismatch)?;
                if outcome.operation_uuid != apple_operation_uuid {
                    return Err(CloudMessagesSaveConsumeError::CorrelationMismatch);
                }
                Ok(CloudMessagesSaveOutcome {
                    local_operation_id,
                    apple_operation_uuid,
                    result: if outcome.result.is_ok() {
                        CloudMessagesSaveResult::Succeeded
                    } else if outcome.failure_class.is_none()
                        || outcome.failure_class == Some(CloudKitFailureClass::Unknown)
                    {
                        // An unclassified operation response is not proof of
                        // rejection. Preserve the stable record mapping and
                        // force reconciliation rather than replaying it.
                        CloudMessagesSaveResult::UnknownOutcome {
                            failure_class: outcome.failure_class,
                            retry_after: outcome.retry_after,
                        }
                    } else {
                        CloudMessagesSaveResult::Failed {
                            scope: CloudMessagesSaveFailureScope::Operation,
                            failure_class: outcome.failure_class,
                            retry_after: outcome.retry_after,
                        }
                    },
                })
            },
        )
        .collect()
}

fn redacted_request_failure_outcomes(
    local_operation_ids: Vec<String>,
    expected_request_identity: &CloudKitRequestIdentity,
    failure: CloudKitRequestFailure,
) -> Result<Vec<CloudMessagesSaveOutcome>, CloudMessagesSaveConsumeError> {
    if failure.request_identity.as_ref() != Some(expected_request_identity)
        || local_operation_ids.len() != expected_request_identity.operation_uuids().len()
    {
        return Err(CloudMessagesSaveConsumeError::CorrelationMismatch);
    }

    let operation_uuids = expected_request_identity.operation_uuids().to_vec();
    let failure_result = if failure.outcome_may_be_committed {
        CloudMessagesSaveResult::UnknownOutcome {
            failure_class: failure.failure_class,
            retry_after: failure.retry_after,
        }
    } else {
        CloudMessagesSaveResult::Failed {
            scope: CloudMessagesSaveFailureScope::Request,
            failure_class: failure.failure_class,
            retry_after: failure.retry_after,
        }
    };

    Ok(local_operation_ids
        .into_iter()
        .zip(operation_uuids)
        .map(
            |(local_operation_id, apple_operation_uuid)| CloudMessagesSaveOutcome {
                local_operation_id,
                apple_operation_uuid,
                result: failure_result,
            },
        )
        .collect())
}

fn ordered_message_save_pairs(
    messages: &[CloudMessageSaveInput],
    request_identity: &CloudKitRequestIdentity,
) -> Result<Vec<(String, String)>, PushError> {
    if messages.is_empty()
        || messages.len() > CLOUDKIT_MAX_OPERATIONS_PER_REQUEST
        || messages.iter().any(|input| {
            input.local_operation_id.is_empty()
                || input.server_record_name.is_empty()
                || input.apple_operation_uuid.is_empty()
        })
    {
        return Err(PushError::BadMsg);
    }

    let mut seen_local_operation_ids = std::collections::HashSet::with_capacity(messages.len());
    let mut seen_server_record_names = std::collections::HashSet::with_capacity(messages.len());
    if messages.iter().any(|input| {
        !seen_local_operation_ids.insert(input.local_operation_id.as_str())
            || !seen_server_record_names.insert(input.server_record_name.as_str())
    }) {
        return Err(PushError::BadMsg);
    }

    if request_identity.operation_uuids().len() != messages.len() {
        return Err(PushError::BadMsg);
    }
    if messages
        .iter()
        .zip(request_identity.operation_uuids())
        .any(|(input, persisted_uuid)| input.apple_operation_uuid != *persisted_uuid)
    {
        return Err(PushError::BadMsg);
    }

    Ok(messages
        .iter()
        .map(|input| {
            (
                input.local_operation_id.clone(),
                input.apple_operation_uuid.clone(),
            )
        })
        .collect())
}

#[cfg(test)]
mod cloud_message_save_tests {
    use super::*;
    use crate::cloudkit::CloudKitOperationOutcome;

    #[test]
    fn only_explicit_server_not_found_proves_record_absence() {
        let not_found = PushError::CloudKitError(cloudkit_proto::response_operation::Result {
            error: Some(cloudkit_proto::response_operation::result::Error {
                server_error: Some(cloudkit_proto::response_operation::result::error::Server {
                    r#type: Some(
                        cloudkit_proto::response_operation::result::error::server::Code::NotFound
                            as i32,
                    ),
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
        let overloaded = PushError::CloudKitError(cloudkit_proto::response_operation::Result {
            error: Some(cloudkit_proto::response_operation::result::Error {
                server_error: Some(cloudkit_proto::response_operation::result::error::Server {
                    r#type: Some(
                        cloudkit_proto::response_operation::result::error::server::Code::Overloaded
                            as i32,
                    ),
                }),
                ..Default::default()
            }),
            ..Default::default()
        });

        assert!(is_cloudkit_record_not_found(&not_found));
        assert!(!is_cloudkit_record_not_found(&overloaded));
        assert!(!is_cloudkit_record_not_found(&PushError::BadMsg));
    }

    fn input(
        local_operation_id: &str,
        server_record_name: &str,
        apple_operation_uuid: &str,
    ) -> CloudMessageSaveInput {
        CloudMessageSaveInput {
            local_operation_id: local_operation_id.to_string(),
            server_record_name: server_record_name.to_string(),
            apple_operation_uuid: apple_operation_uuid.to_string(),
            message: CloudMessage::default(),
        }
    }

    fn identity_with_http(
        http_request_uuid: &str,
        operation_uuids: &[&str],
    ) -> CloudKitRequestIdentity {
        CloudKitRequestIdentity::new(
            http_request_uuid.to_string(),
            operation_uuids
                .iter()
                .map(|uuid| (*uuid).to_string())
                .collect(),
        )
        .unwrap()
    }

    fn identity(operation_uuids: &[&str]) -> CloudKitRequestIdentity {
        identity_with_http("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", operation_uuids)
    }

    #[test]
    fn save_pairing_preserves_local_order_without_returning_server_names() {
        let operation_a = "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB";
        let operation_b = "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC";
        let messages = vec![
            input("local-operation-a", "private-server-record-a", operation_a),
            input("local-operation-b", "private-server-record-b", operation_b),
        ];
        let request_identity = identity(&[operation_a, operation_b]);

        let pairs = ordered_message_save_pairs(&messages, &request_identity).unwrap();

        assert_eq!(
            pairs,
            vec![
                (
                    "local-operation-a".to_string(),
                    "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB".to_string(),
                ),
                (
                    "local-operation-b".to_string(),
                    "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC".to_string(),
                ),
            ]
        );
        assert!(!format!("{pairs:?}").contains("private-server-record"));
    }

    #[test]
    fn save_pairing_rejects_empty_duplicate_and_mismatched_batches() {
        let operation_a = "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB";
        let operation_b = "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC";
        let request_identity = identity(&[operation_a]);

        assert!(matches!(
            ordered_message_save_pairs(&[], &request_identity),
            Err(PushError::BadMsg)
        ));
        assert!(matches!(
            ordered_message_save_pairs(
                &[input("", "server-record", operation_a)],
                &request_identity,
            ),
            Err(PushError::BadMsg)
        ));
        assert!(matches!(
            ordered_message_save_pairs(
                &[
                    input("duplicate", "server-a", operation_a),
                    input("duplicate", "server-b", operation_b),
                ],
                &identity(&[operation_a, operation_b]),
            ),
            Err(PushError::BadMsg)
        ));
        assert!(matches!(
            ordered_message_save_pairs(
                &[
                    input("one", "server", operation_a),
                    input("two", "server", operation_b),
                ],
                &identity(&[operation_a, operation_b]),
            ),
            Err(PushError::BadMsg)
        ));
        assert!(matches!(
            ordered_message_save_pairs(
                &[
                    input("one", "server-one", operation_a),
                    input("two", "server-two", operation_b),
                ],
                &request_identity,
            ),
            Err(PushError::BadMsg)
        ));
        assert!(matches!(
            ordered_message_save_pairs(
                &[
                    input("one", "server-one", operation_b),
                    input("two", "server-two", operation_a),
                ],
                &identity(&[operation_a, operation_b]),
            ),
            Err(PushError::BadMsg)
        ));
    }

    #[test]
    fn save_pairing_rejects_more_than_one_cloudkit_batch() {
        let messages = (0..=CLOUDKIT_MAX_OPERATIONS_PER_REQUEST)
            .map(|index| {
                let operation_uuid = Uuid::new_v4().to_string().to_uppercase();
                input(
                    &format!("local-operation-{index}"),
                    &format!("server-record-{index}"),
                    &operation_uuid,
                )
            })
            .collect::<Vec<_>>();
        let operation_uuids = messages
            .iter()
            .map(|input| input.apple_operation_uuid.clone())
            .collect::<Vec<_>>();
        let request_identity = CloudKitRequestIdentity::new(
            "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA".to_string(),
            operation_uuids,
        )
        .unwrap();

        assert!(matches!(
            ordered_message_save_pairs(&messages, &request_identity),
            Err(PushError::BadMsg)
        ));
    }

    #[test]
    fn save_mode_is_explicitly_create_only() {
        assert!(!CloudMessagesSaveMode::CreateOnly.update_flag());
    }

    #[test]
    fn save_outcomes_follow_request_index_and_reject_mismatches() {
        let operation_a = "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB".to_string();
        let operation_b = "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC".to_string();
        let response = CloudKitBatchResponse {
            request_identity: identity(&[operation_a.as_str(), operation_b.as_str()]),
            outcomes: vec![
                CloudKitOperationOutcome {
                    request_index: 1,
                    operation_uuid: operation_b.clone(),
                    result: Ok(None),
                    retry_after: None,
                    failure_class: None,
                },
                CloudKitOperationOutcome {
                    request_index: 0,
                    operation_uuid: operation_a.clone(),
                    result: Err(PushError::BadMsg),
                    retry_after: Some(Duration::from_secs(3)),
                    failure_class: Some(CloudKitFailureClass::TransientServer),
                },
            ],
        };

        let outcomes = redacted_batch_response_outcomes(
            vec!["local-a".to_string(), "local-b".to_string()],
            &identity(&[operation_a.as_str(), operation_b.as_str()]),
            response,
        )
        .unwrap();
        assert_eq!(outcomes[0].local_operation_id, "local-a");
        assert_eq!(outcomes[0].apple_operation_uuid, operation_a);
        assert!(matches!(
            outcomes[0].result,
            CloudMessagesSaveResult::Failed {
                scope: CloudMessagesSaveFailureScope::Operation,
                failure_class: Some(CloudKitFailureClass::TransientServer),
                retry_after: Some(_),
            }
        ));
        assert_eq!(outcomes[1].local_operation_id, "local-b");
        assert!(matches!(
            outcomes[1].result,
            CloudMessagesSaveResult::Succeeded
        ));

        let mismatched = CloudKitBatchResponse {
            request_identity: identity(&["BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"]),
            outcomes: vec![],
        };
        assert!(matches!(
            redacted_batch_response_outcomes(
                vec!["local-a".to_string()],
                &identity(&["BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"]),
                mismatched,
            ),
            Err(CloudMessagesSaveConsumeError::CorrelationMismatch)
        ));

        let wrong_request_identity = CloudKitBatchResponse {
            request_identity: identity_with_http(
                "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD",
                &["BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"],
            ),
            outcomes: vec![CloudKitOperationOutcome {
                request_index: 0,
                operation_uuid: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB".to_string(),
                result: Ok(None),
                retry_after: None,
                failure_class: None,
            }],
        };
        assert!(matches!(
            redacted_batch_response_outcomes(
                vec!["local-a".to_string()],
                &identity(&["BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"]),
                wrong_request_identity,
            ),
            Err(CloudMessagesSaveConsumeError::CorrelationMismatch)
        ));
    }

    #[test]
    fn unclassified_operation_failure_requires_reconciliation() {
        let operation_uuid = "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB";
        for failure_class in [None, Some(CloudKitFailureClass::Unknown)] {
            let response = CloudKitBatchResponse {
                request_identity: identity(&[operation_uuid]),
                outcomes: vec![CloudKitOperationOutcome {
                    request_index: 0,
                    operation_uuid: operation_uuid.to_owned(),
                    result: Err(PushError::BadMsg),
                    retry_after: None,
                    failure_class,
                }],
            };
            let outcomes = redacted_batch_response_outcomes(
                vec!["local-a".to_owned()],
                &identity(&[operation_uuid]),
                response,
            )
            .expect("unclassified response should retain correlation");
            assert!(matches!(
                outcomes[0].result,
                CloudMessagesSaveResult::UnknownOutcome { .. }
            ));
        }
    }

    #[test]
    fn request_failure_requires_the_exact_persisted_identity() {
        let expected = identity(&["BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"]);
        for request_identity in [
            None,
            Some(identity_with_http(
                "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD",
                &["BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"],
            )),
        ] {
            let failure = CloudKitRequestFailure {
                error: PushError::BadMsg,
                retry_after: None,
                failure_class: Some(CloudKitFailureClass::Unknown),
                request_identity,
                outcome_may_be_committed: false,
            };
            assert!(matches!(
                redacted_request_failure_outcomes(vec!["local-a".to_string()], &expected, failure,),
                Err(CloudMessagesSaveConsumeError::CorrelationMismatch)
            ));
        }
    }

    #[test]
    fn request_failure_preserves_unknown_outcome_after_submission_boundary() {
        let expected = identity(&["BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"]);
        let unknown = redacted_request_failure_outcomes(
            vec!["local-a".to_string()],
            &expected,
            CloudKitRequestFailure {
                error: PushError::BadMsg,
                retry_after: None,
                failure_class: Some(CloudKitFailureClass::Unknown),
                request_identity: Some(expected.clone()),
                outcome_may_be_committed: true,
            },
        )
        .unwrap();
        assert!(matches!(
            unknown[0].result,
            CloudMessagesSaveResult::UnknownOutcome { .. }
        ));

        let pre_submission = redacted_request_failure_outcomes(
            vec!["local-a".to_string()],
            &expected,
            CloudKitRequestFailure {
                error: PushError::BadMsg,
                retry_after: None,
                failure_class: Some(CloudKitFailureClass::Permanent),
                request_identity: Some(expected.clone()),
                outcome_may_be_committed: false,
            },
        )
        .unwrap();
        assert!(matches!(
            pre_submission[0].result,
            CloudMessagesSaveResult::Failed {
                scope: CloudMessagesSaveFailureScope::Request,
                ..
            }
        ));
    }
}

pub struct CloudMessagesClient<P: AnisetteProvider> {
    pub container: Mutex<Option<Arc<CloudKitOpenContainer<'static, P>>>>,
    container_initialization: Mutex<()>,
    read_authentication_container: Mutex<Option<Arc<CloudKitOpenContainer<'static, P>>>>,
    read_authentication_container_initialization: Mutex<()>,
    pub client: Arc<CloudKitClient<P>>,
    pub keychain: Arc<KeychainClient<P>>,
}

impl<P: AnisetteProvider> CloudMessagesClient<P> {
    async fn clear_general_container_if_same(
        &self,
        stale: &Arc<CloudKitOpenContainer<'static, P>>,
    ) {
        let mut cached = self.container.lock().await;
        if cached
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, stale))
        {
            *cached = None;
        }
    }

    async fn clear_read_authentication_container_if_same(
        &self,
        stale: &Arc<CloudKitOpenContainer<'static, P>>,
    ) {
        let mut cached = self.read_authentication_container.lock().await;
        if cached
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, stale))
        {
            *cached = None;
        }
    }

    pub fn new(client: Arc<CloudKitClient<P>>, keychain: Arc<KeychainClient<P>>) -> Self {
        Self {
            container: Mutex::new(None),
            container_initialization: Mutex::new(()),
            read_authentication_container: Mutex::new(None),
            read_authentication_container_initialization: Mutex::new(()),
            client,
            keychain,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_warm_for_test(
        client: Arc<CloudKitClient<P>>,
        keychain: Arc<KeychainClient<P>>,
        container: Arc<CloudKitOpenContainer<'static, P>>,
    ) -> Self {
        Self {
            container: Mutex::new(None),
            container_initialization: Mutex::new(()),
            read_authentication_container: Mutex::new(Some(container)),
            read_authentication_container_initialization: Mutex::new(()),
            client,
            keychain,
        }
    }

    /// Returns the persisted CloudKit and keychain account identifiers only
    /// after their native client composition has been validated.
    ///
    /// This restore-time path is cached and network-free. It deliberately does
    /// not require GSA SPD metadata because that metadata is populated only by
    /// an explicit authentication refresh after process restart. The returned
    /// identifiers are for native Rust use only and must never cross FFI.
    pub async fn validated_persisted_native_account_identifiers(
        &self,
    ) -> Result<(String, String), PushError> {
        let composition_is_exact = Arc::ptr_eq(&self.keychain.client, &self.client)
            && Arc::ptr_eq(&self.keychain.token_provider, &self.client.token_provider)
            && Arc::ptr_eq(&self.keychain.anisette, &self.client.anisette)
            && Arc::ptr_eq(&self.keychain.config, &self.client.config);
        if !composition_is_exact {
            return Err(PushError::UnauthorizedAccountError);
        }

        let cloudkit_dsid = self
            .client
            .state
            .read()
            .await
            .account_identifier()
            .to_owned();
        let (keychain_dsid, keychain_adsid) = {
            let state = self.keychain.state.read().await;
            let (dsid, adsid) = state.native_account_identifiers();
            (dsid.to_owned(), adsid.to_owned())
        };

        if cloudkit_dsid.is_empty()
            || keychain_dsid.is_empty()
            || keychain_adsid.is_empty()
            || cloudkit_dsid != keychain_dsid
        {
            return Err(PushError::UnauthorizedAccountError);
        }

        Ok((cloudkit_dsid, keychain_adsid))
    }

    /// Returns the CloudKit DSID only after the complete native account
    /// composition, including the current GSA SPD, has been validated.
    ///
    /// This path is cached and network-free. A caller restoring a cold process
    /// must explicitly refresh authentication before invoking it. The returned
    /// identifier is for native Rust use only.
    pub async fn validated_native_account_identifier(&self) -> Result<String, PushError> {
        let (persisted_dsid, persisted_adsid) = self
            .validated_persisted_native_account_identifiers()
            .await?;
        let (gsa_dsid, gsa_adsid) = self
            .client
            .token_provider
            .get_gsa_account_identifiers_cached()
            .await?;

        if gsa_dsid != persisted_dsid || gsa_adsid != persisted_adsid {
            return Err(PushError::UnauthorizedAccountError);
        }

        Ok(persisted_dsid)
    }

    pub async fn get_container(&self) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let cached = self.container.lock().await.as_ref().cloned();
        if let Some(container) = cached {
            if container
                .validate_general_identity(
                    &self.client,
                    CloudKitReadAuthenticationContainer::Messages,
                )
                .await
                .is_ok()
            {
                return Ok(container);
            }
            self.clear_general_container_if_same(&container).await;
        }
        let _initialization = self.container_initialization.lock().await;
        let cached = self.container.lock().await.as_ref().cloned();
        if let Some(container) = cached {
            if container
                .validate_general_identity(
                    &self.client,
                    CloudKitReadAuthenticationContainer::Messages,
                )
                .await
                .is_ok()
            {
                return Ok(container);
            }
            self.clear_general_container_if_same(&container).await;
        }
        let container = Arc::new(MESSAGES_CONTAINER.init(self.client.clone()).await?);
        container
            .validate_general_identity(&self.client, CloudKitReadAuthenticationContainer::Messages)
            .await?;
        *self.container.lock().await = Some(container.clone());
        Ok(container)
    }

    /// Opens only the Messages container under the exact writer-pause permit
    /// supplied by the Cloud Sync V2 read-authentication bridge. The permit is
    /// validated even when the container is already cached.
    pub async fn get_container_for_read_authentication(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
    ) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        permit.validate()?;
        let cached = self
            .read_authentication_container
            .lock()
            .await
            .as_ref()
            .cloned();
        if let Some(container) = cached {
            if container
                .validate_read_authentication_identity(
                    &self.client,
                    CloudKitReadAuthenticationContainer::Messages,
                )
                .await
                .is_ok()
            {
                return Ok(container);
            }
            self.clear_read_authentication_container_if_same(&container)
                .await;
        }
        let _initialization = self
            .read_authentication_container_initialization
            .lock()
            .await;
        permit.validate()?;
        let cached = self
            .read_authentication_container
            .lock()
            .await
            .as_ref()
            .cloned();
        if let Some(container) = cached {
            if container
                .validate_read_authentication_identity(
                    &self.client,
                    CloudKitReadAuthenticationContainer::Messages,
                )
                .await
                .is_ok()
            {
                return Ok(container);
            }
            self.clear_read_authentication_container_if_same(&container)
                .await;
        }
        let container = Arc::new(
            MESSAGES_CONTAINER
                .init_for_read_authentication(
                    self.client.clone(),
                    permit,
                    CloudKitReadAuthenticationContainer::Messages,
                )
                .await?,
        );
        *self.read_authentication_container.lock().await = Some(container.clone());
        Ok(container)
    }

    /// Returns only the already-warmed Messages container while the exact
    /// read-authentication permit remains valid. This accessor never enters
    /// container initialization, authentication refresh, or ckAppInit.
    pub async fn get_cached_container_for_read_authentication(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
    ) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        permit.validate()?;
        let container = self.get_read_authentication_container_lookup_only().await?;
        permit.validate()?;
        container
            .validate_read_authentication_identity(
                &self.client,
                CloudKitReadAuthenticationContainer::Messages,
            )
            .await?;
        permit.validate()?;
        Ok(container)
    }

    /// Returns only a general container that has already been initialized by
    /// the legacy/write-capable authentication path. Write preparation must
    /// never consume a container initialized under restored read auth.
    pub async fn get_container_lookup_only(
        &self,
    ) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let container = self
            .container
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or(PushError::CloudKitWarmAuthenticationRequired)?;
        container
            .validate_general_identity(&self.client, CloudKitReadAuthenticationContainer::Messages)
            .await?;
        Ok(container)
    }

    async fn get_writer_container_for_binding(
        &self,
        binding: &CloudMessagesWriterPreparationBinding<P>,
    ) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let current = self.get_container_lookup_only().await?;
        if !Arc::ptr_eq(&current, &binding.container) || current.user_id.is_empty() {
            return Err(PushError::UnauthorizedAccountError);
        }
        Ok(current)
    }

    /// Revalidates that a retained preparation binding still owns the exact
    /// cached writer container. Callers must check this immediately before and
    /// after crossing the remote submission boundary.
    pub async fn validate_writer_preparation_binding(
        &self,
        binding: &CloudMessagesWriterPreparationBinding<P>,
    ) -> Result<(), PushError> {
        self.get_writer_container_for_binding(binding).await?;
        Ok(())
    }

    /// Warms the exact general Messages container and existing message-zone
    /// PCS configuration needed before create-only writer admission.
    ///
    /// This preflight may initialize CloudKit authentication, but its zone and
    /// keychain operations are lookup-only. A missing zone fails instead of
    /// being created, and the container-scoped user ID never leaves native
    /// Rust.
    pub async fn warm_message_writer_preparation_lookup_only(
        &self,
    ) -> Result<CloudMessagesWriterPreparationBinding<P>, PushError> {
        let container = self.get_container().await?;
        let zone = container.private_zone("messageManateeZone".to_string());
        container
            .get_zone_encryption_config_lookup_only(&zone, &self.keychain, &MESSAGES_SERVICE)
            .await?;
        container
            .validate_general_identity(&self.client, CloudKitReadAuthenticationContainer::Messages)
            .await?;
        if container.user_id.is_empty() {
            return Err(PushError::UnauthorizedAccountError);
        }
        Ok(CloudMessagesWriterPreparationBinding { container })
    }

    /// Returns only a container initialized under the restored read-auth
    /// lease. Semantic fetch and decode must not fall back to a general or
    /// write-capable container cache.
    async fn get_read_authentication_container_lookup_only(
        &self,
    ) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let container = self
            .read_authentication_container
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or(PushError::CloudKitWarmAuthenticationRequired)?;
        container
            .validate_read_authentication_identity(
                &self.client,
                CloudKitReadAuthenticationContainer::Messages,
            )
            .await?;
        Ok(container)
    }

    /// Warms the exact Messages PCS zones needed by the semantic reader while
    /// the caller's native writer-pause permit remains active. Every remote
    /// operation is lookup-only: missing zones fail instead of being created,
    /// and the resulting PCS configurations stay on the restored read-auth
    /// container rather than the general/write-capable container.
    pub async fn warm_semantic_read_zone_encryption_configs(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
    ) -> Result<(), PushError> {
        const SEMANTIC_ZONES: [&str; 3] = [
            "chatManateeZone",
            "messageManateeZone",
            "attachmentManateeZone",
        ];

        permit.validate()?;
        let container = self
            .get_cached_container_for_read_authentication(permit)
            .await?;
        let zones = SEMANTIC_ZONES
            .iter()
            .map(|name| (container.private_zone((*name).to_owned()), None))
            .collect::<Vec<_>>();
        let configs = container
            .get_zone_encryption_config_sev_lookup_only(
                &zones,
                &self.keychain,
                &MESSAGES_SERVICE,
                true,
            )
            .await?;
        if configs.len() != zones.len() {
            return Err(PushError::BadMsg);
        }
        for config in configs {
            permit.validate()?;
            config?;
        }
        permit.validate()
    }

    /// Fetches one stable MessageEncryptedV3 record for ambiguous-write
    /// reconciliation. The read-only CloudKit primitive may retry safely, but
    /// only an explicit per-record NOT_FOUND is evidence that create replay is
    /// safe. Every other failure remains unresolved. Container and PCS state
    /// must already be warm; reconciliation never initializes CloudKit,
    /// creates a zone, or mutates Cuttlefish trust.
    pub async fn lookup_message_record(
        &self,
        writer_binding: &CloudMessagesWriterPreparationBinding<P>,
        server_record_name: &str,
    ) -> Result<CloudMessageRecordLookup, PushError> {
        if server_record_name.is_empty() || server_record_name.len() > 4096 {
            return Err(PushError::BadMsg);
        }
        let container = self
            .get_writer_container_for_binding(writer_binding)
            .await?;
        let zone = container.private_zone("messageManateeZone".to_string());
        let key = container
            .get_cached_zone_encryption_config_exact(&zone)
            .await?;
        let expected_record_identifier = record_identifier(zone, server_record_name);
        let operations = [FetchRecordOperation::new(
            &NO_ASSETS,
            expected_record_identifier.clone(),
        )];
        let response = container
            .perform_operations_detailed(
                &CloudKitSession::new(),
                &operations,
                IsolationLevel::Operation,
            )
            .await;
        self.get_writer_container_for_binding(writer_binding)
            .await?;
        let response = match response {
            Ok(response) => response,
            Err(failure) => {
                return Ok(CloudMessageRecordLookup::Unresolved {
                    failure_class: failure.failure_class,
                    retry_after: failure.retry_after,
                })
            }
        };
        if response.outcomes.len() != 1 {
            return Ok(CloudMessageRecordLookup::Unresolved {
                failure_class: Some(CloudKitFailureClass::Unknown),
                retry_after: None,
            });
        }
        let outcome = response
            .outcomes
            .into_iter()
            .next()
            .ok_or(PushError::BadMsg)?;
        match outcome.result {
            Ok(record) => {
                record.verify_identifier(&expected_record_identifier)?;
                Ok(CloudMessageRecordLookup::Found(
                    record.get_record(Some(&key))?,
                ))
            }
            Err(error) if is_cloudkit_record_not_found(&error) => {
                Ok(CloudMessageRecordLookup::NotFound)
            }
            Err(_) => Ok(CloudMessageRecordLookup::Unresolved {
                failure_class: outcome.failure_class,
                retry_after: outcome.retry_after,
            }),
        }
    }

    /// Prepares one message-only, CREATE-ONLY save batch while all
    /// authentication and PCS work is still outside the remote-submission
    /// ambiguity boundary. Existing mapped-record updates are unsupported
    /// until predecessor ETag binding is fixture-proven and durably persisted.
    ///
    /// Container and PCS state must already be warm. Preparation may refresh
    /// the submission authentication token, but it never initializes a
    /// CloudKit container, creates a zone, or mutates Cuttlefish trust.
    ///
    /// `messages` is deliberately an ordered vector instead of a map. Its
    /// local operation IDs, server record names, message payloads, and the
    /// caller's persisted operation UUIDs are paired by position. Only local
    /// operation IDs are retained for correlation after the native save
    /// operation is built.
    pub async fn prepare_message_save_submission(
        &self,
        writer_binding: &CloudMessagesWriterPreparationBinding<P>,
        messages: Vec<CloudMessageSaveInput>,
        request_identity: CloudKitRequestIdentity,
        request_timeout: Duration,
    ) -> Result<CloudMessagesPreparedSaveSubmission<P>, PushError> {
        with_cloudkit_writer_operation(async move {
            if request_timeout.is_zero() || request_timeout > Duration::from_secs(5 * 60) {
                return Err(PushError::BadMsg);
            }
            let ordered_pairs = ordered_message_save_pairs(&messages, &request_identity)?;
            let container = self
                .get_writer_container_for_binding(writer_binding)
                .await?;
            let zone = container.private_zone("messageManateeZone".to_string());
            let key = container
                .get_cached_zone_encryption_config_exact(&zone)
                .await?;

            let mut operations = Vec::with_capacity(messages.len());
            let mut local_operation_ids = Vec::with_capacity(messages.len());
            for (input, (paired_local_operation_id, _)) in
                messages.into_iter().zip(ordered_pairs.iter())
            {
                debug_assert_eq!(&input.local_operation_id, paired_local_operation_id);
                operations.push(SaveRecordOperation::try_new(
                    record_identifier(zone.clone(), &input.server_record_name),
                    input.message,
                    Some(&key),
                    CloudMessagesSaveMode::CreateOnly.update_flag(),
                )?);
                local_operation_ids.push(input.local_operation_id);
            }

            let prepared_authentication = container.prepare_operations_authentication().await?;
            self.get_writer_container_for_binding(writer_binding)
                .await?;

            Ok(CloudMessagesPreparedSaveSubmission {
                container,
                session: CloudKitSession::new(),
                request_identity,
                prepared_authentication,
                operations,
                local_operation_ids,
                retry_policy: CloudKitRetryPolicy {
                    max_attempts: 1,
                    request_timeout,
                    ..CloudKitRetryPolicy::default()
                },
            })
        })
        .await
    }

    async fn sync_records_page(
        &self,
        zone_name: &str,
        expected_record_type: &str,
        continuation_token: Option<Vec<u8>>,
        max_changes: u32,
    ) -> Result<CloudMessageRecordPage, PushError> {
        let container = self.get_read_authentication_container_lookup_only().await?;
        self.sync_records_page_with_container(
            &container,
            zone_name,
            expected_record_type,
            continuation_token,
            max_changes,
        )
        .await
    }

    async fn sync_records_page_for_read_authentication(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
        zone_name: &str,
        expected_record_type: &str,
        continuation_token: Option<Vec<u8>>,
        max_changes: u32,
    ) -> Result<CloudMessageRecordPage, PushError> {
        permit.validate()?;
        let container = self
            .get_cached_container_for_read_authentication(permit)
            .await?;
        permit.validate()?;
        let result = self
            .sync_records_page_with_container(
                &container,
                zone_name,
                expected_record_type,
                continuation_token,
                max_changes,
            )
            .await;
        permit.validate()?;
        result
    }

    async fn sync_records_page_with_container(
        &self,
        container: &Arc<CloudKitOpenContainer<'static, P>>,
        zone_name: &str,
        expected_record_type: &str,
        continuation_token: Option<Vec<u8>>,
        max_changes: u32,
    ) -> Result<CloudMessageRecordPage, PushError> {
        let zone = container.private_zone(zone_name.to_string());
        let page = FetchRecordChangesOperation::fetch_page_with_limit_lookup_only(
            container,
            zone,
            continuation_token,
            &NO_ASSETS,
            max_changes,
        )
        .await?;

        let changes = map_ordered_page_changes(page.changes, expected_record_type);

        Ok(CloudMessageRecordPage {
            changes,
            next_token: page.next_token,
            status: page.status,
        })
    }

    async fn sync_records<T: CloudKitRecord>(
        &self,
        zone: &str,
        continuation_token: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, HashMap<String, Option<T>>, i32), PushError> {
        legacy_cloudkit_page_with_deadline(
            LEGACY_CLOUDKIT_PAGE_TIMEOUT,
            self.sync_records_without_deadline(zone, continuation_token),
        )
        .await
    }

    async fn sync_records_without_deadline<T: CloudKitRecord>(
        &self,
        zone: &str,
        continuation_token: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, HashMap<String, Option<T>>, i32), PushError> {
        info!("Getting records");
        let container = self.get_container().await?;

        let zone = container.private_zone(zone.to_string());
        info!("Getting encryption config");
        let key = container
            .get_zone_encryption_config(&zone, &self.keychain, &MESSAGES_SERVICE)
            .await?;
        info!("Got encryption config");
        let (_assets, response) = container
            .perform(
                &CloudKitSession::new(),
                FetchRecordChangesOperation(cloudkit_proto::RetrieveChangesRequest {
                    sync_continuation_token: continuation_token,
                    zone_identifier: Some(zone.clone()),
                    requested_changes_types: Some(3), // figure out
                    assets_to_download: Some(NO_ASSETS.clone()),
                    newest_first: Some(true),
                    ..Default::default()
                }),
            )
            .await?;

        let mut results = HashMap::new();

        info!("Getting response");

        for change in &response.change {
            let identifier = change
                .identifier
                .as_ref()
                .unwrap()
                .value
                .as_ref()
                .unwrap()
                .name()
                .to_string();

            let Some(record) = &change.record else {
                results.insert(identifier, None);
                continue;
            };
            if record.r#type.as_ref().unwrap().name() != T::record_type() {
                continue;
            }

            let pcskey = match pcs_keys_for_record(&record, &key) {
                Ok(key) => key,
                Err(PushError::PCSRecordKeyMissing) => {
                    container.clear_cache_zone_encryption_config(&zone).await;
                    return Err(PushError::PCSRecordKeyMissing);
                }
                Err(e) => return Err(e),
            };
            let item = T::from_record_encrypted(&record.record_field, Some(&pcskey));

            results.insert(identifier, Some(item));
        }

        info!("Getting finish");

        Ok((
            response.sync_continuation_token().to_vec(),
            results,
            response.status(),
        ))
    }

    async fn save_records<T: CloudKitRecord>(
        &self,
        zone: &str,
        records: HashMap<String, T>,
    ) -> Result<HashMap<String, Result<(), PushError>>, PushError> {
        with_cloudkit_writer_operation(async move {
            let container = self.get_container().await?;

            let zone = container.private_zone(zone.to_string());
            let key = container
                .get_zone_encryption_config(&zone, &self.keychain, &MESSAGES_SERVICE)
                .await?;

            let mut results = HashMap::new();
            let records = records.into_iter().collect::<Vec<_>>();

            for batch in records.chunks(256) {
                let mut operations = vec![];
                let mut ids = vec![];
                for (record_id, chat) in batch {
                    operations.push(SaveRecordOperation::try_new(
                        record_identifier(zone.clone(), &record_id),
                        chat,
                        Some(&key),
                        true,
                    )?);
                    ids.push(record_id.clone());
                }

                let mut result: HashMap<usize, Result<(), PushError>> = match container
                    .perform_operations(
                        &CloudKitSession::new(),
                        &operations,
                        IsolationLevel::Operation,
                    )
                    .await
                {
                    Ok(item) => item
                        .into_iter()
                        .map(|i| i.map(|_| ()))
                        .enumerate()
                        .collect(),
                    Err(e) => {
                        let joined = Arc::new(e);
                        results.extend(
                            ids.into_iter()
                                .map(|r| (r, Err(PushError::BatchError(joined.clone())))),
                        );
                        continue;
                    }
                };

                results.extend(
                    ids.into_iter()
                        .enumerate()
                        .map(|(idx, r)| (r, result.remove(&idx).unwrap())),
                );
            }

            Ok(results)
        })
        .await
    }

    async fn delete_records(&self, zone: &str, records: &[String]) -> Result<(), PushError> {
        with_cloudkit_writer_operation(async move {
            let container = self.get_container().await?;

            let zone = container.private_zone(zone.to_string());

            for batch in records.chunks(256) {
                let mut operations = vec![];
                for record_id in batch {
                    operations.push(DeleteRecordOperation::new(record_identifier(
                        zone.clone(),
                        record_id,
                    )));
                }
                (|| async {
                    container
                        .perform_operations_checked(
                            &CloudKitSession::new(),
                            &operations,
                            IsolationLevel::Operation,
                        )
                        .await
                })
                .retry(
                    &ConstantBuilder::default()
                        .with_delay(Duration::from_secs(5))
                        .with_max_times(3),
                )
                .await?;
            }

            Ok(())
        })
        .await
    }

    async fn count_zone_records(&self, zone: &str) -> Result<CloudMessageSummary, PushError> {
        let container = self.get_container().await?;

        let zone = container.private_zone(zone.to_string());

        let session = CloudKitSession::new();
        let (mut results, _assets) = container
            .perform(
                &session,
                QueryRecordOperation::new(
                    &ALL_ASSETS,
                    zone,
                    cloudkit_proto::Query {
                        types: vec![crate::cloudkit_proto::record::Type {
                            name: Some("MessagesSummary".to_string()),
                        }],
                        filters: vec![],
                        sorts: vec![],
                        distinct: None,
                        query_operator: None,
                    },
                ),
            )
            .await?;

        Ok(if !results.is_empty() {
            results.remove(0).result
        } else {
            Default::default()
        })
    }

    pub async fn count_records(&self) -> Result<CloudMessageSummary, PushError> {
        let mut def = CloudMessageSummary::default();
        for zone in [
            "chatManateeZone",
            "messageManateeZone",
            "attachmentManateeZone",
        ] {
            def = def.merge(self.count_zone_records(zone).await?);
        }
        Ok(def)
    }

    pub async fn reset(&self) -> Result<(), PushError> {
        with_cloudkit_writer_operation(async move {
            let container = self.get_container().await?;

            container.keys.lock().await.clear();

            container
                .perform_operations_checked(
                    &CloudKitSession::new(),
                    &[
                        ZoneDeleteOperation::new(
                            container.private_zone("chatManateeZone".to_string()),
                        ),
                        ZoneDeleteOperation::new(
                            container.private_zone("messageManateeZone".to_string()),
                        ),
                        ZoneDeleteOperation::new(
                            container.private_zone("attachmentManateeZone".to_string()),
                        ),
                        ZoneDeleteOperation::new(
                            container.private_zone("chat1ManateeZone".to_string()),
                        ),
                        ZoneDeleteOperation::new(
                            container.private_zone("messageUpdateZone".to_string()),
                        ),
                        ZoneDeleteOperation::new(
                            container.private_zone("recoverableMessageDeleteZone".to_string()),
                        ),
                        ZoneDeleteOperation::new(
                            container.private_zone("scheduledMessageZone".to_string()),
                        ),
                        ZoneDeleteOperation::new(
                            container.private_zone("chatBotMessageZone".to_string()),
                        ),
                        ZoneDeleteOperation::new(
                            container.private_zone("chatBotAttachmentZone".to_string()),
                        ),
                        ZoneDeleteOperation::new(
                            container
                                .private_zone("chatBotRecoverableMessageDeleteZone".to_string()),
                        ),
                    ],
                    IsolationLevel::Operation,
                )
                .await?;
            Ok(())
        })
        .await
    }

    pub async fn sync_chats(
        &self,
        continuation_token: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, HashMap<String, Option<CloudChat>>, i32), PushError> {
        self.sync_records("chatManateeZone", continuation_token)
            .await
    }

    pub async fn sync_chats_page(
        &self,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_records_page(
            "chatManateeZone",
            CloudChat::record_type(),
            continuation_token,
            max_changes.unwrap_or(CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE),
        )
        .await
    }

    pub async fn sync_chats_page_for_read_authentication(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_records_page_for_read_authentication(
            permit,
            "chatManateeZone",
            CloudChat::record_type(),
            continuation_token,
            max_changes.unwrap_or(CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE),
        )
        .await
    }

    pub async fn save_chats(
        &self,
        chats: HashMap<String, CloudChat>,
    ) -> Result<HashMap<String, Result<(), PushError>>, PushError> {
        self.save_records("chatManateeZone", chats).await
    }

    pub async fn delete_chats(&self, chats: &[String]) -> Result<(), PushError> {
        self.delete_records("chatManateeZone", chats).await
    }

    pub async fn sync_messages(
        &self,
        continuation_token: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, HashMap<String, Option<CloudMessage>>, i32), PushError> {
        self.sync_records("messageManateeZone", continuation_token)
            .await
    }

    pub async fn sync_messages_page(
        &self,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_records_page(
            "messageManateeZone",
            CloudMessage::record_type(),
            continuation_token,
            max_changes.unwrap_or(CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE),
        )
        .await
    }

    pub async fn sync_messages_page_for_read_authentication(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_records_page_for_read_authentication(
            permit,
            "messageManateeZone",
            CloudMessage::record_type(),
            continuation_token,
            max_changes.unwrap_or(CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE),
        )
        .await
    }

    pub async fn save_messages(
        &self,
        messages: HashMap<String, CloudMessage>,
    ) -> Result<HashMap<String, Result<(), PushError>>, PushError> {
        self.save_records("messageManateeZone", messages).await
    }

    pub async fn delete_messages(&self, messages: &[String]) -> Result<(), PushError> {
        self.delete_records("messageManateeZone", messages).await
    }

    pub async fn sync_attachments(
        &self,
        continuation_token: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, HashMap<String, Option<CloudAttachment>>, i32), PushError> {
        self.sync_records("attachmentManateeZone", continuation_token)
            .await
    }

    pub async fn sync_attachments_page(
        &self,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_records_page(
            "attachmentManateeZone",
            CloudAttachment::record_type(),
            continuation_token,
            max_changes.unwrap_or(CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE),
        )
        .await
    }

    pub async fn sync_attachments_page_for_read_authentication(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_records_page_for_read_authentication(
            permit,
            "attachmentManateeZone",
            CloudAttachment::record_type(),
            continuation_token,
            max_changes.unwrap_or(CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE),
        )
        .await
    }

    async fn sync_raw_only_records_page(
        &self,
        zone: &str,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_records_page(
            zone,
            RAW_ONLY_RECORD_TYPE,
            continuation_token,
            max_changes.unwrap_or(CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE),
        )
        .await
    }

    pub async fn sync_message_update_page(
        &self,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_raw_only_records_page("messageUpdateZone", continuation_token, max_changes)
            .await
    }

    pub async fn sync_recoverable_message_delete_page(
        &self,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_raw_only_records_page(
            "recoverableMessageDeleteZone",
            continuation_token,
            max_changes,
        )
        .await
    }

    pub async fn sync_scheduled_message_page(
        &self,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_raw_only_records_page("scheduledMessageZone", continuation_token, max_changes)
            .await
    }

    pub async fn sync_chat1_page(
        &self,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<u32>,
    ) -> Result<CloudMessageRecordPage, PushError> {
        self.sync_raw_only_records_page("chat1ManateeZone", continuation_token, max_changes)
            .await
    }

    pub async fn save_attachments(
        &self,
        attachments: HashMap<String, CloudAttachment>,
    ) -> Result<HashMap<String, Result<(), PushError>>, PushError> {
        self.save_records("attachmentManateeZone", attachments)
            .await
    }

    pub async fn delete_attachments(&self, attachments: &[String]) -> Result<(), PushError> {
        self.delete_records("attachmentManateeZone", attachments)
            .await
    }

    pub async fn prepare_file<T: Read + Send + Sync>(
        &self,
        file: T,
    ) -> Result<PreparedPut, PushError> {
        Ok(prepare_put_v2(
            FileContainer::new(file),
            &get_boundary_key(&MESSAGES_SERVICE, &self.keychain).await?,
        )
        .await?)
    }

    pub async fn download_attachment<T: Write + Send + Sync>(
        &self,
        files: HashMap<String, T>,
    ) -> Result<(), PushError> {
        let container = self.get_container().await?;
        let zone = container.private_zone("attachmentManateeZone".to_string());
        let key = container
            .get_zone_encryption_config(&zone, &self.keychain, &MESSAGES_SERVICE)
            .await?;

        let invoke = container
            .perform_operations(
                &CloudKitSession::new(),
                &FetchRecordOperation::many(
                    &ALL_ASSETS,
                    &zone,
                    &files.keys().cloned().collect::<Vec<_>>(),
                ),
                IsolationLevel::Operation,
            )
            .await?;
        let records = FetchedRecords::new(&invoke);

        let record: Vec<CloudAttachment> = files
            .keys()
            .map(|record_id| {
                records.get_record_exact(&record_identifier(zone.clone(), record_id), Some(&key))
            })
            .collect::<Result<Vec<_>, _>>()?;

        container
            .get_assets(
                &records.assets,
                record
                    .iter()
                    .map(|i| &i.lqa)
                    .zip(files.into_values())
                    .collect::<Vec<_>>(),
            )
            .await?;
        Ok(())
    }

    /// Downloads one attachment under an already-active Cloud Sync writer
    /// pause, only when the fetched record still has the non-empty etag from
    /// the protected source. The closed semantic transport admits only the
    /// concrete record GET; container, PCS, save, delete, zone-create, and
    /// subscription mutation paths are unavailable here.
    pub async fn download_attachment_checked_lookup_only<T: Write + Send + Sync>(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
        expected_native_account_identifier: &str,
        record_id: String,
        expected_record_etag: String,
        file: T,
    ) -> Result<(), PushError> {
        if expected_native_account_identifier.is_empty() || expected_record_etag.is_empty() {
            return Err(PushError::VerificationFailed);
        }
        permit.validate()?;
        if self.validated_native_account_identifier().await? != expected_native_account_identifier {
            return Err(PushError::UnauthorizedAccountError);
        }
        let container = self
            .get_cached_container_for_read_authentication(permit)
            .await?;
        let zone = container.private_zone("attachmentManateeZone".to_string());
        let expected_record_identifier = record_identifier(zone.clone(), &record_id);
        let key = container
            .get_cached_zone_encryption_config_exact(&zone)
            .await?;

        // Revalidate the non-cloneable pause and exact native account as close
        // as possible to the first remote read.
        permit.validate()?;
        if self.validated_native_account_identifier().await? != expected_native_account_identifier {
            return Err(PushError::UnauthorizedAccountError);
        }
        let invoke = container
            .perform_semantic_read_only_operations(
                &CloudKitSession::new(),
                &[FetchRecordOperation::new(
                    &ALL_ASSETS,
                    expected_record_identifier.clone(),
                )],
                IsolationLevel::Operation,
            )
            .await?;
        if invoke.len() != 1 {
            return Err(PushError::BadMsg);
        }
        let fetched = invoke.into_iter().next().ok_or(PushError::BadMsg)??;
        let records = FetchedRecords::new(&[Ok(fetched)]);
        if records.record_etag(&expected_record_identifier)? != expected_record_etag {
            return Err(PushError::VerificationFailed);
        }
        let record: CloudAttachment =
            records.get_record_exact(&expected_record_identifier, Some(&key))?;
        // MMCS is another remote read. Do not let it start after a pause or
        // account transition, and reject a transition before reporting
        // completion to the native cache.
        permit.validate()?;
        if self.validated_native_account_identifier().await? != expected_native_account_identifier {
            return Err(PushError::UnauthorizedAccountError);
        }
        container
            .get_assets_download_only(&records.assets, vec![(&record.lqa, file)])
            .await?;
        permit.validate()?;
        if self.validated_native_account_identifier().await? != expected_native_account_identifier {
            return Err(PushError::UnauthorizedAccountError);
        }
        Ok(())
    }

    pub async fn download_group_photo<T: Write + Send + Sync>(
        &self,
        files: HashMap<String, T>,
    ) -> Result<(), PushError> {
        let container = self.get_container().await?;
        let zone = container.private_zone("chatManateeZone".to_string());
        let key = container
            .get_zone_encryption_config(&zone, &self.keychain, &MESSAGES_SERVICE)
            .await?;

        let invoke = container
            .perform_operations(
                &CloudKitSession::new(),
                &FetchRecordOperation::many(
                    &ALL_ASSETS,
                    &zone,
                    &files.keys().cloned().collect::<Vec<_>>(),
                ),
                IsolationLevel::Operation,
            )
            .await?;
        let records = FetchedRecords::new(&invoke);
        let record: Vec<CloudChat> = files
            .keys()
            .map(|record_id| {
                records.get_record_exact(&record_identifier(zone.clone(), record_id), Some(&key))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if record.iter().any(|r| r.group_photo.is_none()) {
            return Err(PushError::MissingGroupPhoto);
        }

        container
            .get_assets(
                &records.assets,
                record
                    .iter()
                    .map(|i| i.group_photo.as_ref().expect("No group photo!"))
                    .zip(files.into_values())
                    .collect::<Vec<_>>(),
            )
            .await?;
        Ok(())
    }

    // files is (prepared, file, record_id)
    pub async fn upload_attachments<T: Read + Send + Sync>(
        &self,
        files: Vec<(PreparedPut, T, String)>,
    ) -> Result<Vec<cloudkit_proto::Asset>, PushError> {
        with_cloudkit_writer_operation(async move {
            let container = self.get_container().await?;
            Ok(container
                .upload_asset(
                    &CloudKitSession::new(),
                    &container.private_zone("attachmentManateeZone".to_string()),
                    files
                        .into_iter()
                        .map(|f| CloudKitUploadRequest {
                            file: Some(f.1),
                            record_id: f.2,
                            field: "lqa",
                            record_type: CloudAttachment::record_type(),
                            prepared: f.0,
                        })
                        .collect(),
                )
                .await?
                .remove("lqa")
                .unwrap_or_default())
        })
        .await
    }

    pub async fn upload_group_photo<T: Read + Send + Sync>(
        &self,
        files: Vec<(PreparedPut, T, String)>,
    ) -> Result<Vec<cloudkit_proto::Asset>, PushError> {
        with_cloudkit_writer_operation(async move {
            let container = self.get_container().await?;
            Ok(container
                .upload_asset(
                    &CloudKitSession::new(),
                    &container.private_zone("chatManateeZone".to_string()),
                    files
                        .into_iter()
                        .map(|f| CloudKitUploadRequest {
                            file: Some(f.1),
                            record_id: f.2,
                            field: "gp",
                            record_type: CloudChat::record_type(),
                            prepared: f.0,
                        })
                        .collect(),
                )
                .await?
                .remove("gp")
                .unwrap_or_default())
        })
        .await
    }
}

#[cfg(test)]
mod cloud_message_identity_tests {
    use super::*;
    use crate::{
        cloudkit::{CloudKitClient, CloudKitState},
        cloudkit_operation_gate::{
            acquire_cloudkit_read_authentication, pause_cloudkit_writer_operations,
            resume_cloudkit_writer_operations,
        },
        keychain::{CloudKitContainerCaches, KeychainClient, KeychainClientState},
        DebugMeta, DebugRwLock, OSConfig, RegisterMeta, TokenProvider,
    };
    use icloud_auth::{AppleAccount, LoginClientInfo};
    use omnisette::{AnisetteClient, AnisetteError, ArcAnisetteClient};
    use std::{collections::HashMap, future::Future};

    #[test]
    fn semantic_pcs_warmup_is_permit_bound_and_lookup_only() {
        let source = include_str!("cloud_messages.rs");
        let method_start = source
            .find("pub async fn warm_semantic_read_zone_encryption_configs")
            .expect("semantic PCS warmup method");
        let following_method = source[method_start..]
            .find("pub async fn lookup_message_record")
            .expect("following lookup method");
        let method = &source[method_start..method_start + following_method];

        assert!(method.matches("permit.validate()").count() >= 3);
        assert!(method.contains("get_cached_container_for_read_authentication(permit)"));
        assert!(method.contains("get_zone_encryption_config_sev_lookup_only"));
        assert!(method.contains("chatManateeZone"));
        assert!(method.contains("messageManateeZone"));
        assert!(method.contains("attachmentManateeZone"));
        assert!(!method.contains("get_zone_encryption_config_sev("));
        assert!(!method.contains("get_zone_encryption_config("));
    }

    #[test]
    fn semantic_record_page_fetch_is_permit_bound_and_lookup_only() {
        let source = include_str!("cloud_messages.rs");
        let production_end = source
            .find("mod cloud_message_identity_tests {")
            .expect("identity test module boundary");
        let production_source = &source[..production_end];
        let method_start = source
            .find("async fn sync_records_page_for_read_authentication")
            .expect("permit-bound record-page method");
        let following_method = source[method_start..]
            .find("async fn sync_records_page_with_container")
            .expect("shared lookup-only page helper");
        let method = &source[method_start..method_start + following_method];

        assert!(method.matches("permit.validate()?").count() >= 3);
        assert!(method.contains("get_cached_container_for_read_authentication(permit)"));
        assert!(!method.contains("get_read_authentication_container_lookup_only"));
        for method_name in [
            "sync_chats_page_for_read_authentication",
            "sync_messages_page_for_read_authentication",
            "sync_attachments_page_for_read_authentication",
        ] {
            assert!(
                production_source.contains(method_name),
                "missing {method_name}"
            );
        }
        for forbidden_method in [
            "sync_message_update_page_for_read_authentication",
            "sync_recoverable_message_delete_page_for_read_authentication",
            "sync_scheduled_message_page_for_read_authentication",
            "sync_chat1_page_for_read_authentication",
        ] {
            assert!(
                !production_source.contains(forbidden_method),
                "unexpected semantic fetch surface: {forbidden_method}"
            );
        }
    }

    #[test]
    fn attachment_download_structurally_uses_cached_container_and_pcs_configuration() {
        let source = include_str!("cloud_messages.rs");
        let method_start = source
            .find("pub async fn download_attachment_checked_lookup_only")
            .expect("attachment download method");
        let following_method = source[method_start..]
            .find("pub async fn download_group_photo")
            .expect("following attachment method");
        let method = &source[method_start..method_start + following_method];

        assert!(method.contains(".get_cached_container_for_read_authentication(permit)"));
        assert!(!method.contains("get_container_for_read_authentication(permit)"));
        assert!(method.contains(".get_cached_zone_encryption_config_exact(&zone)"));
        assert!(!method.contains("get_zone_encryption_config_lookup_only"));
    }

    #[test]
    fn write_paths_require_general_container_and_already_cached_pcs_configuration() {
        let source = include_str!("cloud_messages.rs");
        for method_name in [
            "pub async fn lookup_message_record",
            "pub async fn prepare_message_save_submission",
        ] {
            let method_start = source.find(method_name).expect("write-path method");
            let method_body_start = method_start + method_name.len();
            let following_method = source[method_body_start..]
                .find("pub async fn ")
                .map(|offset| method_body_start + offset)
                .unwrap_or(source.len());
            let method = &source[method_start..following_method];

            assert!(method.contains("get_writer_container_for_binding"));
            assert!(method.contains("writer_binding"));
            assert!(method.contains(".get_cached_zone_encryption_config_exact(&zone)"));
            assert!(!method.contains("get_zone_encryption_config_lookup_only"));
            assert!(!method.contains("get_container_for_read_authentication"));
        }
    }

    #[test]
    fn writer_preparation_warms_only_the_existing_message_zone() {
        let source = include_str!("cloud_messages.rs");
        let method_start = source
            .find("pub async fn warm_message_writer_preparation_lookup_only")
            .expect("writer preparation method");
        let following_method = source[method_start..]
            .find("async fn get_read_authentication_container_lookup_only")
            .expect("following read-authentication accessor");
        let method = &source[method_start..method_start + following_method];

        assert!(method.contains("self.get_container().await?"));
        assert!(method.contains("messageManateeZone"));
        assert!(method.contains("get_zone_encryption_config_lookup_only"));
        assert!(method.contains("validate_general_identity"));
        assert!(!method.contains("get_zone_encryption_config("));
        assert!(!method.contains("get_zone_encryption_config_sev("));
        assert!(!method.contains("SaveRecordOperation"));
        assert!(!method.contains("DeleteRecordOperation"));
    }

    #[tokio::test]
    async fn writer_binding_rejects_same_user_container_replacement() {
        let fixture = valid_fixture();
        let original = Arc::new(CloudKitOpenContainer::new_cached_identity_for_test(
            &MESSAGES_CONTAINER,
            fixture.client.clone(),
            "writer-original".to_owned(),
            "123".to_owned(),
        ));
        let replacement = Arc::new(CloudKitOpenContainer::new_cached_identity_for_test(
            &MESSAGES_CONTAINER,
            fixture.client.clone(),
            "writer-replacement".to_owned(),
            "123".to_owned(),
        ));
        *fixture.messages.container.lock().await = Some(original.clone());
        let binding = CloudMessagesWriterPreparationBinding::new_for_test(original);

        fixture
            .messages
            .validate_writer_preparation_binding(&binding)
            .await
            .expect("the exact prepared container must remain valid");

        *fixture.messages.container.lock().await = Some(replacement);

        assert!(matches!(
            fixture
                .messages
                .validate_writer_preparation_binding(&binding)
                .await,
            Err(PushError::UnauthorizedAccountError)
        ));
    }

    #[test]
    fn cached_container_accessor_structurally_validates_permit_without_initializing() {
        let source = include_str!("cloud_messages.rs");
        let method_start = source
            .find("pub async fn get_cached_container_for_read_authentication")
            .expect("cached container accessor");
        let following_method = source[method_start..]
            .find("pub async fn get_container_lookup_only")
            .expect("following lookup-only accessor");
        let method = &source[method_start..method_start + following_method];

        assert!(method.matches("permit.validate()?").count() >= 3);
        assert!(method.contains("get_read_authentication_container_lookup_only"));
        assert!(method.contains("validate_read_authentication_identity"));
        assert!(!method.contains("init_for_read_authentication"));
        assert!(!method.contains("container_initialization"));
    }

    struct NoBootstrapAnisette;

    impl AnisetteProvider for NoBootstrapAnisette {
        fn get_anisette_headers(
            &mut self,
        ) -> impl Future<Output = Result<HashMap<String, String>, AnisetteError>> + Send {
            async { panic!("identity validation must not generate Anisette data") }
        }
    }

    struct NoBootstrapConfig;

    #[async_trait::async_trait]
    impl OSConfig for NoBootstrapConfig {
        fn build_activation_info(&self, _csr: Vec<u8>) -> crate::activation::ActivationInfo {
            unreachable!("identity validation must not activate")
        }

        fn get_activation_device(&self) -> String {
            "identity-test-device".to_owned()
        }

        async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
            unreachable!("identity validation must not bootstrap")
        }

        fn get_protocol_version(&self) -> u32 {
            1
        }

        fn get_register_meta(&self) -> RegisterMeta {
            RegisterMeta {
                hardware_version: "identity-test-hardware".to_owned(),
                os_version: "identity-test-os".to_owned(),
                software_version: "identity-test-software".to_owned(),
            }
        }

        fn get_normal_ua(&self, item: &str) -> String {
            item.to_owned()
        }

        fn get_mme_clientinfo(&self, item: &str) -> String {
            item.to_owned()
        }

        fn get_version_ua(&self) -> String {
            "identity-test-version".to_owned()
        }

        fn get_device_name(&self) -> String {
            "identity-test-device".to_owned()
        }

        fn get_device_uuid(&self) -> String {
            "identity-test-device-uuid".to_owned()
        }

        fn get_private_data(&self) -> plist::Dictionary {
            plist::Dictionary::new()
        }

        fn get_debug_meta(&self) -> DebugMeta {
            DebugMeta {
                user_version: "identity-test-user-version".to_owned(),
                hardware_version: "identity-test-hardware".to_owned(),
                serial_number: "identity-test-serial".to_owned(),
            }
        }

        fn get_login_url(&self) -> &'static str {
            "http://127.0.0.1/identity-test-unused"
        }

        fn get_serial_number(&self) -> String {
            "identity-test-serial".to_owned()
        }

        fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
            HashMap::new()
        }

        fn get_aoskit_version(&self) -> String {
            "identity-test-aoskit".to_owned()
        }

        fn get_udid(&self) -> String {
            "identity-test-udid".to_owned()
        }
    }

    type TestTokenProvider = TokenProvider<NoBootstrapAnisette>;
    type TestCloudKitClient = CloudKitClient<NoBootstrapAnisette>;
    type TestKeychainClient = KeychainClient<NoBootstrapAnisette>;

    struct Fixture {
        messages: CloudMessagesClient<NoBootstrapAnisette>,
        client: Arc<TestCloudKitClient>,
        token_provider: Arc<TestTokenProvider>,
        anisette: ArcAnisetteClient<NoBootstrapAnisette>,
        config: Arc<dyn OSConfig>,
    }

    fn spd(dsid: Option<Value>, adsid: Option<Value>) -> Option<plist::Dictionary> {
        let mut values = plist::Dictionary::new();
        if let Some(dsid) = dsid {
            values.insert("DsPrsId".to_owned(), dsid);
        }
        if let Some(adsid) = adsid {
            values.insert("adsid".to_owned(), adsid);
        }
        Some(values)
    }

    fn token_provider(
        spd: Option<plist::Dictionary>,
        anisette: ArcAnisetteClient<NoBootstrapAnisette>,
        config: Arc<dyn OSConfig>,
    ) -> Arc<TestTokenProvider> {
        let mut account = AppleAccount::new_with_anisette(LoginClientInfo::default(), anisette)
            .expect("test Apple account must initialize");
        account.spd = spd;
        TokenProvider::new(Arc::new(DebugMutex::new(account)), config)
    }

    fn cloudkit_client(
        dsid: &str,
        anisette: ArcAnisetteClient<NoBootstrapAnisette>,
        config: Arc<dyn OSConfig>,
        token_provider: Arc<TestTokenProvider>,
    ) -> Arc<TestCloudKitClient> {
        Arc::new(CloudKitClient {
            anisette,
            state: DebugRwLock::new(
                CloudKitState::new(dsid.to_owned()).expect("test CloudKit state"),
            ),
            config,
            token_provider,
        })
    }

    fn keychain_state(dsid: &str, adsid: &str) -> KeychainClientState {
        let mut keychain_sync = plist::Dictionary::new();
        keychain_sync.insert(
            "escrowProxyUrl".to_owned(),
            Value::String("https://127.0.0.1/identity-test-unused".to_owned()),
        );
        let mut delegate_config = plist::Dictionary::new();
        delegate_config.insert(
            "com.apple.Dataclass.KeychainSync".to_owned(),
            Value::Dictionary(keychain_sync),
        );
        let delegate = crate::auth::MobileMeDelegateResponse {
            tokens: HashMap::new(),
            config: delegate_config,
        };
        KeychainClientState::new(dsid.to_owned(), adsid.to_owned(), &delegate)
            .expect("test keychain state")
    }

    fn keychain_client(
        client: Arc<TestCloudKitClient>,
        token_provider: Arc<TestTokenProvider>,
        anisette: ArcAnisetteClient<NoBootstrapAnisette>,
        config: Arc<dyn OSConfig>,
        dsid: &str,
        adsid: &str,
    ) -> Arc<TestKeychainClient> {
        Arc::new(KeychainClient {
            anisette,
            token_provider,
            state: DebugRwLock::new(keychain_state(dsid, adsid)),
            config,
            update_state: Box::new(|_| {}),
            container: tokio::sync::Mutex::new(None),
            container_initialization: tokio::sync::Mutex::new(()),
            security_container: tokio::sync::Mutex::new(None),
            security_container_initialization: tokio::sync::Mutex::new(()),
            client,
        })
    }

    fn fixture(
        gsa_spd: Option<plist::Dictionary>,
        cloudkit_dsid: &str,
        keychain_dsid: &str,
        keychain_adsid: &str,
    ) -> Fixture {
        let anisette = Arc::new(tokio::sync::Mutex::new(AnisetteClient::new(
            NoBootstrapAnisette,
        )));
        let config: Arc<dyn OSConfig> = Arc::new(NoBootstrapConfig);
        let token_provider = token_provider(gsa_spd, anisette.clone(), config.clone());
        let client = cloudkit_client(
            cloudkit_dsid,
            anisette.clone(),
            config.clone(),
            token_provider.clone(),
        );
        let keychain = keychain_client(
            client.clone(),
            token_provider.clone(),
            anisette.clone(),
            config.clone(),
            keychain_dsid,
            keychain_adsid,
        );

        Fixture {
            messages: CloudMessagesClient::new(client.clone(), keychain),
            client,
            token_provider,
            anisette,
            config,
        }
    }

    fn valid_fixture() -> Fixture {
        fixture(
            spd(
                Some(Value::Integer(123.into())),
                Some(Value::String("adsid-123".to_owned())),
            ),
            "123",
            "123",
            "adsid-123",
        )
    }

    #[tokio::test]
    async fn restored_read_authentication_containers_are_provenance_separated() {
        static CUTTLEFISH_CONTAINER_FOR_TEST: CloudKitContainer<'static> = CloudKitContainer {
            database_type: cloudkit_proto::request_operation::header::Database::PrivateDb,
            bundleid: "com.apple.security.cuttlefish",
            containerid: "com.apple.security.keychain",
            env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
        };
        static SECURITYD_CONTAINER_FOR_TEST: CloudKitContainer<'static> = CloudKitContainer {
            database_type: cloudkit_proto::request_operation::header::Database::PrivateDb,
            bundleid: "com.apple.securityd",
            containerid: "com.apple.security.keychain",
            env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
        };

        let fixture = valid_fixture();
        let client = fixture.client.clone();
        let keychain = fixture.messages.keychain.clone();
        let read_generation = client
            .token_provider
            .restore_cloudkit_read_authentication(
                "read-mme-token".to_owned(),
                "read-cloudkit-token".to_owned(),
                SystemTime::now(),
                || Ok(()),
            )
            .await
            .expect("test read generation");
        let cached = |container: &'static CloudKitContainer<'static>, provenance: &str| {
            Arc::new(CloudKitOpenContainer::new_cached_identity_for_test(
                container,
                client.clone(),
                provenance.to_owned(),
                "123".to_owned(),
            ))
        };

        let general_messages = cached(&MESSAGES_CONTAINER, "general-messages");
        let restored_messages = Arc::new(CloudKitOpenContainer::new_cached_read_identity_for_test(
            &MESSAGES_CONTAINER,
            client.clone(),
            "restored-messages".to_owned(),
            "123".to_owned(),
            read_generation.clone(),
        ));
        let general_cuttlefish = cached(&CUTTLEFISH_CONTAINER_FOR_TEST, "general-cuttlefish");
        let restored_cuttlefish =
            Arc::new(CloudKitOpenContainer::new_cached_read_identity_for_test(
                &CUTTLEFISH_CONTAINER_FOR_TEST,
                client.clone(),
                "restored-cuttlefish".to_owned(),
                "123".to_owned(),
                read_generation.clone(),
            ));
        let general_securityd = cached(&SECURITYD_CONTAINER_FOR_TEST, "general-securityd");
        let restored_securityd =
            Arc::new(CloudKitOpenContainer::new_cached_read_identity_for_test(
                &SECURITYD_CONTAINER_FOR_TEST,
                client.clone(),
                "restored-securityd".to_owned(),
                "123".to_owned(),
                read_generation,
            ));

        *fixture.messages.container.lock().await = Some(general_messages.clone());
        *fixture.messages.read_authentication_container.lock().await =
            Some(restored_messages.clone());
        *keychain.container.lock().await = Some(CloudKitContainerCaches::new_for_test(
            general_cuttlefish.clone(),
            restored_cuttlefish.clone(),
        ));
        *keychain.security_container.lock().await = Some(CloudKitContainerCaches::new_for_test(
            general_securityd.clone(),
            restored_securityd.clone(),
        ));

        let general_messages_result = fixture.messages.get_container().await;
        let general_cuttlefish_result = keychain.get_container().await;
        let general_securityd_result = keychain.get_security_container().await;

        const TOKEN: u64 = 0xCA_CE_D0_02;
        pause_cloudkit_writer_operations(TOKEN)
            .await
            .expect("test writer pause");
        let permit = match acquire_cloudkit_read_authentication(TOKEN) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = resume_cloudkit_writer_operations(TOKEN).await;
                panic!("test read-authentication permit: {error}");
            }
        };
        let restored_messages_result = fixture
            .messages
            .get_container_for_read_authentication(&permit)
            .await;
        let restored_cuttlefish_result = keychain
            .get_container_for_read_authentication(&permit)
            .await;
        let restored_securityd_result = keychain
            .get_security_container_for_read_authentication(&permit)
            .await;
        drop(permit);
        let resume_result = resume_cloudkit_writer_operations(TOKEN).await;

        assert!(general_messages_result
            .as_ref()
            .is_ok_and(|container| Arc::ptr_eq(container, &general_messages)));
        assert!(general_cuttlefish_result
            .as_ref()
            .is_ok_and(|container| Arc::ptr_eq(container, &general_cuttlefish)));
        assert!(general_securityd_result
            .as_ref()
            .is_ok_and(|container| Arc::ptr_eq(container, &general_securityd)));
        assert!(restored_messages_result
            .as_ref()
            .is_ok_and(|container| Arc::ptr_eq(container, &restored_messages)));
        assert!(restored_cuttlefish_result
            .as_ref()
            .is_ok_and(|container| Arc::ptr_eq(container, &restored_cuttlefish)));
        assert!(restored_securityd_result
            .as_ref()
            .is_ok_and(|container| Arc::ptr_eq(container, &restored_securityd)));
        assert!(!Arc::ptr_eq(&general_messages, &restored_messages));
        assert!(!Arc::ptr_eq(&general_cuttlefish, &restored_cuttlefish));
        assert!(!Arc::ptr_eq(&general_securityd, &restored_securityd));
        assert!(general_messages
            .validate_general_identity(&client, CloudKitReadAuthenticationContainer::Messages)
            .await
            .is_ok());
        assert!(restored_messages
            .validate_general_identity(&client, CloudKitReadAuthenticationContainer::Messages)
            .await
            .is_err());
        resume_result.expect("resume test writer operations");
    }

    #[tokio::test]
    async fn cached_container_accessor_requires_warm_exact_messages_identity() {
        static WRONG_CONTAINER: CloudKitContainer<'static> = CloudKitContainer {
            database_type: cloudkit_proto::request_operation::header::Database::PrivateDb,
            bundleid: "com.apple.MobileSMS",
            containerid: "com.apple.messages.cloud",
            env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
        };

        let cold = valid_fixture();
        let keychain = cold.messages.keychain.clone();
        let generation = cold
            .token_provider
            .restore_cloudkit_read_authentication(
                "read-mme-token".to_owned(),
                "read-cloudkit-token".to_owned(),
                SystemTime::now(),
                || Ok(()),
            )
            .await
            .expect("test read generation");
        let warm_open = Arc::new(CloudKitOpenContainer::new_cached_read_identity_for_test(
            &MESSAGES_CONTAINER,
            cold.client.clone(),
            "cached-user".to_owned(),
            "123".to_owned(),
            generation.clone(),
        ));
        let warm = CloudMessagesClient::new_warm_for_test(
            cold.client.clone(),
            keychain.clone(),
            warm_open.clone(),
        );
        let wrong_open = Arc::new(CloudKitOpenContainer::new_cached_read_identity_for_test(
            &WRONG_CONTAINER,
            cold.client.clone(),
            "cached-user".to_owned(),
            "123".to_owned(),
            generation,
        ));
        let wrong =
            CloudMessagesClient::new_warm_for_test(cold.client.clone(), keychain, wrong_open);

        const TOKEN: u64 = 0xCA_CE_D0_01;
        pause_cloudkit_writer_operations(TOKEN)
            .await
            .expect("test writer pause");
        let permit = match acquire_cloudkit_read_authentication(TOKEN) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = resume_cloudkit_writer_operations(TOKEN).await;
                panic!("test read-authentication permit: {error}");
            }
        };

        let cold_result = cold
            .messages
            .get_cached_container_for_read_authentication(&permit)
            .await;
        let warm_result = warm
            .get_cached_container_for_read_authentication(&permit)
            .await;
        let wrong_result = wrong
            .get_cached_container_for_read_authentication(&permit)
            .await;
        drop(permit);
        let resume_result = resume_cloudkit_writer_operations(TOKEN).await;

        assert!(matches!(
            cold_result,
            Err(PushError::CloudKitWarmAuthenticationRequired)
        ));
        assert!(warm_result
            .as_ref()
            .is_ok_and(|container| Arc::ptr_eq(container, &warm_open)));
        assert!(matches!(
            wrong_result,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
        resume_result.expect("resume test writer operations");
    }

    #[tokio::test]
    async fn validated_identifier_accepts_exact_match_without_bootstrap_or_network() {
        let fixture = valid_fixture();

        assert_eq!(
            fixture
                .messages
                .validated_native_account_identifier()
                .await
                .expect("exact account composition must validate"),
            "123"
        );
    }

    #[tokio::test]
    async fn validated_identifier_rejects_missing_gsa_spd() {
        let fixture = fixture(None, "123", "123", "adsid-123");

        assert!(matches!(
            fixture.messages.validated_native_account_identifier().await,
            Err(PushError::UnauthorizedAccountError)
        ));
    }

    #[tokio::test]
    async fn persisted_identifier_accepts_missing_gsa_spd() {
        let fixture = fixture(None, "123", "123", "adsid-123");

        assert_eq!(
            fixture
                .messages
                .validated_persisted_native_account_identifiers()
                .await
                .expect("matching persisted account composition must validate"),
            ("123".to_owned(), "adsid-123".to_owned())
        );
    }

    #[tokio::test]
    async fn persisted_identifier_rejects_cloudkit_keychain_mismatch() {
        let fixture = fixture(None, "456", "123", "adsid-123");

        assert!(matches!(
            fixture
                .messages
                .validated_persisted_native_account_identifiers()
                .await,
            Err(PushError::UnauthorizedAccountError)
        ));
    }

    #[tokio::test]
    async fn cached_gsa_identifiers_reject_malformed_and_empty_spd_values() {
        for malformed_spd in [
            spd(
                Some(Value::String("123".to_owned())),
                Some(Value::String("adsid-123".to_owned())),
            ),
            spd(
                Some(Value::Integer(123.into())),
                Some(Value::Integer(123.into())),
            ),
            spd(
                Some(Value::Integer(0.into())),
                Some(Value::String("adsid-123".to_owned())),
            ),
            spd(
                Some(Value::Integer(123.into())),
                Some(Value::String("   ".to_owned())),
            ),
        ] {
            let fixture = fixture(malformed_spd, "123", "123", "adsid-123");
            assert!(matches!(
                fixture
                    .token_provider
                    .get_gsa_account_identifiers_cached()
                    .await,
                Err(PushError::UnauthorizedAccountError)
            ));
        }
    }

    #[tokio::test]
    async fn validated_identifier_rejects_dsid_mismatch() {
        let fixture = fixture(
            spd(
                Some(Value::Integer(123.into())),
                Some(Value::String("adsid-123".to_owned())),
            ),
            "456",
            "123",
            "adsid-123",
        );

        assert!(matches!(
            fixture.messages.validated_native_account_identifier().await,
            Err(PushError::UnauthorizedAccountError)
        ));
    }

    #[tokio::test]
    async fn validated_identifier_rejects_adsid_mismatch() {
        let fixture = fixture(
            spd(
                Some(Value::Integer(123.into())),
                Some(Value::String("adsid-a".to_owned())),
            ),
            "123",
            "123",
            "adsid-b",
        );

        assert!(matches!(
            fixture.messages.validated_native_account_identifier().await,
            Err(PushError::UnauthorizedAccountError)
        ));
    }

    #[tokio::test]
    async fn validated_identifier_rejects_mismatched_client_and_token_provider_arcs() {
        let fixture = valid_fixture();
        let wrong_client = cloudkit_client(
            "123",
            fixture.anisette.clone(),
            fixture.config.clone(),
            fixture.token_provider.clone(),
        );
        let wrong_client_keychain = keychain_client(
            wrong_client,
            fixture.token_provider.clone(),
            fixture.anisette.clone(),
            fixture.config.clone(),
            "123",
            "adsid-123",
        );
        let wrong_client_messages =
            CloudMessagesClient::new(fixture.client.clone(), wrong_client_keychain);
        assert!(matches!(
            wrong_client_messages
                .validated_native_account_identifier()
                .await,
            Err(PushError::UnauthorizedAccountError)
        ));

        let wrong_token_provider = token_provider(
            spd(
                Some(Value::Integer(123.into())),
                Some(Value::String("adsid-123".to_owned())),
            ),
            fixture.anisette.clone(),
            fixture.config.clone(),
        );
        let wrong_token_keychain = keychain_client(
            fixture.client.clone(),
            wrong_token_provider,
            fixture.anisette.clone(),
            fixture.config.clone(),
            "123",
            "adsid-123",
        );
        let wrong_token_messages = CloudMessagesClient::new(fixture.client, wrong_token_keychain);
        assert!(matches!(
            wrong_token_messages
                .validated_native_account_identifier()
                .await,
            Err(PushError::UnauthorizedAccountError)
        ));
    }
}
