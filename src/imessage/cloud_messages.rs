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
    pcs_keys_for_record, record_identifier, CloudKitSession, CloudKitUploadRequest,
    DeleteRecordOperation, FetchRecordChangesOperation, FetchRecordOperation, FetchedRecords,
    QueryRecordOperation, SaveRecordOperation, ZoneDeleteOperation, ALL_ASSETS,
    CLOUDKIT_DEFAULT_MAX_CHANGES_PER_PAGE, NO_ASSETS,
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
use log::info;
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
    cloudkit::{CloudKitClient, CloudKitContainer, CloudKitOpenContainer},
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
                r#type: Some(2),
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
            r#type: Some(2),
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

fn record_metadata_is_well_formed(
    record: &Record,
    change_record_name: Option<&str>,
    change_record_type: Option<&str>,
) -> bool {
    let Some(change_record_name) = change_record_name else {
        return false;
    };
    if record_identifier_name(record.record_identifier.as_ref()) != Some(change_record_name) {
        return false;
    }

    let Some(record_type) = record
        .r#type
        .as_ref()
        .and_then(|record_type| record_type.name.as_deref())
        .filter(|record_type| !record_type.is_empty())
    else {
        return false;
    };
    if change_record_type.is_some_and(|change_record_type| change_record_type != record_type) {
        return false;
    }

    record.record_field.iter().all(|field| {
        field
            .identifier
            .as_ref()
            .and_then(|identifier| identifier.name.as_deref())
            .is_some_and(|name| !name.is_empty())
    })
}

fn map_ordered_page_changes(
    changes: Vec<RecordChange>,
    expected_record_type: &str,
) -> Vec<CloudMessageRecordPageChange> {
    changes
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

            let change_shape_is_well_formed = match change.r#type {
                Some(1) => change.record.is_some(),
                Some(2) => change.record.is_none(),
                Some(_) => false,
                None => true,
            };
            let kind = if record_name.is_none() || !change_shape_is_well_formed {
                CloudMessageRecordKind::MalformedMetadata
            } else if let Some(record) = change.record.as_ref() {
                if !record_metadata_is_well_formed(
                    record,
                    record_name.as_deref(),
                    change
                        .record_type
                        .as_ref()
                        .and_then(|record_type| record_type.name.as_deref()),
                ) {
                    CloudMessageRecordKind::MalformedMetadata
                } else {
                    match record_type.as_deref() {
                        Some(record_type) if record_type == expected_record_type => {
                            CloudMessageRecordKind::EncryptedUpsert
                        }
                        Some(_) => CloudMessageRecordKind::UnsupportedRecordType,
                        None => CloudMessageRecordKind::MalformedMetadata,
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
        .collect()
}

pub struct CloudMessagesClient<P: AnisetteProvider> {
    pub container: Mutex<Option<Arc<CloudKitOpenContainer<'static, P>>>>,
    pub client: Arc<CloudKitClient<P>>,
    pub keychain: Arc<KeychainClient<P>>,
}

impl<P: AnisetteProvider> CloudMessagesClient<P> {
    pub fn new(client: Arc<CloudKitClient<P>>, keychain: Arc<KeychainClient<P>>) -> Self {
        Self {
            container: Mutex::new(None),
            client,
            keychain,
        }
    }

    /// Returns the active account identifier inside the native boundary.
    /// Callers must immediately transform it with an application-secret keyed
    /// function and must never expose it over FFI or logs.
    pub async fn native_account_identifier(&self) -> String {
        self.client
            .state
            .read()
            .await
            .account_identifier()
            .to_owned()
    }

    pub async fn get_container(&self) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let mut locked = self.container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone());
        }
        let container = Arc::new(MESSAGES_CONTAINER.init(self.client.clone()).await?);
        *locked = Some(container.clone());
        Ok(container)
    }

    async fn sync_records_page(
        &self,
        zone_name: &str,
        expected_record_type: &str,
        continuation_token: Option<Vec<u8>>,
        max_changes: u32,
    ) -> Result<CloudMessageRecordPage, PushError> {
        let container = self.get_container().await?;
        let zone = container.private_zone(zone_name.to_string());
        let page = FetchRecordChangesOperation::fetch_page_with_limit(
            &container,
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
                operations.push(SaveRecordOperation::new(
                    record_identifier(zone.clone(), &record_id),
                    chat,
                    Some(&key),
                    true,
                ));
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
    }

    async fn delete_records(&self, zone: &str, records: &[String]) -> Result<(), PushError> {
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
        let container = self.get_container().await?;

        container.keys.lock().await.clear();

        container
            .perform_operations_checked(
                &CloudKitSession::new(),
                &[
                    ZoneDeleteOperation::new(container.private_zone("chatManateeZone".to_string())),
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
                        container.private_zone("chatBotRecoverableMessageDeleteZone".to_string()),
                    ),
                ],
                IsolationLevel::Operation,
            )
            .await?;
        Ok(())
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
            .map(|f| records.get_record(f, Some(&key)))
            .collect::<Vec<_>>();

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
            .map(|f| records.get_record(f, Some(&key)))
            .collect::<Vec<_>>();

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
    }

    pub async fn upload_group_photo<T: Read + Send + Sync>(
        &self,
        files: Vec<(PreparedPut, T, String)>,
    ) -> Result<Vec<cloudkit_proto::Asset>, PushError> {
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
    }
}
