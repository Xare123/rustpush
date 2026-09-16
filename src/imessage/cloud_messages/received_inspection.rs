//! Strict, read-only native view of one fetched MessageEncryptedV3 record.
//! Does not use the forgiving derive decoder: missing fields, decryption
//! errors, ambiguous fields and malformed gzip/protobuf must remain errors.
use super::{
    cloudmessagesp::{MessageProto, MessageProto2, MessageProto3, MessageProto4},
    CloudMessage, CloudMessagesClient, CloudMessagesWriterPreparationBinding, GZipWrapper,
    MessageFlags,
};
use crate::{
    cloudkit::{pcs_keys_for_record, FetchedRecord},
    cloudkit_operation_gate::CloudKitReadAuthenticationPermit,
    PushError,
};
use cloudkit_proto::{
    record::{
        field::{value::Type, EncryptedValue, Value},
        Field,
    },
    Record,
};
use omnisette::AnisetteProvider;
use prost::Message;
use std::{
    collections::HashMap,
    io::{Cursor, Read},
    time::{Duration, UNIX_EPOCH},
};

const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_FIELDS: usize = 32;

/// Owned native-only original plaintext protos. No Debug/serde/bridge surface.
/// The caller still proves exact record identity, parent, origin and version.
pub struct CloudMessageRecordInspection {
    pub message: CloudMessage,
    pub msg_proto: Vec<u8>,
    pub msg_proto_2: Option<Vec<u8>>,
    pub msg_proto_3: Option<Vec<u8>>,
    pub msg_proto_4: Option<Vec<u8>>,
}

impl<P: AnisetteProvider> CloudMessagesClient<P> {
    /// The same strict raw-wire lookup for an already selected writer binding.
    /// Used only by received-origin create preflight/readback, never a mutation.
    pub async fn lookup_received_message_record_for_writer(
        &self,
        writer_binding: &CloudMessagesWriterPreparationBinding<P>,
        server_record_name: &str,
    ) -> Result<super::CloudMessageRecordVersionLookup, PushError> {
        use crate::cloudkit::{record_identifier, CloudKitFailureClass, CloudKitSession,
            FetchRecordOperation, InspectReceivedRecordOperation, NO_ASSETS};
        use cloudkit_proto::request_operation::header::IsolationLevel;
        if server_record_name.is_empty() || server_record_name.len() > 4096 {
            return Err(PushError::BadMsg);
        }
        let container = self.get_writer_container_for_binding(writer_binding).await?;
        let zone = container.private_zone("messageManateeZone".into());
        container.get_cached_zone_encryption_config_exact(&zone).await?;
        let expected = record_identifier(zone, server_record_name);
        let response = container.perform_operations_detailed(&CloudKitSession::new(),
            &[InspectReceivedRecordOperation(FetchRecordOperation::new(&NO_ASSETS, expected.clone()))],
            IsolationLevel::Operation).await;
        let after = self.get_writer_container_for_binding(writer_binding).await?;
        if !std::sync::Arc::ptr_eq(&container, &after) {
            return Err(PushError::UnauthorizedAccountError);
        }
        let response = match response {
            Ok(value) => value,
            Err(failure) => return Ok(super::CloudMessageRecordVersionLookup::Unresolved {
                failure_class: failure.failure_class, retry_after: failure.retry_after,
            }),
        };
        if response.outcomes.len() != 1 {
            return Ok(super::CloudMessageRecordVersionLookup::Unresolved {
                failure_class: Some(CloudKitFailureClass::Unknown), retry_after: None,
            });
        }
        let outcome = response.outcomes.into_iter().next().ok_or(PushError::BadMsg)?;
        match outcome.result {
            Ok(record) => super::validate_message_record_version(record, &expected),
            Err(error) if super::is_cloudkit_record_not_found(&error) => Ok(super::CloudMessageRecordVersionLookup::NotFound),
            Err(_) => Ok(super::CloudMessageRecordVersionLookup::Unresolved {
                failure_class: outcome.failure_class, retry_after: outcome.retry_after,
            }),
        }
    }

    /// Exact read-only lookup from the already-warmed restored-read container.
    /// No fallback to the general/write container and no asset downloads.
    pub async fn lookup_received_message_record(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
        server_record_name: &str,
    ) -> Result<super::CloudMessageRecordVersionLookup, PushError> {
        use crate::cloudkit::{
            record_identifier, CloudKitFailureClass, CloudKitSession, FetchRecordOperation,
            InspectReceivedRecordOperation, NO_ASSETS,
        };
        use cloudkit_proto::request_operation::header::IsolationLevel;
        if server_record_name.is_empty() || server_record_name.len() > 4096 {
            return Err(PushError::BadMsg);
        };
        let container = self
            .get_cached_container_for_read_authentication(permit)
            .await?;
        let zone = container.private_zone("messageManateeZone".into());
        container
            .get_cached_zone_encryption_config_exact(&zone)
            .await?;
        let expected = record_identifier(zone, server_record_name);
        let response = container
            .perform_semantic_read_only_operations(
                &CloudKitSession::new(),
                &[InspectReceivedRecordOperation(FetchRecordOperation::new(
                    &NO_ASSETS,
                    expected.clone(),
                ))],
                IsolationLevel::Operation,
            )
            .await;
        let after = self
            .get_cached_container_for_read_authentication(permit)
            .await?;
        if !std::sync::Arc::ptr_eq(&container, &after) {
            return Err(PushError::UnauthorizedAccountError);
        };
        let unresolved = || super::CloudMessageRecordVersionLookup::Unresolved {
            failure_class: Some(CloudKitFailureClass::Unknown),
            retry_after: None,
        };
        let response = match response {
            Ok(value) => value,
            Err(_) => return Ok(unresolved()),
        };
        if response.len() != 1 {
            return Ok(unresolved());
        };
        let outcome = response.into_iter().next().ok_or(PushError::BadMsg)?;
        match outcome {
            Ok(record) => super::validate_message_record_version(record, &expected),
            Err(error) if super::is_cloudkit_record_not_found(&error) => {
                Ok(super::CloudMessageRecordVersionLookup::NotFound)
            }
            Err(_) => Ok(unresolved()),
        }
    }

    /// Same strict inspector under a restored-read permit. No credential/PCS
    /// warmup, mutation, alias normalization or refreshed container is allowed.
    pub async fn inspect_received_message_record_read_only(
        &self,
        permit: &CloudKitReadAuthenticationPermit<'_>,
        fetched: &FetchedRecord,
    ) -> Result<CloudMessageRecordInspection, PushError> {
        let container = self
            .get_cached_container_for_read_authentication(permit)
            .await?;
        let zone = container.private_zone("messageManateeZone".into());
        let keys = container
            .get_cached_zone_encryption_config_exact(&zone)
            .await?;
        let raw = fetched.get_raw_record()?;
        let decryptor = pcs_keys_for_record(raw, &keys)?;
        let view = inspect(raw, |name, bytes| {
            decryptor.decrypt_data_checked(bytes, name)
        })?;
        let after = self
            .get_cached_container_for_read_authentication(permit)
            .await?;
        if !std::sync::Arc::ptr_eq(&container, &after) {
            return Err(PushError::UnauthorizedAccountError);
        };
        Ok(view)
    }

    /// Cached same-container PCS only; no request, refresh, zone creation,
    /// re-encryption or mutation. This is separate from the legacy decoder.
    pub async fn inspect_received_message_record(
        &self,
        binding: &CloudMessagesWriterPreparationBinding<P>,
        fetched: &FetchedRecord,
    ) -> Result<CloudMessageRecordInspection, PushError> {
        let container = self.get_writer_container_for_binding(binding).await?;
        let zone = container.private_zone("messageManateeZone".into());
        let key = container
            .get_cached_zone_encryption_config_exact(&zone)
            .await?;
        let raw = fetched.get_raw_record()?;
        let decryptor = pcs_keys_for_record(raw, &key)?;
        let view = inspect(raw, |field, bytes| {
            decryptor.decrypt_data_checked(bytes, field)
        })?;
        self.get_writer_container_for_binding(binding).await?;
        Ok(view)
    }
}

fn inspect(
    record: &Record,
    decrypt: impl Fn(&str, &[u8]) -> Result<Vec<u8>, PushError>,
) -> Result<CloudMessageRecordInspection, PushError> {
    if record.r#type.as_ref().and_then(|v| v.name.as_deref()) != Some("MessageEncryptedV3")
        || record.protection_info.is_some()
        || record.pcs_key.as_ref().is_none_or(|v| v.len() != 4)
        || record.record_field.len() > MAX_FIELDS
    {
        return Err(PushError::BadMsg);
    }
    let mut fields = HashMap::new();
    for Field {
        identifier, value, ..
    } in &record.record_field
    {
        let name = identifier
            .as_ref()
            .and_then(|v| v.name.as_deref())
            .ok_or(PushError::BadMsg)?;
        if !matches!(
            name,
            "utm"
                | "msgType"
                | "eCode"
                | "chatID"
                | "sender"
                | "time"
                | "msgProto2"
                | "dcId"
                | "msgProto"
                | "flags"
                | "guid"
                | "msgProto3"
                | "svc"
                | "msgProto4"
        ) {
            return Err(PushError::BadMsg);
        }
        if fields
            .insert(name, value.as_ref().ok_or(PushError::BadMsg)?)
            .is_some()
        {
            return Err(PushError::BadMsg);
        }
    }
    let required = |name: &str| fields.get(name).copied().ok_or(PushError::BadMsg);
    let plain_int = |name: &str| -> Result<i64, PushError> {
        let value = required(name)?;
        require_shape(value, Type::Int64Type, false)?;
        value.signed_value.ok_or(PushError::BadMsg)
    };
    let encrypted_scalar = |name: &str, kind: Type| -> Result<EncryptedValue, PushError> {
        let value = required(name)?;
        require_shape(value, kind, true)?;
        let bytes = value
            .bytes_value
            .as_deref()
            .filter(|v| !v.is_empty() && v.len() <= MAX_BYTES)
            .ok_or(PushError::BadMsg)?;
        let decoded = decrypt(name, bytes)?;
        if decoded.len() > MAX_BYTES {
            return Err(PushError::BadMsg);
        }
        let result = EncryptedValue::decode(decoded.as_slice()).map_err(|_| PushError::BadMsg)?;
        // Check raw scalar presence and unknown/duplicate fields, accepting
        // field order/valid varint representation rather than reencoding.
        let expected = match kind {
            Type::Int64Type => 3,
            Type::StringType => 6,
            _ => return Err(PushError::BadMsg),
        };
        validate_scalar_wire(&decoded, expected)?;
        Ok(result)
    };
    let text = |name: &str| {
        encrypted_scalar(name, Type::StringType)?
            .string_value
            .ok_or(PushError::BadMsg)
    };
    let integer = |name: &str| {
        encrypted_scalar(name, Type::Int64Type)?
            .signed_value
            .ok_or(PushError::BadMsg)
    };
    let proto = |name: &str| -> Result<Option<Vec<u8>>, PushError> {
        let Some(value) = fields.get(name) else {
            return Ok(None);
        };
        require_shape(value, Type::EncryptedBytesType, true)?;
        let ciphertext = value
            .bytes_value
            .as_deref()
            .filter(|v| !v.is_empty() && v.len() <= MAX_BYTES)
            .ok_or(PushError::BadMsg)?;
        let compressed = decrypt(name, ciphertext)?;
        if compressed.is_empty() || compressed.len() > MAX_BYTES {
            return Err(PushError::BadMsg);
        }
        let mut decoder = flate2::bufread::GzDecoder::new(Cursor::new(&compressed));
        let mut bytes = Vec::new();
        decoder
            .by_ref()
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| PushError::BadMsg)?;
        if bytes.len() > MAX_BYTES || decoder.into_inner().position() as usize != compressed.len() {
            return Err(PushError::BadMsg);
        }
        Ok(Some(bytes))
    };
    let msg_proto = proto("msgProto")?.ok_or(PushError::BadMsg)?;
    let msg_proto_2 = proto("msgProto2")?;
    let msg_proto_3 = proto("msgProto3")?;
    let msg_proto_4 = proto("msgProto4")?;
    let flags = integer("flags")?;
    let utm = fields
        .get("utm")
        .map(|value| {
            require_shape(value, Type::DateType, false)?;
            let seconds = value
                .date_value
                .as_ref()
                .and_then(|v| v.time)
                .ok_or(PushError::BadMsg)?;
            let duration = Duration::try_from_secs_f64(seconds).map_err(|_| PushError::BadMsg)?;
            (UNIX_EPOCH + Duration::from_secs(978307200))
                .checked_add(duration)
                .ok_or(PushError::BadMsg)
        })
        .transpose()?;
    let message = CloudMessage {
        utm,
        r#type: plain_int("msgType")?,
        error: plain_int("eCode")?,
        chat_id: text("chatID")?,
        sender: text("sender")?,
        time: integer("time")?,
        destination_caller_id: text("dcId")?,
        msg_proto: GZipWrapper(
            MessageProto::decode(msg_proto.as_slice()).map_err(|_| PushError::BadMsg)?,
        ),
        msg_proto_2: decode_optional::<MessageProto2>(&msg_proto_2)?,
        msg_proto_3: decode_optional::<MessageProto3>(&msg_proto_3)?,
        msg_proto_4: decode_optional::<MessageProto4>(&msg_proto_4)?,
        flags: MessageFlags::from_bits_retain(flags),
        guid: text("guid")?,
        service: text("svc")?,
    };
    Ok(CloudMessageRecordInspection {
        message,
        msg_proto,
        msg_proto_2,
        msg_proto_3,
        msg_proto_4,
    })
}

fn decode_optional<T: Message + Default>(
    bytes: &Option<Vec<u8>>,
) -> Result<Option<GZipWrapper<T>>, PushError> {
    bytes
        .as_ref()
        .map(|v| {
            T::decode(v.as_slice())
                .map(GZipWrapper)
                .map_err(|_| PushError::BadMsg)
        })
        .transpose()
}

fn require_shape(value: &Value, kind: Type, encrypted: bool) -> Result<(), PushError> {
    if value.r#type != Some(kind as i32)
        || (value.is_encrypted == Some(true)) != encrypted
        || value.double_value.is_some()
        || value.string_value.is_some()
        || value.location_value.is_some()
        || value.reference_value.is_some()
        || value.asset_value.is_some()
        || value.package_value.is_some()
        || !value.list_values.is_empty()
    {
        return Err(PushError::BadMsg);
    }
    if encrypted {
        if value.is_encrypted != Some(true)
            || value.signed_value.is_some()
            || value.date_value.is_some()
            || value.bytes_value.is_none()
        {
            return Err(PushError::BadMsg);
        }
    } else if value.bytes_value.is_some()
        || match kind {
            Type::Int64Type => value.signed_value.is_none() || value.date_value.is_some(),
            Type::DateType => value.date_value.is_none() || value.signed_value.is_some(),
            _ => true,
        }
    {
        return Err(PushError::BadMsg);
    }
    Ok(())
}

fn scalar_varint(bytes: &[u8], pos: &mut usize) -> Result<u64, PushError> {
    let mut result = 0;
    for i in 0..10 {
        let value = *bytes.get(*pos).ok_or(PushError::BadMsg)?;
        *pos += 1;
        if i == 9 && value > 1 {
            return Err(PushError::BadMsg);
        };
        result |= u64::from(value & 127) << (i * 7);
        if value & 128 == 0 {
            return Ok(result);
        };
    }
    Err(PushError::BadMsg)
}
fn validate_scalar_wire(bytes: &[u8], field: u64) -> Result<(), PushError> {
    let mut pos = 0;
    let wire = if field == 3 { 0 } else { 2 };
    if scalar_varint(bytes, &mut pos)? != ((field << 3) | wire) {
        return Err(PushError::BadMsg);
    }
    if wire == 0 {
        scalar_varint(bytes, &mut pos)?;
    } else {
        let length =
            usize::try_from(scalar_varint(bytes, &mut pos)?).map_err(|_| PushError::BadMsg)?;
        pos = pos
            .checked_add(length)
            .filter(|v| *v <= bytes.len())
            .ok_or(PushError::BadMsg)?;
    }
    if pos != bytes.len() {
        return Err(PushError::BadMsg);
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloudkit_proto::{record::Type as RecordType, CloudKitEncryptor, CloudKitRecord};
    struct IdentityCipher;
    impl CloudKitEncryptor for IdentityCipher {
        fn encrypt_data(&self, bytes: &[u8], _: &str) -> Vec<u8> {
            bytes.to_vec()
        }
        fn decrypt_data(&self, bytes: &[u8], _: &str) -> Vec<u8> {
            bytes.to_vec()
        }
    }
    fn fixture() -> Record {
        let message = CloudMessage {
            r#type: 1,
            error: 0,
            chat_id: "iMessage;-;peer@example.test".into(),
            sender: "peer@example.test".into(),
            destination_caller_id: "owner@example.test".into(),
            guid: "synthetic-guid".into(),
            time: 1_000_000,
            service: "iMessage".into(),
            msg_proto: GZipWrapper(MessageProto {
                unk1: 1,
                text: Some("synthetic text".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        Record {
            r#type: Some(RecordType {
                name: Some("MessageEncryptedV3".into()),
                ..Default::default()
            }),
            record_field: message.to_record_encrypted(Some(&IdentityCipher)),
            pcs_key: Some(vec![1; 4]),
            ..Default::default()
        }
    }
    fn read(record: &Record) -> Result<CloudMessageRecordInspection, PushError> {
        inspect(record, |_, v| Ok(v.to_vec()))
    }
    #[test]
    fn strict_view_keeps_original_proto_and_empty_sender_for_mirrors() {
        let record = fixture();
        let view = read(&record).unwrap();
        assert_eq!(
            view.message.msg_proto.0.text.as_deref(),
            Some("synthetic text")
        );
        assert_eq!(
            MessageProto::decode(view.msg_proto.as_slice()).unwrap(),
            view.message.msg_proto.0
        );
        assert!(view.msg_proto_2.is_none());
    }
    #[test]
    fn malformed_missing_duplicate_or_unknown_outer_fields_do_not_default() {
        let original = fixture();
        for field in [
            "msgType", "eCode", "chatID", "sender", "time", "dcId", "flags", "guid", "svc",
            "msgProto",
        ] {
            let mut missing = original.clone();
            missing
                .record_field
                .retain(|v| v.identifier.as_ref().and_then(|v| v.name.as_deref()) != Some(field));
            assert!(read(&missing).is_err());
        }
        let mut duplicate = original.clone();
        duplicate
            .record_field
            .push(duplicate.record_field[0].clone());
        assert!(read(&duplicate).is_err());
        let mut unknown = original.clone();
        unknown.record_field[0].identifier.as_mut().unwrap().name = Some("unknown-field".into());
        assert!(read(&unknown).is_err());
        let mut wrong = original.clone();
        wrong
            .record_field
            .iter_mut()
            .find(|v| v.identifier.as_ref().unwrap().name.as_deref() == Some("sender"))
            .unwrap()
            .value
            .as_mut()
            .unwrap()
            .is_encrypted = Some(false);
        assert!(read(&wrong).is_err());
    }
    #[test]
    fn preserves_unknown_flags_and_rejects_plaintext_substitution_and_bad_gzip() {
        let mut record = fixture();
        let flags = record
            .record_field
            .iter_mut()
            .find(|v| v.identifier.as_ref().unwrap().name.as_deref() == Some("flags"))
            .unwrap()
            .value
            .as_mut()
            .unwrap();
        flags.bytes_value = Some(
            EncryptedValue {
                signed_value: Some(i64::MIN),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        assert_eq!(read(&record).unwrap().message.flags.bits(), i64::MIN);
        let proto = record
            .record_field
            .iter_mut()
            .find(|v| v.identifier.as_ref().unwrap().name.as_deref() == Some("msgProto"))
            .unwrap()
            .value
            .as_mut()
            .unwrap();
        proto.bytes_value = Some(vec![1, 2, 3]);
        assert!(read(&record).is_err());
        assert!(inspect(&fixture(), |_, _| Err(PushError::BadMsg)).is_err());
    }
    #[test]
    fn encrypted_scalar_unknown_or_duplicate_fields_cannot_be_dropped() {
        assert!(validate_scalar_wire(&[0x18, 0], 3).is_ok());
        assert!(validate_scalar_wire(&[0x32, 0], 6).is_ok());
        for bytes in [
            &[0x18, 0, 0x18, 1][..],
            &[0x18, 0, 0x08, 1],
            &[0x18, 0x80],
            &[0x32, 2, 0],
        ] {
            assert!(validate_scalar_wire(bytes, 3).is_err());
        }
    }

    #[test]
    fn gzip_trailing_member_trailing_bytes_and_expansion_are_rejected() {
        use std::io::Write;
        let compressed = |bytes: &[u8]| {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap()
        };
        let proto = MessageProto {
            unk1: 1,
            text: Some("synthetic text".into()),
            ..Default::default()
        }
        .encode_to_vec();
        for bytes in [
            [compressed(&proto), compressed(&[0x98, 6, 1])].concat(),
            [compressed(&proto), vec![1, 2, 3]].concat(),
            compressed(&vec![0; MAX_BYTES + 1]),
        ] {
            let mut record = fixture();
            record
                .record_field
                .iter_mut()
                .find(|f| f.identifier.as_ref().unwrap().name.as_deref() == Some("msgProto"))
                .unwrap()
                .value
                .as_mut()
                .unwrap()
                .bytes_value = Some(bytes);
            assert!(read(&record).is_err());
        }
    }

    #[test]
    fn source_contract_uses_restored_no_refresh_transport_only() {
        let source = include_str!("received_inspection.rs");
        let lookup = source
            .split("pub async fn lookup_received_message_record(")
            .nth(1)
            .unwrap()
            .split("pub async fn inspect_received_message_record_read_only(")
            .next()
            .unwrap();
        assert!(lookup.contains(".perform_semantic_read_only_operations("));
        assert!(lookup.contains("InspectReceivedRecordOperation("));
        for forbidden in [
            ".perform_operations_detailed(",
            ".get_container(",
            "refresh_now",
            "SaveRecord",
            "ZoneSave",
        ] {
            assert!(!lookup.contains(forbidden));
        }
    }

    #[test]
    fn received_writer_readback_uses_strict_wire_and_pinned_container() {
        let source = include_str!("received_inspection.rs");
        let method = source.split("pub async fn lookup_received_message_record_for_writer(")
            .nth(1).unwrap().split("pub async fn lookup_received_message_record(").next().unwrap();
        assert!(method.contains("InspectReceivedRecordOperation("));
        assert!(method.contains("get_cached_zone_encryption_config_exact"));
        assert!(method.contains("Arc::ptr_eq(&container, &after)"));
        assert_eq!(method.matches("get_writer_container_for_binding").count(), 2);
        for forbidden in ["SaveRecordOperation", "DeleteRecordOperation", "refresh_now", "get_container()"] {
            assert!(!method.contains(forbidden));
        }
    }
}
