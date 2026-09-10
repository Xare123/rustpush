//! Typed attachment-record creation after a separately journaled byte upload.
//! This primitive is not upload admission. Its caller must retain the original
//! file, record name, upload result and request identity before consuming it.

use super::*;

const ATTACHMENT_CREATE_ZONE: &str = "attachmentManateeZone";
const MAX_ATTACHMENT_METADATA_BYTES: usize = 2 * 1024 * 1024;

pub struct CloudAttachmentSaveInput {
    pub local_operation_id: String,
    pub server_record_name: String,
    pub apple_operation_uuid: String,
    pub attachment: CloudAttachment,
}

pub enum CloudAttachmentRecordLookup {
    Found(CloudAttachment, CloudMessagesSaveReceipt),
    NotFound,
    Unresolved {
        failure_class: Option<CloudKitFailureClass>,
        retry_after: Option<Duration>,
    },
}

impl Debug for CloudAttachmentRecordLookup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Found(..) => "CloudAttachmentRecordLookup::Found(redacted)",
            Self::NotFound => "CloudAttachmentRecordLookup::NotFound",
            Self::Unresolved { .. } => "CloudAttachmentRecordLookup::Unresolved",
        })
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}

fn allocated_record_name(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.get_version() == Some(uuid::Version::Random))
}

fn validate_attachment(attachment: &CloudAttachment) -> Result<(), PushError> {
    let metadata = &attachment.cm.0;
    let asset = &attachment.lqa;
    if !valid_identifier(&metadata.guid)
        || !metadata.is_outgoing
        || metadata.version != 1
        || metadata.total_bytes < 0
        || asset.size != Some(metadata.total_bytes as u64)
        || asset.size.is_none_or(|size| size > u32::MAX as u64)
        || !asset
            .signature
            .as_ref()
            .is_some_and(|sig| sig.len() == 21 && sig[0] == 4)
        || !asset
            .reference_signature
            .as_ref()
            .is_some_and(|sig| sig.len() == 21 && sig[0] == 1)
        || !asset
            .protection_info
            .as_ref()
            .and_then(|info| info.protection_info.as_ref())
            .is_some_and(|key| key.len() == 32)
    {
        return Err(PushError::BadMsg);
    }
    Ok(())
}

// The legacy generated decoder fills omitted fields from Default and can
// collapse a failed PCS unwrap into empty key material. Reconciliation must
// not turn that into Found. Decode both required fields with checked crypto.
fn decode_attachment(
    fields: &[cloudkit_proto::record::Field],
    decryptor: &crate::pcs::PCSEncryptor,
) -> Result<CloudAttachment, PushError> {
    use cloudkit_proto::record::field::value::Type;
    let mut metadata = None;
    let mut asset = None;
    for field in fields {
        let name = field
            .identifier
            .as_ref()
            .and_then(|id| id.name.as_deref())
            .ok_or(PushError::BadMsg)?;
        match name {
            "cm" => {
                if metadata.is_some() {
                    return Err(PushError::BadMsg);
                }
                let value = field.value.as_ref().ok_or(PushError::BadMsg)?;
                if value.r#type != Some(Type::EncryptedBytesType as i32)
                    || value.is_encrypted != Some(true)
                {
                    return Err(PushError::BadMsg);
                }
                let cipher = value.bytes_value.as_deref().ok_or(PushError::BadMsg)?;
                if cipher.len() > MAX_ATTACHMENT_METADATA_BYTES {
                    return Err(PushError::BadMsg);
                }
                let compressed = decryptor
                    .decrypt_data_checked(cipher, "cm")
                    .map_err(|_| PushError::BadMsg)?;
                let mut bytes = Vec::new();
                libflate::gzip::Decoder::new(compressed.as_slice())
                    .map_err(|_| PushError::BadMsg)?
                    .take((MAX_ATTACHMENT_METADATA_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| PushError::BadMsg)?;
                if bytes.len() > MAX_ATTACHMENT_METADATA_BYTES {
                    return Err(PushError::BadMsg);
                }
                metadata = Some(
                    plist::from_bytes::<AttachmentMeta>(&bytes).map_err(|_| PushError::BadMsg)?,
                );
            }
            "lqa" => {
                if asset.is_some() {
                    return Err(PushError::BadMsg);
                }
                let value = field.value.as_ref().ok_or(PushError::BadMsg)?;
                if value.r#type != Some(Type::AssetType as i32) {
                    return Err(PushError::BadMsg);
                }
                let mut decoded = value.asset_value.clone().ok_or(PushError::BadMsg)?;
                let signature = decoded.signature.as_deref().ok_or(PushError::BadMsg)?;
                let reference = decoded
                    .reference_signature
                    .as_deref()
                    .ok_or(PushError::BadMsg)?;
                if signature.len() != 21 || reference.len() != 21 {
                    return Err(PushError::BadMsg);
                }
                let context = format!(
                    "lqa-{}-{}",
                    base64_encode(signature),
                    base64_encode(reference)
                );
                let key = decoded
                    .protection_info
                    .as_mut()
                    .and_then(|info| info.protection_info.as_mut())
                    .ok_or(PushError::BadMsg)?;
                if key.len() > 4096 {
                    return Err(PushError::BadMsg);
                }
                *key = decryptor
                    .decrypt_data_checked(key, &context)
                    .map_err(|_| PushError::BadMsg)?;
                if decoded
                    .record_id
                    .as_ref()
                    .is_some_and(|id| id != &decryptor.record_id)
                {
                    return Err(PushError::BadMsg);
                }
                asset = Some(decoded);
            }
            _ => {}
        }
    }
    let attachment = CloudAttachment {
        cm: GZipWrapper(metadata.ok_or(PushError::BadMsg)?),
        lqa: asset.ok_or(PushError::BadMsg)?,
    };
    validate_attachment(&attachment)?;
    Ok(attachment)
}

fn validate_input(
    input: &CloudAttachmentSaveInput,
    request_identity: &CloudKitRequestIdentity,
) -> Result<(), PushError> {
    validate_attachment(&input.attachment)?;
    // Leave room for gzip/PCS overhead within the bounded readback decoder.
    if input.attachment.cm.0.to_bytes().len() > MAX_ATTACHMENT_METADATA_BYTES / 2 {
        return Err(PushError::BadMsg);
    }
    let asset = &input.attachment.lqa;
    if !valid_identifier(&input.local_operation_id)
        || !allocated_record_name(&input.server_record_name)
        || request_identity.operation_uuids() != [input.apple_operation_uuid.clone()]
        || request_identity.http_request_uuid() == input.apple_operation_uuid
        || !asset
            .upload_receipt
            .as_ref()
            .is_some_and(|receipt| !receipt.is_empty())
    {
        return Err(PushError::BadMsg);
    }
    Ok(())
}

fn build_create_operation(
    zone: RecordZoneIdentifier,
    input: CloudAttachmentSaveInput,
    key: &crate::cloudkit::PCSZoneConfig,
) -> Result<SaveRecordOperation, PushError> {
    let identifier = record_identifier(zone.clone(), &input.server_record_name);
    if zone.value.as_ref().and_then(|value| value.name.as_deref()) != Some(ATTACHMENT_CREATE_ZONE)
        || !key.matches_zone(&zone)
        || input.attachment.lqa.record_id.as_ref() != Some(&identifier)
    {
        return Err(PushError::BadMsg);
    }
    SaveRecordOperation::try_new(
        identifier,
        input.attachment,
        Some(key),
        CloudMessagesSaveMode::CreateOnly.update_flag(),
    )
}

impl<P: AnisetteProvider> CloudMessagesClient<P> {
    /// Explicit writer preflight; existing zone/key lookup never provisions a
    /// zone or borrows a restored read-only authentication container.
    pub async fn warm_attachment_writer_preparation_lookup_only(
        &self,
    ) -> Result<CloudMessagesWriterPreparationBinding<P>, PushError> {
        let container = self.get_container().await?;
        let zone = container.private_zone(ATTACHMENT_CREATE_ZONE.to_owned());
        container
            .get_writer_zone_encryption_config_lookup_only(&zone, &self.keychain, &MESSAGES_SERVICE)
            .await?;
        container
            .validate_general_identity(&self.client, CloudKitReadAuthenticationContainer::Messages)
            .await?;
        if container.user_id.is_empty() {
            return Err(PushError::UnauthorizedAccountError);
        }
        Ok(CloudMessagesWriterPreparationBinding { container })
    }

    /// Prepare one attachment save using the existing no-replay owner. A
    /// returned owner means prepared, not submitted and not remotely saved.
    pub async fn prepare_attachment_save_submission(
        &self,
        writer_binding: &CloudMessagesWriterPreparationBinding<P>,
        input: CloudAttachmentSaveInput,
        request_identity: CloudKitRequestIdentity,
        request_timeout: Duration,
    ) -> Result<CloudMessagesPreparedSaveSubmission<P>, PushError> {
        with_cloudkit_writer_operation(async move {
            if request_timeout.is_zero() || request_timeout > Duration::from_secs(5 * 60) {
                return Err(PushError::BadMsg);
            }
            validate_input(&input, &request_identity)?;
            let container = self
                .get_writer_container_for_binding(writer_binding)
                .await?;
            let zone = container.private_zone(ATTACHMENT_CREATE_ZONE.to_owned());
            let key = container
                .get_cached_zone_encryption_config_exact(&zone)
                .await?;
            let local_operation_id = input.local_operation_id.clone();
            let operation = build_create_operation(zone, input, &key)?;
            let prepared_authentication = container.prepare_operations_authentication().await?;
            self.get_writer_container_for_binding(writer_binding)
                .await?;
            Ok(CloudMessagesPreparedSaveSubmission {
                container,
                session: CloudKitSession::new(),
                request_identity,
                prepared_authentication,
                operations: vec![operation],
                local_operation_ids: vec![local_operation_id],
                retry_policy: CloudKitRetryPolicy {
                    max_attempts: 1,
                    request_timeout,
                    ..CloudKitRetryPolicy::default()
                },
            })
        })
        .await
    }

    /// A record lookup is not an MMCS upload-status query. NotFound here must
    /// never authorize a new record identity or blind byte-upload replay.
    pub async fn lookup_attachment_record(
        &self,
        writer_binding: &CloudMessagesWriterPreparationBinding<P>,
        server_record_name: &str,
    ) -> Result<CloudAttachmentRecordLookup, PushError> {
        if !allocated_record_name(server_record_name) {
            return Err(PushError::BadMsg);
        }
        let container = self
            .get_writer_container_for_binding(writer_binding)
            .await?;
        let zone = container.private_zone(ATTACHMENT_CREATE_ZONE.to_owned());
        let key = container
            .get_cached_zone_encryption_config_exact(&zone)
            .await?;
        let expected = record_identifier(zone, server_record_name);
        let response = container
            .perform_operations_detailed(
                &CloudKitSession::new(),
                &[FetchRecordOperation::new(&NO_ASSETS, expected.clone())],
                IsolationLevel::Operation,
            )
            .await;
        self.get_writer_container_for_binding(writer_binding)
            .await?;
        let response = match response {
            Ok(response) => response,
            Err(failure) => {
                return Ok(CloudAttachmentRecordLookup::Unresolved {
                    failure_class: failure.failure_class,
                    retry_after: failure.retry_after,
                })
            }
        };
        if response.outcomes.len() != 1 {
            return Ok(CloudAttachmentRecordLookup::Unresolved {
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
                record.verify_identifier(&expected)?;
                let raw = record.get_raw_record()?;
                if raw.r#type.as_ref().and_then(|kind| kind.name.as_deref())
                    != Some(CloudAttachment::record_type())
                {
                    return Err(PushError::BadMsg);
                }
                let Some(receipt) = CloudMessagesSaveReceipt::validate(Some(&expected), Some(raw))
                else {
                    return Ok(CloudAttachmentRecordLookup::Unresolved {
                        failure_class: Some(CloudKitFailureClass::Unknown),
                        retry_after: None,
                    });
                };
                let decryptor = pcs_keys_for_record(raw, &key)?;
                let attachment = decode_attachment(&raw.record_field, &decryptor)?;
                Ok(CloudAttachmentRecordLookup::Found(attachment, receipt))
            }
            Err(error) if is_cloudkit_record_not_found(&error) => {
                Ok(CloudAttachmentRecordLookup::NotFound)
            }
            Err(_) => Ok(CloudAttachmentRecordLookup::Unresolved {
                failure_class: outcome.failure_class,
                retry_after: outcome.retry_after,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: &str = "DDDDDDDD-DDDD-4DDD-8DDD-DDDDDDDDDDDD";
    const OPERATION: &str = "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB";
    const REQUEST: &str = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA";

    fn zone() -> RecordZoneIdentifier {
        RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(ATTACHMENT_CREATE_ZONE.to_owned()),
                r#type: Some(cloudkit_proto::identifier::Type::RecordZone as i32),
            }),
            owner_identifier: Some(cloudkit_proto::Identifier {
                name: Some("fixture-owner".to_owned()),
                r#type: Some(cloudkit_proto::identifier::Type::User as i32),
            }),
            ..Default::default()
        }
    }

    fn identity() -> CloudKitRequestIdentity {
        CloudKitRequestIdentity::new(REQUEST.to_owned(), vec![OPERATION.to_owned()]).unwrap()
    }

    fn input() -> CloudAttachmentSaveInput {
        CloudAttachmentSaveInput {
            local_operation_id: "local-attachment-operation".to_owned(),
            server_record_name: RECORD.to_owned(),
            apple_operation_uuid: OPERATION.to_owned(),
            attachment: CloudAttachment {
                cm: GZipWrapper(AttachmentMeta {
                    guid: "attachment-fixture-guid".to_owned(),
                    is_outgoing: true,
                    version: 1,
                    total_bytes: 3,
                    mime_type: Some("application/pdf".to_owned()),
                    ..Default::default()
                }),
                lqa: Asset {
                    size: Some(3),
                    signature: Some(vec![4; 21]),
                    reference_signature: Some(vec![1; 21]),
                    record_id: Some(record_identifier(zone(), RECORD)),
                    upload_receipt: Some("fixture-receipt".to_owned()),
                    protection_info: Some(cloudkit_proto::ProtectionInfo {
                        protection_info: Some(vec![7; 32]),
                        protection_info_tag: None,
                    }),
                    ..Default::default()
                },
            },
        }
    }

    #[test]
    fn attachment_create_requires_exact_identity_and_completed_asset_shape() {
        validate_input(&input(), &identity()).unwrap();
        let changes: &[fn(&mut CloudAttachmentSaveInput)] = &[
            |i| i.server_record_name.clear(),
            |i| i.local_operation_id.clear(),
            |i| i.apple_operation_uuid = REQUEST.to_owned(),
            |i| i.attachment.cm.0.guid.clear(),
            |i| i.attachment.cm.0.is_outgoing = false,
            |i| i.attachment.cm.0.version = 0,
            |i| i.attachment.cm.0.total_bytes = -1,
            |i| i.attachment.lqa.size = Some(4),
            |i| i.attachment.lqa.signature = None,
            |i| i.attachment.lqa.signature = Some(vec![1; 21]),
            |i| i.attachment.lqa.reference_signature = None,
            |i| i.attachment.lqa.protection_info = None,
            |i| {
                i.attachment
                    .lqa
                    .protection_info
                    .as_mut()
                    .unwrap()
                    .protection_info = Some(vec![0; 31])
            },
            |i| i.attachment.lqa.upload_receipt = Some(String::new()),
        ];
        for change in changes {
            let mut candidate = input();
            change(&mut candidate);
            assert!(validate_input(&candidate, &identity()).is_err());
        }
    }

    #[test]
    fn attachment_create_serializes_create_only_and_round_trips_metadata() {
        let zone = zone();
        let keys = vec![PCSKey::random()];
        let key =
            crate::cloudkit::PCSZoneConfig::with_record_keys_for_test(zone.clone(), keys.clone());
        let operation = build_create_operation(zone.clone(), input(), &key).unwrap();
        assert_eq!(operation.0.save_semantics, Some(2));
        let record = operation.0.record.unwrap();
        let identifier = record_identifier(zone, RECORD);
        assert_eq!(record.record_identifier.as_ref(), Some(&identifier));
        assert_eq!(
            record.r#type.as_ref().unwrap().name.as_deref(),
            Some("attachment")
        );
        let decoded = decode_attachment(
            &record.record_field,
            &crate::pcs::PCSEncryptor {
                keys,
                record_id: identifier,
            },
        )
        .unwrap();
        assert_eq!(decoded.cm.0.guid, input().attachment.cm.0.guid);
        assert_eq!(decoded.cm.0.mime_type, Some("application/pdf".to_owned()));
        assert_eq!(decoded.cm.0.total_bytes, 3);
        assert_eq!(decoded.lqa.signature, input().attachment.lqa.signature);
        assert_eq!(
            decoded.lqa.reference_signature,
            input().attachment.lqa.reference_signature
        );
        assert_eq!(
            decoded.lqa.protection_info,
            input().attachment.lqa.protection_info
        );
    }

    #[test]
    fn readback_rejects_omitted_duplicate_or_corrupt_fields_without_defaults() {
        let zone = zone();
        let keys = vec![PCSKey::random()];
        let key =
            crate::cloudkit::PCSZoneConfig::with_record_keys_for_test(zone.clone(), keys.clone());
        let record = build_create_operation(zone.clone(), input(), &key)
            .unwrap()
            .0
            .record
            .unwrap();
        let decryptor = crate::pcs::PCSEncryptor {
            keys,
            record_id: record_identifier(zone, RECORD),
        };
        let fields = record.record_field;
        assert!(decode_attachment(&fields, &decryptor).is_ok());
        assert!(decode_attachment(&[], &decryptor).is_err());
        for index in 0..fields.len() {
            let mut omitted = fields.clone();
            omitted.remove(index);
            assert!(decode_attachment(&omitted, &decryptor).is_err());
            let mut duplicate = fields.clone();
            duplicate.push(fields[index].clone());
            assert!(decode_attachment(&duplicate, &decryptor).is_err());
            let mut corrupt = fields.clone();
            let value = corrupt[index].value.as_mut().unwrap();
            if let Some(bytes) = &mut value.bytes_value {
                bytes.clear();
            } else if let Some(asset) = &mut value.asset_value {
                asset.protection_info = None;
            }
            assert!(decode_attachment(&corrupt, &decryptor).is_err());
        }
    }

    #[test]
    fn attachment_metadata_is_bounded_before_save_and_after_decryption() {
        let mut oversized = input();
        oversized.attachment.cm.0.filename = Some("x".repeat(MAX_ATTACHMENT_METADATA_BYTES + 1));
        assert!(validate_input(&oversized, &identity()).is_err());
        let zone = zone();
        let keys = vec![PCSKey::random()];
        let key =
            crate::cloudkit::PCSZoneConfig::with_record_keys_for_test(zone.clone(), keys.clone());
        // Bypass save admission to represent a hostile remote record, whose
        // small compressed body expands past the local decode limit.
        let record = build_create_operation(zone.clone(), oversized, &key)
            .unwrap()
            .0
            .record
            .unwrap();
        let decryptor = crate::pcs::PCSEncryptor {
            keys,
            record_id: record_identifier(zone, RECORD),
        };
        assert!(decode_attachment(&record.record_field, &decryptor).is_err());
    }

    #[test]
    fn asset_record_and_zone_cannot_be_substituted() {
        let correct_zone = zone();
        let key = crate::cloudkit::PCSZoneConfig::with_record_keys_for_test(
            correct_zone.clone(),
            vec![PCSKey::random()],
        );
        let mut wrong_record = input();
        wrong_record.attachment.lqa.record_id =
            Some(record_identifier(correct_zone.clone(), REQUEST));
        assert!(build_create_operation(correct_zone.clone(), wrong_record, &key).is_err());
        let mut wrong_zone = correct_zone.clone();
        wrong_zone.value.as_mut().unwrap().name = Some("messageManateeZone".to_owned());
        assert!(build_create_operation(wrong_zone, input(), &key).is_err());
        let mut wrong_owner = correct_zone;
        wrong_owner.owner_identifier.as_mut().unwrap().name = Some("other-owner".to_owned());
        assert!(build_create_operation(wrong_owner, input(), &key).is_err());
    }
}
