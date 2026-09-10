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

// Fixed native-upload bindings for the attachment byte lane. The record
// create stays a separate prepared-save step; this lane never builds a
// SaveRecordOperation and never creates a record.
const ATTACHMENT_UPLOAD_FIELD: &str = "lqa";
const ATTACHMENT_UPLOAD_RECORD_TYPE: &str = "attachment";
// Upper bound for one native upload attempt, matching the prepared-save
// one-shot ceiling and the CloudKit one-shot request ceiling.
const MAX_NATIVE_UPLOAD_TIMEOUT: Duration = Duration::from_secs(5 * 60);

// Already-persisted inputs for one native attachment byte upload. The
// PreparedPut must be the exact persisted value and reader must replay
// its exact bytes; this lane never re-derives or mutates them.
pub struct CloudAttachmentNativeUploadInput<R: Read + Send + Sync> {
    pub local_operation_id: String,
    pub server_record_name: String,
    pub apple_operation_uuid: String,
    pub prepared: PreparedPut,
    pub reader: R,
}

// Fixed failure vocabulary for never-submitted consumption. No raw
// payloads cross this boundary: no signatures, receipts, etags, or key
// material, and logs stay redacted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudAttachmentUploadConsumeError {
    CorrelationMismatch,
    BindingMismatch,
}

// Outcome of one consumed native upload. Uploaded carries the exact
// single expected asset; Failed is an explicit pre-commit rejection;
// UnknownOutcome retains the protected attempt without granting replay.
pub struct CloudAttachmentNativeUploadOutcome {
    pub local_operation_id: String,
    pub apple_operation_uuid: String,
    pub result: CloudAttachmentNativeUploadResult,
}

pub enum CloudAttachmentNativeUploadResult {
    Uploaded(Asset),
    Failed {
        failure_class: Option<CloudKitFailureClass>,
        retry_after: Option<Duration>,
    },
    UnknownOutcome {
        failure_class: Option<CloudKitFailureClass>,
        retry_after: Option<Duration>,
    },
}

// Single-use owner for one native attachment byte upload, mirroring
// CloudMessagesPreparedSaveSubmission. There is intentionally no Clone:
// consume_once moves the retained identity, prepared authentication,
// PreparedPut, and reader into the no-replay CloudKit primitive together.
//
// The caller must durably journal the full protected attempt BEFORE calling
// consume_once: attemptId correlation plus local operation id, server record
// name, Apple operation UUID, request UUID, byte-content hash, and writer
// binding reference. The full request identity stays in the native protected
// plan/attempt; the journal holds protected refs/hash/binding only, never
// raw signatures, receipts, keys, or tokens. After submission starts, a
// missing or malformed response cannot prove Apple did not commit the bytes,
// so this owner can never be re-created or re-submitted from here. An
// unknown byte attempt remains retained in the protected attempt; record
// reconciliation applies only after final-save admission.
pub struct CloudMessagesPreparedUploadSubmission<P: AnisetteProvider, R: Read + Send + Sync> {
    container: Arc<CloudKitOpenContainer<'static, P>>,
    session: CloudKitSession,
    request_identity: CloudKitRequestIdentity,
    prepared_authentication: CloudKitPreparedAuthentication<P>,
    local_operation_id: String,
    apple_operation_uuid: String,
    server_record_name: String,
    prepared: PreparedPut,
    reader: Option<R>,
    retry_policy: CloudKitRetryPolicy,
}

fn validate_native_upload_input<R: Read + Send + Sync>(
    input: &CloudAttachmentNativeUploadInput<R>,
    request_identity: &CloudKitRequestIdentity,
) -> Result<(), PushError> {
    if !valid_identifier(&input.local_operation_id)
        || !allocated_record_name(&input.server_record_name)
        || request_identity.operation_uuids() != [input.apple_operation_uuid.clone()]
        || request_identity.http_request_uuid() == input.apple_operation_uuid
        || input.prepared.total_sig.is_empty()
        || u32::try_from(input.prepared.total_len).is_err()
    {
        return Err(PushError::BadMsg);
    }
    Ok(())
}

fn map_native_upload_request_failure(
    local_operation_id: String,
    apple_operation_uuid: String,
    expected_request_identity: &CloudKitRequestIdentity,
    failure: CloudKitRequestFailure,
) -> CloudAttachmentNativeUploadOutcome {
    let result = if failure.request_identity.as_ref() != Some(expected_request_identity)
        || failure.outcome_may_be_committed
    {
        CloudAttachmentNativeUploadResult::UnknownOutcome {
            failure_class: failure.failure_class,
            retry_after: failure.retry_after,
        }
    } else {
        CloudAttachmentNativeUploadResult::Failed {
            failure_class: failure.failure_class,
            retry_after: failure.retry_after,
        }
    };
    CloudAttachmentNativeUploadOutcome {
        local_operation_id,
        apple_operation_uuid,
        result,
    }
}

impl<P: AnisetteProvider> CloudMessagesClient<P> {
    // Prepare one native attachment byte upload using the existing
    // no-replay owner shape. A returned owner means prepared, not
    // submitted and not remotely uploaded. The caller must durably journal
    // the full protected attempt BEFORE consuming the owner. Uses only the
    // writer-warmed cached exact attachment zone; never creates zones
    // or syncs keys.
    pub async fn prepare_attachment_native_upload_submission<R: Read + Send + Sync>(
        &self,
        writer_binding: &CloudMessagesWriterPreparationBinding<P>,
        input: CloudAttachmentNativeUploadInput<R>,
        request_identity: CloudKitRequestIdentity,
        request_timeout: Duration,
    ) -> Result<CloudMessagesPreparedUploadSubmission<P, R>, PushError> {
        with_cloudkit_writer_operation(async move {
            if request_timeout.is_zero() || request_timeout > MAX_NATIVE_UPLOAD_TIMEOUT {
                return Err(PushError::BadMsg);
            }
            validate_native_upload_input(&input, &request_identity)?;
            let container = self
                .get_writer_container_for_binding(writer_binding)
                .await?;
            let zone = container.private_zone(ATTACHMENT_CREATE_ZONE.to_owned());
            // Cached exact zone only: proves the writer-warmed attachment
            // zone is present without creating zones or syncing keys. The
            // zone key itself is not needed for the byte upload.
            let _cached_zone_key = container
                .get_cached_zone_encryption_config_exact(&zone)
                .await?;
            let prepared_authentication = container.prepare_operations_authentication().await?;
            self.get_writer_container_for_binding(writer_binding)
                .await?;
            Ok(CloudMessagesPreparedUploadSubmission {
                container,
                session: CloudKitSession::new(),
                request_identity,
                prepared_authentication,
                local_operation_id: input.local_operation_id,
                apple_operation_uuid: input.apple_operation_uuid,
                server_record_name: input.server_record_name,
                prepared: input.prepared,
                reader: Some(input.reader),
                retry_policy: CloudKitRetryPolicy {
                    max_attempts: 1,
                    request_timeout,
                    ..CloudKitRetryPolicy::default()
                },
            })
        })
        .await
    }
}

impl<P: AnisetteProvider, R: Read + Send + Sync> CloudMessagesPreparedUploadSubmission<P, R> {
    // Consumes this owner exactly once through the identified, no-replay
    // native upload. The caller must already have durably journaled the full
    // protected attempt; after submission an ambiguous response is reported as
    // UnknownOutcome, never replayed here. An unknown byte attempt remains
    // retained; record reconciliation applies only after final-save admission.
    // Returns the exact single expected asset on success and never creates
    // a record.
    pub async fn consume_once(
        self,
        client: &CloudMessagesClient<P>,
        writer_binding: &CloudMessagesWriterPreparationBinding<P>,
    ) -> Result<CloudAttachmentNativeUploadOutcome, CloudAttachmentUploadConsumeError> {
        let Self {
            container,
            session,
            request_identity,
            prepared_authentication,
            local_operation_id,
            apple_operation_uuid,
            server_record_name,
            prepared,
            reader,
            retry_policy,
        } = self;
        if request_identity.operation_uuids() != [apple_operation_uuid.clone()]
            || request_identity.http_request_uuid() == apple_operation_uuid
        {
            return Err(CloudAttachmentUploadConsumeError::CorrelationMismatch);
        }
        if !Arc::ptr_eq(&container, &writer_binding.container)
            || client
                .validate_writer_preparation_binding(writer_binding)
                .await
                .is_err()
        {
            return Err(CloudAttachmentUploadConsumeError::BindingMismatch);
        }
        let Some(reader) = reader else {
            return Err(CloudAttachmentUploadConsumeError::CorrelationMismatch);
        };
        let expected_request_identity = request_identity.clone();
        let zone = container.private_zone(ATTACHMENT_CREATE_ZONE.to_owned());
        let upload = CloudKitUploadRequest {
            file: Some(reader),
            record_id: server_record_name,
            field: ATTACHMENT_UPLOAD_FIELD,
            prepared,
            record_type: ATTACHMENT_UPLOAD_RECORD_TYPE,
        };
        let uploaded = container
            .upload_single_prepared_asset_once_with_identity(
                &session,
                &zone,
                upload,
                request_identity,
                prepared_authentication,
                &retry_policy,
            )
            .await;
        // Revalidate the exact writer binding after crossing the remote
        // submission boundary. Drift here cannot prove the bytes did not
        // land, so retain the attempt rather than treating it as a rejection.
        let binding_still_exact = Arc::ptr_eq(&container, &writer_binding.container)
            && client
                .validate_writer_preparation_binding(writer_binding)
                .await
                .is_ok();
        if !binding_still_exact {
            warn!("Attachment native upload binding drifted after submission (result=unknown)");
        }
        match uploaded {
            Ok(asset) if binding_still_exact => Ok(CloudAttachmentNativeUploadOutcome {
                local_operation_id,
                apple_operation_uuid,
                result: CloudAttachmentNativeUploadResult::Uploaded(asset),
            }),
            Ok(_) => Ok(CloudAttachmentNativeUploadOutcome {
                local_operation_id,
                apple_operation_uuid,
                result: CloudAttachmentNativeUploadResult::UnknownOutcome {
                    failure_class: Some(CloudKitFailureClass::Unknown),
                    retry_after: None,
                },
            }),
            Err(failure) => {
                let mut outcome = map_native_upload_request_failure(
                    local_operation_id,
                    apple_operation_uuid,
                    &expected_request_identity,
                    failure,
                );
                if !binding_still_exact {
                    outcome.result = CloudAttachmentNativeUploadResult::UnknownOutcome {
                        failure_class: Some(CloudKitFailureClass::Unknown),
                        retry_after: None,
                    };
                }
                Ok(outcome)
            }
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

    fn native_upload_input() -> CloudAttachmentNativeUploadInput<Cursor<Vec<u8>>> {
        CloudAttachmentNativeUploadInput {
            local_operation_id: "local-native-upload".to_owned(),
            server_record_name: RECORD.to_owned(),
            apple_operation_uuid: OPERATION.to_owned(),
            prepared: PreparedPut {
                total_sig: vec![7; 21],
                chunk_sigs: vec![],
                total_len: 3,
                ford_key: None,
                ford: None,
            },
            reader: Cursor::new(vec![1, 2, 3]),
        }
    }

    #[test]
    fn native_upload_input_requires_exact_identity_and_persisted_shape() {
        validate_native_upload_input(&native_upload_input(), &identity()).unwrap();
        // The Apple operation UUID must equal the single preallocated identity slot.
        let mut wrong_operation = native_upload_input();
        wrong_operation.apple_operation_uuid = REQUEST.to_owned();
        assert!(validate_native_upload_input(&wrong_operation, &identity()).is_err());
        // The request UUID must never double as the operation UUID.
        let conflated =
            CloudKitRequestIdentity::new(OPERATION.to_owned(), vec![OPERATION.to_owned()]).unwrap();
        assert!(validate_native_upload_input(&native_upload_input(), &conflated).is_err());
        // Record names must stay allocated UUIDs; local ids must stay present.
        let mut bad_record = native_upload_input();
        bad_record.server_record_name = "not-a-uuid".to_owned();
        assert!(validate_native_upload_input(&bad_record, &identity()).is_err());
        let mut bad_local = native_upload_input();
        bad_local.local_operation_id.clear();
        assert!(validate_native_upload_input(&bad_local, &identity()).is_err());
        // The persisted PreparedPut must be present and length-bounded.
        let mut bad_sig = native_upload_input();
        bad_sig.prepared.total_sig.clear();
        assert!(validate_native_upload_input(&bad_sig, &identity()).is_err());
        let mut bad_len = native_upload_input();
        bad_len.prepared.total_len = usize::MAX;
        assert!(validate_native_upload_input(&bad_len, &identity()).is_err());
    }

    #[test]
    fn native_upload_failure_mapping_preserves_correlation_without_raw_payload() {
        let failure = |committed: bool| CloudKitRequestFailure {
            error: PushError::BadMsg,
            retry_after: Some(Duration::from_secs(7)),
            failure_class: Some(CloudKitFailureClass::Throttled),
            request_identity: Some(identity()),
            outcome_may_be_committed: committed,
        };
        let clean = map_native_upload_request_failure(
            "local-native-upload".to_owned(),
            OPERATION.to_owned(),
            &identity(),
            failure(false),
        );
        assert_eq!(clean.local_operation_id, "local-native-upload");
        assert_eq!(clean.apple_operation_uuid, OPERATION);
        assert!(matches!(
            clean.result,
            CloudAttachmentNativeUploadResult::Failed {
                failure_class: Some(CloudKitFailureClass::Throttled),
                retry_after: Some(_),
            }
        ));
        // Anything past the submission boundary reconciles instead of failing typed.
        let ambiguous = map_native_upload_request_failure(
            "local-native-upload".to_owned(),
            OPERATION.to_owned(),
            &identity(),
            failure(true),
        );
        assert!(matches!(
            ambiguous.result,
            CloudAttachmentNativeUploadResult::UnknownOutcome { .. }
        ));
        // A response that cannot be tied to the preallocated identity is never
        // a typed rejection, even for an otherwise clean failure.
        let stray_identity =
            CloudKitRequestIdentity::new(REQUEST.to_owned(), vec![REQUEST.to_owned()]).unwrap();
        let mut stray = failure(false);
        stray.request_identity = Some(stray_identity);
        let stray_outcome = map_native_upload_request_failure(
            "local-native-upload".to_owned(),
            OPERATION.to_owned(),
            &identity(),
            stray,
        );
        assert!(matches!(
            stray_outcome.result,
            CloudAttachmentNativeUploadResult::UnknownOutcome { .. }
        ));
    }

    #[test]
    fn native_upload_lane_wiring_is_single_use_bounded_and_record_free() {
        let source = include_str!("attachment_create.rs");
        // Prepare mirrors the save-submission owner shape: exact writer
        // binding in, cached exact zone only, prepared auth, single attempt.
        let prepare_start = source
            .find("pub async fn prepare_attachment_native_upload_submission")
            .expect("native upload prepare");
        let consume_start = source
            .find("pub async fn consume_once")
            .expect("native upload consume");
        let prepare = &source[prepare_start..consume_start];
        assert!(prepare.contains("get_writer_container_for_binding"));
        assert_eq!(
            prepare.matches("get_writer_container_for_binding").count(),
            2
        );
        assert!(prepare.contains(".get_cached_zone_encryption_config_exact(&zone)"));
        assert!(!prepare.contains("SaveRecordOperation"));
        assert!(!prepare.contains("create_zone"));
        assert!(prepare.contains("prepare_operations_authentication"));
        assert!(prepare.contains("max_attempts: 1"));
        // Consume takes the owner by value (single consumption), authorizes
        // through the no-replay one-shot primitive, and revalidates the
        // exact writer binding after the result without creating a record.
        let test_start = source.find("#[cfg(test)]").expect("test module");
        let consume = &source[consume_start..test_start];
        assert!(consume.contains("self,"));
        assert!(!consume.contains("&self"));
        assert!(consume.contains("upload_single_prepared_asset_once_with_identity"));
        assert!(consume.contains("validate_writer_preparation_binding"));
        assert!(consume.contains("map_native_upload_request_failure"));
        assert!(!consume.contains("SaveRecordOperation"));
        assert!(!consume.contains("perform_operations_detailed("));
        // The owner itself is not Clone: single consumption is structural.
        let owner = source
            .find("pub struct CloudMessagesPreparedUploadSubmission")
            .expect("upload owner");
        assert!(!source[owner.saturating_sub(256)..owner].contains("Clone"));
        // The native one-shot upload authorizes with the preallocated
        // identity only: no fresh identities, bounded single attempt, same
        // authorize-body/PUT pieces as the legacy upload, exact single asset.
        let cloudkit = include_str!("../../icloud/cloudkit.rs");
        let method_start = cloudkit
            .find("pub async fn upload_single_prepared_asset_once_with_identity")
            .expect("one-shot upload");
        let method_end = cloudkit[method_start..]
            .find("fn validate_cloudkit_upload_requests")
            .map(|offset| method_start + offset)
            .unwrap_or(cloudkit.len());
        let method = &cloudkit[method_start..method_end];
        assert!(method.contains("perform_operations_detailed_once_with_identity"));
        assert!(!method.contains("CloudKitRequestIdentity::generated"));
        assert!(method.contains("max_attempts != 1"));
        assert!(method.contains("put_authorize_body"));
        assert!(method.contains("put_mmcs"));
        assert!(method.contains("completed_cloudkit_upload_assets"));
        assert!(method.contains("outcome_may_be_committed"));
        // The byte window is bounded through the dedicated clamp (covered
        // behaviorally in cloudkit_upload_integrity_tests), and the lane has
        // no generic perform() fallback: only the identified one-shot primitive.
        assert!(method.contains("bounded_upload_bytes_timeout"));
        assert!(!method.contains(".perform("));
        assert!(!method.contains("perform_operations("));
    }
}
