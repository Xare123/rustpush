//! Create-only direct-chat operations. This is a native primitive, not upload
//! admission: the caller must persist one immutable payload/record name, prove
//! there is no existing chat owner, and retain an unknown outcome for lookup.
//! The app does not expose this lane until that durable orchestration is wired.

use super::*;

const CHAT_CREATE_ZONE: &str = "chatManateeZone";

/// Native-only correlation and payload. Never generate a replacement record
/// name in prepare/retry; it must come from the original durable envelope.
pub struct CloudChatSaveInput {
    pub local_operation_id: String,
    pub server_record_name: String,
    pub apple_operation_uuid: String,
    pub chat: CloudChat,
}

/// Only an exact, etag-bearing record can be Found. NotFound is restricted to
/// Apple's explicit per-record result, never a transport/auth/PCS failure.
pub enum CloudChatRecordLookup {
    Found(CloudChat, CloudMessagesSaveReceipt),
    NotFound,
    Unresolved {
        failure_class: Option<CloudKitFailureClass>,
        retry_after: Option<Duration>,
    },
}

impl Debug for CloudChatRecordLookup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Found(..) => "CloudChatRecordLookup::Found(redacted)",
            Self::NotFound => "CloudChatRecordLookup::NotFound",
            Self::Unresolved { .. } => "CloudChatRecordLookup::Unresolved",
        })
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}

fn valid_allocated_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.get_version() == Some(uuid::Version::Random))
}

/// First-create scope is a one-to-one iMessage chat with no group assets.
/// This validates wire identity only. Account/alias ownership remains the
/// responsibility of the protected admission and canonical projection gates.
pub fn validate_direct_chat_create(chat: &CloudChat) -> Result<(), PushError> {
    if chat.style != 45
        || chat.service_name != "iMessage"
        || chat.state != 3
        || chat.successful_query != 1
        || chat.is_filtered != 0
        || !valid_identifier(&chat.chat_identifier)
        || !valid_identifier(&chat.last_addressed_handle)
        || chat.guid != format!("iMessage;-;{}", chat.chat_identifier)
        || chat.participants.len() != 1
        || chat.participants[0].uri != chat.chat_identifier
        || !valid_allocated_uuid(&chat.group_id)
        || chat.group_id != chat.original_group_id
        || chat.last_read_message_timestamp < 0
        || chat.display_name.is_some()
        || chat.group_photo.is_some()
        || chat.group_photo_guid.is_some()
        || chat.properties.as_ref().is_some_and(|properties| {
            properties.should_force_to_sms == Some(true)
                || !properties.legacy_group_identifiers.is_empty()
                || properties.group_photo_guid.is_some()
        })
    {
        return Err(PushError::BadMsg);
    }
    Ok(())
}

fn validate_chat_input(
    input: &CloudChatSaveInput,
    request_identity: &CloudKitRequestIdentity,
) -> Result<(), PushError> {
    // Deliberately one chat, not a cross-zone batch or a generic update lane.
    if !valid_identifier(&input.local_operation_id)
        || !valid_allocated_uuid(&input.server_record_name)
        || request_identity.operation_uuids() != [input.apple_operation_uuid.clone()]
        || request_identity.http_request_uuid() == input.apple_operation_uuid
    {
        return Err(PushError::BadMsg);
    }
    validate_direct_chat_create(&input.chat)
}

fn build_chat_create_operation(
    zone: RecordZoneIdentifier,
    input: CloudChatSaveInput,
    key: &crate::cloudkit::PCSZoneConfig,
) -> Result<SaveRecordOperation, PushError> {
    if zone.value.as_ref().and_then(|value| value.name.as_deref()) != Some(CHAT_CREATE_ZONE)
        || !key.matches_zone(&zone)
    {
        return Err(PushError::BadMsg);
    }
    SaveRecordOperation::try_new(
        record_identifier(zone, &input.server_record_name),
        input.chat,
        Some(key),
        CloudMessagesSaveMode::CreateOnly.update_flag(),
    )
}

impl<P: AnisetteProvider> CloudMessagesClient<P> {
    /// Authentication/key lookup only. A missing zone must fail, not create a
    /// new PCS zone or borrow the restored read-authentication container.
    pub async fn warm_chat_writer_preparation_lookup_only(
        &self,
    ) -> Result<CloudMessagesWriterPreparationBinding<P>, PushError> {
        let container = self.get_container().await?;
        let zone = container.private_zone(CHAT_CREATE_ZONE.to_owned());
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

    /// Prepare one create with the same single-use/no-replay owner as message
    /// creates. The exact general container and chat PCS key must be warm.
    /// No remote RecordSave occurs until the caller consumes the owner.
    pub async fn prepare_chat_save_submission(
        &self,
        writer_binding: &CloudMessagesWriterPreparationBinding<P>,
        input: CloudChatSaveInput,
        request_identity: CloudKitRequestIdentity,
        request_timeout: Duration,
    ) -> Result<CloudMessagesPreparedSaveSubmission<P>, PushError> {
        with_cloudkit_writer_operation(async move {
            if request_timeout.is_zero() || request_timeout > Duration::from_secs(5 * 60) {
                return Err(PushError::BadMsg);
            }
            validate_chat_input(&input, &request_identity)?;
            let container = self
                .get_writer_container_for_binding(writer_binding)
                .await?;
            let zone = container.private_zone(CHAT_CREATE_ZONE.to_owned());
            let key = container
                .get_cached_zone_encryption_config_exact(&zone)
                .await?;
            let local_operation_id = input.local_operation_id.clone();
            let operation = build_chat_create_operation(zone, input, &key)?;
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

    /// Reconcile the original random record name; never allocate another one
    /// after a timeout. An unresolved lookup must not authorize resubmission.
    pub async fn lookup_chat_record(
        &self,
        writer_binding: &CloudMessagesWriterPreparationBinding<P>,
        server_record_name: &str,
    ) -> Result<CloudChatRecordLookup, PushError> {
        if !valid_allocated_uuid(server_record_name) {
            return Err(PushError::BadMsg);
        }
        let container = self
            .get_writer_container_for_binding(writer_binding)
            .await?;
        let zone = container.private_zone(CHAT_CREATE_ZONE.to_owned());
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
                return Ok(CloudChatRecordLookup::Unresolved {
                    failure_class: failure.failure_class,
                    retry_after: failure.retry_after,
                })
            }
        };
        if response.outcomes.len() != 1 {
            return Ok(CloudChatRecordLookup::Unresolved {
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
                // Type validation must precede the generated CloudChat decoder.
                if raw.r#type.as_ref().and_then(|kind| kind.name.as_deref())
                    != Some(CloudChat::record_type())
                {
                    return Err(PushError::BadMsg);
                }
                let Some(receipt) = CloudMessagesSaveReceipt::validate(Some(&expected), Some(raw))
                else {
                    return Ok(CloudChatRecordLookup::Unresolved {
                        failure_class: Some(CloudKitFailureClass::Unknown),
                        retry_after: None,
                    });
                };
                let decryptor = pcs_keys_for_record(raw, &key)?;
                let chat =
                    CloudChat::try_from_record_encrypted(&raw.record_field, Some(&decryptor))
                        .map_err(|_| PushError::BadMsg)?;
                Ok(CloudChatRecordLookup::Found(chat, receipt))
            }
            Err(error) if is_cloudkit_record_not_found(&error) => {
                Ok(CloudChatRecordLookup::NotFound)
            }
            Err(_) => Ok(CloudChatRecordLookup::Unresolved {
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

    fn input() -> CloudChatSaveInput {
        CloudChatSaveInput {
            local_operation_id: "local-chat-operation".to_owned(),
            server_record_name: RECORD.to_owned(),
            apple_operation_uuid: OPERATION.to_owned(),
            chat: CloudChat {
                style: 45,
                successful_query: 1,
                state: 3,
                chat_identifier: "recipient@example.invalid".to_owned(),
                guid: "iMessage;-;recipient@example.invalid".to_owned(),
                group_id: RECORD.to_owned(),
                original_group_id: RECORD.to_owned(),
                service_name: "iMessage".to_owned(),
                last_addressed_handle: "sender@example.invalid".to_owned(),
                participants: vec![CloudParticipant {
                    uri: "recipient@example.invalid".to_owned(),
                }],
                ..Default::default()
            },
        }
    }

    fn identity() -> CloudKitRequestIdentity {
        CloudKitRequestIdentity::new(REQUEST.to_owned(), vec![OPERATION.to_owned()]).unwrap()
    }

    #[test]
    fn direct_chat_create_requires_exact_canonical_identity() {
        validate_chat_input(&input(), &identity()).unwrap();
        let changes: &[fn(&mut CloudChat)] = &[
            |c| c.style = 43,
            |c| c.service_name = "SMS".to_owned(),
            |c| c.state = 0,
            |c| c.guid = RECORD.to_owned(),
            |c| c.chat_identifier = "another@example.invalid".to_owned(),
            |c| c.participants.clear(),
            |c| c.participants.push(c.participants[0].clone()),
            |c| c.last_addressed_handle.clear(),
            |c| c.original_group_id = REQUEST.to_owned(),
            |c| c.group_id = "not-a-uuid".to_owned(),
            |c| c.last_read_message_timestamp = -1,
            |c| c.display_name = Some("Group".to_owned()),
            |c| c.group_photo_guid = Some(RECORD.to_owned()),
            |c| c.group_photo = Some(Asset::default()),
            |c| {
                c.properties = Some(CloudProp {
                    should_force_to_sms: Some(true),
                    ..Default::default()
                })
            },
        ];
        for change in changes {
            let mut candidate = input();
            change(&mut candidate.chat);
            assert!(validate_chat_input(&candidate, &identity()).is_err());
        }
    }

    #[test]
    fn chat_create_requires_one_exact_persisted_operation_and_record() {
        let mut candidate = input();
        candidate.apple_operation_uuid = REQUEST.to_owned();
        assert!(validate_chat_input(&candidate, &identity()).is_err());
        candidate = input();
        candidate.server_record_name = "not-a-record-uuid".to_owned();
        assert!(validate_chat_input(&candidate, &identity()).is_err());
        candidate = input();
        candidate.local_operation_id.clear();
        assert!(validate_chat_input(&candidate, &identity()).is_err());
        let extra = CloudKitRequestIdentity::new(
            REQUEST.to_owned(),
            vec![OPERATION.to_owned(), RECORD.to_owned()],
        )
        .unwrap();
        assert!(validate_chat_input(&input(), &extra).is_err());
    }

    #[test]
    fn chat_create_refuses_missing_pcs_material_and_wrong_zone() {
        let zone = RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(CHAT_CREATE_ZONE.to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let key = crate::cloudkit::PCSZoneConfig::with_record_keys_for_test(zone.clone(), vec![]);
        assert!(build_chat_create_operation(zone.clone(), input(), &key).is_err());
        let mut wrong = zone;
        wrong.value.as_mut().unwrap().name = Some("messageManateeZone".to_owned());
        assert!(build_chat_create_operation(wrong, input(), &key).is_err());
    }

    #[test]
    fn chat_create_wire_is_create_only_and_pcs_round_trips_exact_identity() {
        let zone = RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(CHAT_CREATE_ZONE.to_owned()),
                r#type: Some(cloudkit_proto::identifier::Type::RecordZone as i32),
            }),
            owner_identifier: Some(cloudkit_proto::Identifier {
                name: Some("fixture-owner".to_owned()),
                r#type: Some(cloudkit_proto::identifier::Type::User as i32),
            }),
            ..Default::default()
        };
        let record_keys = vec![PCSKey::random()];
        let key = crate::cloudkit::PCSZoneConfig::with_record_keys_for_test(
            zone.clone(),
            record_keys.clone(),
        );
        let mut wrong_owner = zone.clone();
        wrong_owner.owner_identifier.as_mut().unwrap().name = Some("other-owner".to_owned());
        assert!(!key.matches_zone(&wrong_owner));
        assert!(build_chat_create_operation(wrong_owner, input(), &key).is_err());
        let operation = build_chat_create_operation(zone.clone(), input(), &key).unwrap();
        assert_eq!(operation.0.save_semantics, Some(2));
        let record = operation.0.record.unwrap();
        let identifier = record_identifier(zone, RECORD);
        assert_eq!(record.record_identifier.as_ref(), Some(&identifier));
        assert_eq!(
            record.r#type.as_ref().unwrap().name.as_deref(),
            Some("chatEncryptedv2")
        );
        let decoded = CloudChat::from_record_encrypted(
            &record.record_field,
            Some(&crate::pcs::PCSEncryptor {
                keys: record_keys,
                record_id: identifier,
            }),
        );
        assert_eq!(decoded.guid, input().chat.guid);
        assert_eq!(decoded.chat_identifier, input().chat.chat_identifier);
        assert_eq!(
            decoded.participants[0].uri,
            input().chat.participants[0].uri
        );
        assert_eq!(decoded.group_id, input().chat.group_id);
        assert_eq!(decoded.original_group_id, input().chat.original_group_id);
    }

    #[test]
    fn native_chat_create_has_no_legacy_update_or_zone_provisioning_path() {
        let source = include_str!("chat_create.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("CloudMessagesSaveMode::CreateOnly.update_flag()"));
        assert!(production.contains("max_attempts: 1"));
        assert!(production.contains("get_cached_zone_encryption_config_exact"));
        assert!(production.contains("get_zone_encryption_config_lookup_only"));
        for forbidden in [
            "save_chats(",
            "save_records(",
            "ZoneSaveOperation",
            "DeleteRecordOperation",
            "get_zone_encryption_config(",
            "get_read_authentication_container",
            "Uuid::new_v4",
            "info!(",
            "debug!(",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected chat-create primitive: {forbidden}"
            );
        }
    }
}
