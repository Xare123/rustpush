use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::Cursor,
    ops::Deref,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::KeyInit;
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use base64::engine::general_purpose;
use base64::Engine;
use facetimep::{
    ConversationInvitationPreference, ConversationLink, ConversationLinkLifetimeScope,
    ConversationMember, ConversationMessage, ConversationMessageType, ConversationParticipant,
    ConversationParticipantDidJoinContext, ConversationReport, EncryptedConversationMessage,
    Handle, HandleType,
};
use hkdf::Hkdf;
use log::{debug, info, warn};
use openssl::{
    derive::Deriver,
    pkey::Private,
    sha::sha1,
    symm::{decrypt, Cipher},
};
use plist::{Data, Dictionary, Value};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    aps::{get_message, APSInterestToken},
    ids::{
        identity_manager::{IDSQuickRelaySettings, IDSSendMessage, IdentityResource, Raw},
        user::{IDSService, QueryOptions},
        IDSRecvMessage,
    },
    util::{
        base64_decode, base64_encode, duration_since_epoch, ec_deserialize_priv_compact,
        ec_serialize_priv, plist_to_bin, proto_deserialize_opt, proto_serialize_opt, CompactECKey,
        DebugMutex, DebugRwLock,
    },
    APSConnection, APSMessage, IdentityManager, MessageTarget, OSConfig, PushError,
};

pub mod facetimep {
    include!(concat!(env!("OUT_DIR"), "/facetimep.rs"));
}

const FACETIME_VIDEO_AV_MODE: i32 = 2;

fn apply_conversation_message_metadata(
    session: &mut FTSession,
    message: Option<&ConversationMessage>,
) -> ConversationMessageType {
    let Some(message) = message else {
        return ConversationMessageType::Unknown;
    };

    if let Some(link) = &message.link {
        session.link = Some(link.clone());
    }

    if let Some(report) = &message.report_data {
        session.report_id = report.conversation_id.clone();
        session.start_time =
            Some((UNIX_TO_2001 + Duration::from_secs_f64(report.timebase)).as_millis() as u64);
    }

    message.r#type()
}

fn configure_video_invitation(
    message: &mut ConversationMessage,
    context: &mut ConversationParticipantDidJoinContext,
) {
    message.av_mode = Some(FACETIME_VIDEO_AV_MODE);
    context.video = Some(true);
    context.video_enabled = Some(true);
    context.av_mode = Some(FACETIME_VIDEO_AV_MODE as u32);
}

pub const FACETIME_SERVICE: IDSService = IDSService {
    name: "com.apple.private.alloy.facetime.multi",
    sub_services: &[],
    client_data: &[
        ("show-peer-errors", Value::Boolean(true)),
        ("supports-avless", Value::Boolean(true)),
        ("supports-co", Value::Boolean(true)),
        ("supports-gft-calls", Value::Boolean(true)),
        ("supports-gft-errors", Value::Boolean(true)),
        ("supports-modern-gft", Value::Boolean(true)),
        ("supports-self-one-to-one-invites", Value::Boolean(true)),
    ],
    flags: 1,
    capabilities_name: "Invitation",
};

pub const VIDEO_SERVICE: IDSService = IDSService {
    name: "com.apple.ess",
    sub_services: &[
        "com.apple.private.alloy.facetime.lp",
        "com.apple.private.alloy.facetime.mw",
        "com.apple.private.alloy.facetime.video",
    ],
    client_data: &[
        ("show-peer-errors", Value::Boolean(true)),
        ("supports-gft-errors", Value::Boolean(true)),
        ("supports-live-delivery", Value::Boolean(true)),
    ],
    flags: 1,
    capabilities_name: "Invitation",
};

fn handle_from_ids(ids: &str) -> facetimep::Handle {
    let mut handle = facetimep::Handle::default();
    if ids.starts_with("mailto:") {
        handle.set_type(HandleType::EmailAddress);
        handle.value = ids.replacen("mailto:", "", 1);
    } else if ids.starts_with("tel:") {
        handle.set_type(HandleType::PhoneNumber);
        handle.value = ids.replacen("tel:", "", 1);
        // other countries? use whatsapp
        handle.iso_country_code = "us".to_string();
    } else if ids.starts_with("temp:") {
        handle.set_type(HandleType::Generic);
        handle.value = ids.to_string();
    }
    handle
}

fn handle_to_ids(handle: &Handle) -> String {
    match handle.r#type() {
        HandleType::EmailAddress => format!("mailto:{}", handle.value),
        HandleType::Generic => handle.value.clone(),
        HandleType::PhoneNumber => format!("tel:{}", handle.value),
        HandleType::None => "NONETYPEHANDLE".to_string(),
    }
}

fn canonicalize_ids_handle(handle: &str) -> String {
    if handle.starts_with("mailto:") || handle.starts_with("tel:") || handle.starts_with("temp:") {
        return handle.to_owned();
    }
    if handle.contains('@') {
        return format!("mailto:{handle}");
    }
    if handle.starts_with('+')
        || (!handle.is_empty() && handle.chars().all(|character| character.is_ascii_digit()))
    {
        return format!("tel:{handle}");
    }
    handle.to_owned()
}

const NONCE_COUNT: usize = 12;

#[derive(Serialize, Deserialize)]
pub struct FTLink {
    #[serde(
        serialize_with = "ec_serialize_priv",
        deserialize_with = "ec_deserialize_priv_compact"
    )]
    pub key: CompactECKey<Private>,
    pub pseud: String,
    pub handle: String,
    pub session_link: Option<String>,
    pub creation_time: f64, // ms since epoch
    pub expiry_time: f64,
    // purely for my bookkeeping
    pub usage: Option<String>,
}

impl FTLink {
    pub fn get_link(&self) -> Result<String, PushError> {
        let public = self.key.compress();
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&public);

        Ok(format!(
            "https://facetime.apple.com/join#v=1&p={}&k={}",
            &self.pseud[6..],
            encoded
        ))
    }

    pub fn is_expired(&self) -> bool {
        self.expiry_time < duration_since_epoch().as_secs_f64()
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct FTParticipant {
    pub token: Option<String>,
    pub handle: String,
    pub participant_id: u64,
    pub last_join_date: Option<u64>, // ms since epoch
    #[serde(
        default,
        serialize_with = "proto_serialize_opt",
        deserialize_with = "proto_deserialize_opt"
    )]
    pub active: Option<ConversationParticipant>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub struct FTMember {
    pub nickname: Option<String>,
    pub handle: String,
}

impl FTMember {
    fn to_conversation(&self) -> ConversationMember {
        ConversationMember {
            version: 0,
            handle: Some(handle_from_ids(&self.handle)),
            nickname: self.nickname.clone(),
            lightweight_primary: None,
            lightweight_primary_participant_id: 0,
            validation_source: 0,
        }
    }
}

fn send_for_message(
    sender: String,
    message: ConversationMessage,
    context: Option<u64>,
) -> IDSSendMessage {
    IDSSendMessage {
        sender,
        raw: Raw::Body(message.encode_to_vec()),
        send_delivered: false,
        command: 242,
        no_response: false,
        id: Uuid::new_v4().to_string().to_uppercase(),
        scheduled_ms: None,
        queue_id: None,
        relay: None,
        extras: Default::default(),
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum FTMode {
    Outgoing,
    Incoming,
    Missed,
    MissedOutgoing,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct FTSession {
    pub group_id: String,
    pub my_handles: Vec<String>,
    pub participants: HashMap<String /* participant ID */, FTParticipant>,
    #[serde(
        default,
        serialize_with = "proto_serialize_opt",
        deserialize_with = "proto_deserialize_opt"
    )]
    pub link: Option<ConversationLink>,
    pub members: HashSet<FTMember>,
    pub report_id: String, // this is different from group_id because we are thinking different
    pub start_time: Option<u64>, // ms since epoch
    pub last_rekey: Option<u64>, // ms since epoch
    #[serde(skip)]
    pub is_propped: bool,
    // WARNING: this value may not accurately represent state. It's just used as a temporary store to see if we need to prop it up
    // also represents ringing from other (our) devices
    #[serde(skip)]
    pub is_ringing_inaccurate: bool,
    pub mode: Option<FTMode>,
    #[serde(skip)]
    pub recent_member_adds: HashMap<String, u64>,
}

// time to track recently added members
const RECENT_MEMBER_TRACK_TIME: Duration = Duration::from_secs(15);

impl FTSession {
    fn prune_recent_members(&mut self) {
        let sweep_time = duration_since_epoch();
        self.recent_member_adds
            .retain(|_, ms| Duration::from_millis(*ms) + RECENT_MEMBER_TRACK_TIME > sweep_time);
    }

    // returns recently added members that were excluded from this message
    // so the caller knows who may have been cut off from a state change
    fn unpack_members(&mut self, members: &[ConversationMember]) -> Vec<FTMember> {
        self.prune_recent_members();

        // Apple can send a partial participant-state update with no member
        // snapshot. A missing/empty snapshot is not proof that every member
        // left; explicit RemoveMember and command 208 events own removal.
        if members.is_empty() {
            return Vec::new();
        }

        let stand_up_for = self
            .members
            .iter()
            .filter(|a| {
                self.recent_member_adds.contains_key(&a.handle)
                    && !members
                        .iter()
                        .any(|i| handle_to_ids(i.handle.as_ref().expect("No handle?")) == a.handle)
            })
            .cloned()
            .collect::<Vec<_>>();

        // Participant-state payloads can be partial subsets. Merge what was
        // observed and let typed RemoveMember messages own member deletion.
        self.new_members(&members);
        stand_up_for
    }

    fn get_participant(&self, token: [u8; 32]) -> Option<&FTParticipant> {
        let base64_encoded = Some(base64_encode(&token));
        self.participants
            .values()
            .find(|p| &p.token == &base64_encoded)
    }

    fn get_report(&self) -> ConversationReport {
        ConversationReport {
            conversation_id: self.report_id.clone(),
            timebase: (Duration::from_millis(self.start_time.expect("Bad state!")) - UNIX_TO_2001)
                .as_secs_f64(),
        }
    }

    fn new_members(&mut self, members: &[ConversationMember]) -> HashSet<FTMember> {
        let mut new_items: HashSet<FTMember> = members
            .iter()
            .map(|a| FTMember {
                nickname: a.nickname.clone(),
                handle: handle_to_ids(a.handle.as_ref().expect("No handle?")),
            })
            .collect();
        new_items.retain(|i| !self.members.contains(i));
        self.members.extend(new_items.clone());
        new_items
    }

    fn remove_members(&mut self, members: &[ConversationMember]) -> HashSet<FTMember> {
        let mut removed_members: HashSet<FTMember> = members
            .iter()
            .map(|a| FTMember {
                nickname: a.nickname.clone(),
                handle: handle_to_ids(a.handle.as_ref().expect("No handle?")),
            })
            .collect();
        removed_members.retain(|i| self.members.contains(i));
        self.members.retain(|i| !removed_members.contains(i));
        removed_members
    }

    fn unpack_participants(&mut self, participants: &[ConversationParticipant], token: &[u8]) {
        // An empty partial snapshot is not a definitive all-participants-left
        // signal. Command 208 is the authoritative participant leave event.
        if participants.is_empty() {
            return;
        }
        // A non-empty participant list may still be a partial subset. Merge
        // listed participants and let command 208 own active-state removal.
        for participant in participants {
            let ftparticipant = self
                .participants
                .entry(participant.identifier.to_string())
                .or_default();
            ftparticipant.handle = handle_to_ids(participant.handle.as_ref().expect("No handle?"));
            ftparticipant.participant_id = participant.identifier;
            // don't let other participants tell us whether we are active or not
            if Some(base64_encode(&token)) != ftparticipant.token {
                ftparticipant.active = Some(participant.clone());
            }
        }
    }

    fn apply_participant_join(
        &mut self,
        participant: ParticipantID,
        token: &[u8],
        sender: &str,
        avc_data: Vec<u8>,
        context: &ConversationParticipantDidJoinContext,
        joined_ms: u64,
    ) -> ConversationMessageType {
        let message = context.message.as_ref();
        let message_type = apply_conversation_message_metadata(self, message);

        self.is_ringing_inaccurate = message_type == ConversationMessageType::Invitation;
        self.unpack_members(&context.members);
        let sender = canonicalize_ids_handle(sender);
        self.participants.insert(
            participant.to_string(),
            FTParticipant {
                token: Some(base64_encode(token)),
                participant_id: participant.into(),
                last_join_date: Some(joined_ms),
                handle: sender.clone(),
                active: Some(ConversationParticipant {
                    version: context.version,
                    identifier: participant.into(),
                    handle: Some(handle_from_ids(&sender)),
                    avc_data,
                    is_moments_available: Some(context.is_moments_available),
                    is_screen_sharing_available: Some(context.is_screen_sharing_available),
                    is_gondola_calling_available: Some(context.is_gondola_calling_available),
                    is_mirage_available: Some(context.is_mirage_available),
                    is_lightweight: Some(context.is_lightweight),
                    share_play_protocol_version: context.share_play_protocol_version,
                    options: 0,
                    is_gft_downgrade_to_one_to_one_available: context
                        .is_gft_downgrade_to_one_to_one_available,
                    guest_mode_enabled: message.map(|value| value.guest_mode_enabled),
                    association: context.participant_association.clone(),
                    is_u_plus_n_downgrade_available: context.is_u_plus_n_downgrade_available,
                }),
            },
        );

        message_type
    }

    fn apply_participant_join_wire(
        &mut self,
        participant: ParticipantID,
        token: &[u8],
        sender: &str,
        avc_data: Option<Data>,
        context: Option<Data>,
        joined_ms: u64,
    ) -> Result<Option<ParticipantJoinOutcome>, PushError> {
        let Some(context) = context else {
            return Ok(None);
        };
        let decoded_context =
            ConversationParticipantDidJoinContext::decode(&mut Cursor::new(context))?;
        let nested_message = decoded_context.message.is_some();
        let message_type = self.apply_participant_join(
            participant,
            token,
            sender,
            avc_data.map_or_else(Vec::new, Into::into),
            &decoded_context,
            joined_ms,
        );
        Ok(Some(ParticipantJoinOutcome {
            message_type,
            nested_message,
        }))
    }

    fn resolve_participant_leave_id(
        &self,
        announced: ParticipantID,
        uri_map: Option<&HashMap<String, Vec<ParticipantID>>>,
    ) -> ParticipantID {
        if self.participants.contains_key(&announced.to_string()) {
            return announced;
        }
        let Some((handle, _)) = uri_map.and_then(|map| {
            map.iter().find(|(_, ids)| {
                ids.iter()
                    .any(|candidate| candidate.to_string() == announced.to_string())
            })
        }) else {
            return announced;
        };
        let canonical_handle = canonicalize_ids_handle(handle);
        self.participants
            .values()
            .find(|participant| participant.handle == canonical_handle)
            .map(|participant| ParticipantID::Unsigned(participant.participant_id))
            .unwrap_or(announced)
    }

    fn apply_participant_leave(
        &mut self,
        participant: ParticipantID,
        event_ms: u64,
    ) -> ParticipantLeaveOutcome {
        let key = participant.to_string();
        let Some(current) = self.participants.get_mut(&key) else {
            return ParticipantLeaveOutcome::Unknown;
        };
        if current
            .last_join_date
            .is_some_and(|last_join_date| event_ms < last_join_date)
        {
            return ParticipantLeaveOutcome::Stale;
        }

        current.active = None;
        let handle = current.handle.clone();
        if handle.starts_with("temp:") {
            self.members.retain(|member| member.handle != handle);
            self.participants.remove(&key);
        }

        ParticipantLeaveOutcome::Applied {
            handle,
            no_active_participants: self
                .participants
                .values()
                .all(|participant| participant.active.is_none()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ParticipantLeaveOutcome {
    Unknown,
    Stale,
    Applied {
        handle: String,
        no_active_participants: bool,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct ParticipantJoinOutcome {
    message_type: ConversationMessageType,
    nested_message: bool,
}

const UNIX_TO_2001: Duration = Duration::from_millis(978307200000);

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(untagged)]
enum ParticipantID {
    Signed(i64),
    Unsigned(u64),
}
impl ParticipantID {
    fn encoding(self) -> &'static str {
        match self {
            Self::Signed(_) => "signed",
            Self::Unsigned(_) => "unsigned",
        }
    }
}
impl Into<u64> for ParticipantID {
    fn into(self) -> u64 {
        match self {
            Self::Signed(i) => i as u64,
            Self::Unsigned(i) => i,
        }
    }
}
impl From<u64> for ParticipantID {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

impl ToString for ParticipantID {
    fn to_string(&self) -> String {
        let num: u64 = (*self).into();
        num.to_string()
    }
}

#[derive(Clone, Debug)]
pub enum FTMessage {
    LetMeInRequest(LetMeInRequest),
    LinkChanged {
        guid: String,
    },
    JoinEvent {
        guid: String,
        participant: u64,
        handle: String,
        ring: bool,
    },
    AddMembers {
        guid: String,
        members: HashSet<FTMember>,
        ring: bool,
    },
    RemoveMembers {
        guid: String,
        members: HashSet<FTMember>,
    },
    LeaveEvent {
        guid: String,
        participant: u64,
        handle: String,
    },
    Ring {
        guid: String,
    },
    Decline {
        guid: String,
    },
    RespondedElsewhere {
        guid: String,
    },
}

#[derive(Clone, Debug)]
pub struct LetMeInRequest {
    pub shared_secret: Vec<u8>,
    pub pseud: String,
    pub requestor: String,
    pub nickname: Option<String>,
    pub token: Vec<u8>,
    pub delegation_uuid: Option<String>,
    pub usage: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct FTState {
    pub links: HashMap<String, FTLink>,
    pub sessions: HashMap<String, FTSession>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct FTWireMessage {
    #[serde(rename = "s")]
    session: String,
    #[serde(rename = "rtmpk")]
    prekey: Option<Data>,
    #[serde(rename = "rtmpwm")]
    prekey_wrap_mode: Option<u32>,
    #[serde(rename = "fanout-groupID-key")]
    fanout_groupid: String,
    client_context_data_key: Option<Data>,
    participant_data_key: Option<Data>,
    is_initiator_key: Option<bool>,
    #[serde(rename = "fanout-groupMembers-key")]
    fanout_groupmembers: Option<Vec<String>>,
    is_u_plus_one_key: Option<bool>,
    join_notification_key: Option<u32>,
    participant_id_key: Option<ParticipantID>, // also i64 sometimes?
    uri_to_participant_id_key: Option<HashMap<String, Vec<ParticipantID>>>,
}

pub struct FTClient {
    pub conn: APSConnection,
    pub identity: IdentityManager,
    os_config: Arc<dyn OSConfig>,
    _interest_token: APSInterestToken,
    pub state: DebugRwLock<FTState>,
    update_state: Box<dyn Fn(&FTState) + Send + Sync>,
    pub delegated_requests: DebugMutex<HashMap<String, LetMeInRequest>>,
}

impl FTClient {
    pub async fn new(
        state: FTState,
        update_state: Box<dyn Fn(&FTState) + Send + Sync>,
        conn: APSConnection,
        identity: IdentityManager,
        config: Arc<dyn OSConfig>,
    ) -> Self {
        let token = conn
            .request_topics(&[
                "com.apple.private.alloy.facetime.multi",
                "com.apple.private.alloy.facetime.video",
                "com.apple.private.alloy.quickrelay",
            ])
            .await;

        Self {
            _interest_token: token,
            conn,
            identity,
            os_config: config,
            state: DebugRwLock::new(state),
            update_state,
            delegated_requests: DebugMutex::new(HashMap::new()),
        }
    }

    pub async fn ensure_allocations(
        &self,
        session: &mut FTSession,
        new_members: &[FTMember],
    ) -> Result<(), PushError> {
        // ensure all members have participant entries
        let has_relay = session.members.iter().chain(new_members).all(|member| {
            session
                .participants
                .values()
                .any(|p| p.handle == member.handle)
        });
        if has_relay {
            return Ok(());
        }

        // we need to do quickrelay allocations
        let people_in_chatroom: Vec<String> = session
            .members
            .iter()
            .chain(new_members)
            .map(|m| m.handle.clone())
            .collect();
        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                &people_in_chatroom,
                &handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;

        let targets = self.identity.cache.lock().await.get_participants_targets(
            &topic,
            handle,
            &people_in_chatroom,
        );
        let receiver = self.conn.subscribe().await;
        let uuid = Uuid::new_v4();
        self.identity
            .send_message(
                topic,
                IDSSendMessage::quickrelay(
                    handle.clone(),
                    uuid,
                    IDSQuickRelaySettings {
                        reason: 0, // something along the lines of 'someone joined'
                        group_id: session.group_id.clone(),
                        request_type: 3, // allocate relay
                        member_count: people_in_chatroom.len() as u32,
                    },
                ),
                targets,
            )
            .await?;

        #[derive(Deserialize)]
        pub struct QuickRelayAllocation {
            #[serde(rename = "qri")]
            id: i64,
            #[serde(rename = "tP")]
            participant: String,
            #[serde(rename = "t")]
            token: Data,
        }

        #[derive(Deserialize)]
        pub struct QuickRelayAllocationsResponse {
            #[serde(rename = "U")]
            for_id: Data,
            #[serde(rename = "qal")]
            allocations: Vec<QuickRelayAllocation>,
        }

        let response = self
            .conn
            .wait_for_timeout(
                receiver,
                get_message(
                    |payload| {
                        info!("Got relay {:?}", payload);
                        let parsed =
                            match plist::from_value::<QuickRelayAllocationsResponse>(&payload) {
                                Ok(parsed) => parsed,
                                Err(e) => {
                                    info!("Failed to parse {e}");
                                    return None;
                                }
                            };
                        // let Ok(parsed) = plist::from_value::<QuickRelayAllocationsResponse>(&payload) else {
                        //     return None
                        // };
                        if parsed.for_id.as_ref() == uuid.as_bytes() {
                            Some(parsed)
                        } else {
                            None
                        }
                    },
                    &["com.apple.private.alloy.quickrelay"],
                ),
            )
            .await?;

        for allocation in response.allocations {
            let id = allocation.id as u64;
            let participant = session.participants.entry(id.to_string()).or_default();
            participant.handle = allocation.participant;
            participant.participant_id = id;
            participant.token = Some(base64_encode(allocation.token.as_ref()));
        }

        Ok(())
    }

    // warning: Doesn't save the link
    async fn new_link(
        &self,
        handle: &str,
        usage: Option<String>,
        supported_for: Duration,
    ) -> Result<FTLink, PushError> {
        let since_the_epoch = duration_since_epoch();

        let expiry = since_the_epoch + supported_for;

        let new_alias = self
            .identity
            .create_pseudonym(
                handle,
                "Gondola",
                [("com.apple.private.alloy.facetime.multi", vec![])]
                    .into_iter()
                    .collect(),
                expiry.as_secs_f64(),
            )
            .await?;

        info!("Creating new link using pseud {new_alias} for handle {handle} with usage {usage:?}");

        let key = CompactECKey::new()?;

        Ok(FTLink {
            key,
            pseud: new_alias.clone(),
            handle: handle.to_string(),
            session_link: None,
            creation_time: since_the_epoch.as_secs_f64(),
            expiry_time: expiry.as_secs_f64(),
            usage,
        })
    }

    pub async fn use_link_for(&self, old_usage: &str, usage: &str) -> Result<(), PushError> {
        let state = self.state.read().await;
        let Some(existing) = state
            .links
            .values()
            .find(|a| a.usage == Some(old_usage.to_string()))
        else {
            return Ok(());
        };
        let pseud = existing.pseud.clone();
        if state.links[&pseud].usage == Some(usage.to_string()) {
            return Ok(());
        }
        info!(
            "Using link {} for {usage} from {old_usage}",
            existing.handle
        );
        if let Some(link) = state
            .links
            .values()
            .find(|l| l.usage == Some(usage.to_string()))
        {
            // delete this link, no longer has a use
            let old_pseud = link.pseud.clone();
            drop(state);
            self.delete_link(&old_pseud).await?;
        } else {
            drop(state);
        }

        let mut state = self.state.write().await;
        state.links.get_mut(&pseud).expect("No link??").usage = Some(usage.to_string());
        (self.update_state)(&*state);
        Ok(())
    }

    pub async fn get_link_for_usage(&self, handle: &str, usage: &str) -> Result<String, PushError> {
        let mut state = self.state.write().await;
        state.links.retain(|_, l| !l.is_expired()); // remove expiredg links
        if let Some(link) = state
            .links
            .values()
            .find(|a| a.usage == Some(usage.to_string()))
        {
            if self
                .identity
                .validate_pseudonym(
                    "com.apple.private.alloy.facetime.multi",
                    handle,
                    &link.pseud,
                )
                .await?
            {
                return Ok(link.get_link()?);
            } else {
                warn!("Failed to validate pseudonym! {}", link.pseud);
            }
        }

        // disassociate any bad links, so we don't pull from them and we only have one link with this usage
        // we don't delete because that is too error prone, we can just let them expire instead.
        // after all, the point of this function is to get a link that works, not do pruning. (there may be many (hundreds) due past bug)
        for (_, link) in &mut state.links {
            if link.usage != Some(usage.to_string()) {
                continue;
            }
            link.usage = None;
        }

        let link_obj = self
            .new_link(
                handle,
                Some(usage.to_string()),
                Duration::from_secs(31536000), /* one year */
            )
            .await?;
        let link = link_obj.get_link()?;

        state.links.insert(link_obj.pseud.clone(), link_obj);
        (self.update_state)(&*state);

        Ok(link)
    }

    pub async fn clear_links(&self) -> Result<(), PushError> {
        self.identity
            .clear_pseudonyms(
                "Gondola",
                [("com.apple.private.alloy.facetime.multi", vec![])]
                    .into_iter()
                    .collect(),
            )
            .await?;

        let mut state = self.state.write().await;
        state.links.clear();
        (self.update_state)(&*state);
        Ok(())
    }

    pub async fn delete_link(&self, pseud: &str) -> Result<(), PushError> {
        self.identity
            .delete_pseudonym(
                "Gondola",
                [("com.apple.private.alloy.facetime.multi", vec![])]
                    .into_iter()
                    .collect(),
                pseud.to_string(),
            )
            .await?;

        let mut state = self.state.write().await;
        state.links.remove(pseud);
        (self.update_state)(&*state);
        Ok(())
    }

    pub async fn get_session_link(&self, guid: &str) -> Result<String, PushError> {
        let mut state = self.state.write().await;
        let state = &mut *state;
        let session = state.sessions.get_mut(guid).expect("No session found!");
        let my_handle = session.my_handles.first().expect("No handle").clone();
        if let Some(link) = &session.link {
            let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&link.public_key);
            return Ok(format!(
                "https://facetime.apple.com/join#v=1&p={}&k={}",
                &link.pseudonym[6..],
                encoded
            ));
        }

        let mut link_obj = self
            .new_link(
                &my_handle,
                None,
                Duration::from_secs(31536000), /* year */
            )
            .await?;
        link_obj.session_link = Some(session.group_id.clone());
        let conversation_link = ConversationLink {
            pseudonym: link_obj.pseud.clone(),
            public_key: link_obj.key.compress().to_vec(),
            private_key: vec![],
            invited_handles: session
                .members
                .clone()
                .into_iter()
                .filter(|a| a.handle != my_handle)
                .map(|a| handle_from_ids(&a.handle))
                .collect(),
            creation_date_epoch_time: link_obj.creation_time as f64 / 1000f64,
            group_uuid_string: session.group_id.clone(),
            originator_handle: Some(handle_from_ids(&my_handle)),
            pseudonym_expiration_date_epoch_time: link_obj.expiry_time as f64 / 1000f64,
            is_activated: true,
            generator_descriptor: None,
            link_name: Default::default(),
            link_lifetime_scope: ConversationLinkLifetimeScope::Indefinite as i32,
        };

        let mut message = ConversationMessage::default();
        message.link = Some(conversation_link.clone());
        message.set_type(ConversationMessageType::LinkCreated);
        message.conversation_group_uuid_string = session.group_id.clone();

        let link = link_obj.get_link()?;
        session.link = Some(conversation_link);
        state.links.insert(link_obj.pseud.clone(), link_obj);

        self.message_session(my_handle, message, session, None)
            .await?;

        Ok(link)
    }

    // group is random uuid
    pub async fn create_session(
        &self,
        for_group: String,
        handle: String,
        participants: &[String],
    ) -> Result<(), PushError> {
        let since_the_epoch = duration_since_epoch();

        let session = FTSession {
            group_id: for_group,
            members: participants
                .iter()
                .chain(std::iter::once(&handle))
                .map(|p| FTMember {
                    nickname: None,
                    handle: p.to_string(),
                })
                .collect(),
            my_handles: vec![handle],
            participants: HashMap::new(), // filled in by quickrelay
            link: None,
            report_id: Uuid::new_v4().to_string().to_uppercase(),
            start_time: Some(since_the_epoch.as_millis() as u64),
            last_rekey: None,
            is_propped: false,
            is_ringing_inaccurate: true,
            mode: Some(FTMode::Outgoing),
            recent_member_adds: HashMap::new(),
        };

        let mut my_session = self.state.write().await;
        let group = session.group_id.clone();
        my_session.sessions.insert(group.clone(), session);

        let session = my_session.sessions.get_mut(&group).unwrap();

        self.ensure_allocations(session, &[]).await?;

        self.prop_up_conv(session, true).await?;

        Ok(())
    }

    async fn message_session(
        &self,
        my_handle: String,
        message: ConversationMessage,
        session: &FTSession,
        context: Option<u64>,
    ) -> Result<(), PushError> {
        let relevant_people: Vec<String> =
            session.members.iter().map(|m| m.handle.clone()).collect();
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                &relevant_people,
                &my_handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;

        let targets = self.identity.cache.lock().await.get_participants_targets(
            &topic,
            &my_handle,
            &relevant_people,
        );
        self.identity
            .send_message(
                topic,
                send_for_message(my_handle, message, context),
                targets,
            )
            .await?;
        Ok(())
    }

    pub async fn update_conversation(
        &self,
        session: &mut FTSession,
        join_type: u32,
        message: ConversationMessage,
        before_members: &HashSet<FTMember>,
        to_people: &[String],
    ) -> Result<(), PushError> {
        let mut update_context = ConversationParticipantDidJoinContext::default();
        update_context.members = before_members
            .iter()
            .map(|a| a.to_conversation())
            .collect::<Vec<_>>();
        update_context.message = Some(message);
        update_context.is_screen_sharing_available = true;
        update_context.is_gondola_calling_available = true;
        update_context.share_play_protocol_version = 4;

        let my_participant = session
            .get_participant(self.conn.get_token().await)
            .ok_or(PushError::NoParticipantTokenIndex)?;

        let is_initiator = true; // todo, what does this mean
        let is_u_plus_one = join_type == 3; // new user flag (one on one downgrade??)
        let wire_message = FTWireMessage {
            session: session.group_id.clone(),
            prekey: None,
            prekey_wrap_mode: None,
            fanout_groupid: session.group_id.clone(),
            client_context_data_key: Some(update_context.encode_to_vec().into()),
            participant_data_key: None, // should be AV mode, hopefully this doens't give us trouble?
            is_initiator_key: Some(is_initiator),
            fanout_groupmembers: Some(to_people.to_vec()),
            is_u_plus_one_key: Some(is_u_plus_one),
            join_notification_key: Some(join_type),
            participant_id_key: Some(ParticipantID::Unsigned(my_participant.participant_id)),
            uri_to_participant_id_key: Some(session.participants.values().fold(
                HashMap::new(),
                |mut a, i| {
                    a.entry(i.handle.clone())
                        .or_default()
                        .push(ParticipantID::Unsigned(i.participant_id));
                    a
                },
            )),
        };

        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                to_people,
                &handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;

        let targets = self
            .identity
            .cache
            .lock()
            .await
            .get_participants_targets(&topic, &handle, to_people);
        self.identity
            .send_message(
                topic,
                IDSSendMessage {
                    sender: handle.clone(),
                    raw: Raw::Body(plist_to_bin(&wire_message)?),
                    send_delivered: false,
                    command: 209,
                    no_response: false,
                    id: Uuid::new_v4().to_string().to_uppercase(),
                    scheduled_ms: None,
                    queue_id: None,
                    relay: None,
                    extras: Dictionary::from_iter([
                        ("is-initiator-key", Value::Boolean(is_initiator)),
                        ("up1", Value::Boolean(is_u_plus_one)),
                    ]),
                },
                targets,
            )
            .await?;

        Ok(())
    }

    pub async fn prop_up_conv(&self, session: &mut FTSession, ring: bool) -> Result<(), PushError> {
        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        // we are picking up a call (the prop isn't to ring, and we are ringing)
        if !ring && session.is_ringing_inaccurate {
            let mut message = ConversationMessage::default();
            message.set_type(ConversationMessageType::RespondedElsewhere);
            message.conversation_group_uuid_string = session.group_id.clone();
            message.disconnected_reason = 4; // :shrug:

            let relevant_people = vec![handle.clone()];
            let topic = "com.apple.private.alloy.facetime.multi";
            self.identity
                .cache_keys(
                    topic,
                    &relevant_people,
                    handle,
                    false,
                    &QueryOptions {
                        required_for_message: true,
                        result_expected: true,
                    },
                )
                .await?;

            let targets = self.identity.cache.lock().await.get_participants_targets(
                &topic,
                handle,
                &relevant_people,
            );
            self.identity
                .send_message(
                    topic,
                    send_for_message(handle.clone(), message, None),
                    targets,
                )
                .await?;
        }

        // update_context.members.push(ConversationMember {});

        let self_token = self.conn.get_token().await;

        let base64_encoded = Some(base64_encode(&self_token));

        let is_initiator = true; // todo, what does this mean
        let is_u_plus_one = false; // new user flag (one on one downgrade??)

        let relevant_people: Vec<String> = session
            .members
            .union(&session.members)
            .map(|m| m.handle.clone())
            .collect();
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                &relevant_people,
                &handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;

        let builder_session = session.clone();
        let my_participant = builder_session
            .participants
            .values()
            .find(|p| &p.token == &base64_encoded)
            .ok_or(PushError::NoParticipantTokenIndex)?
            .clone();

        let targets = self.identity.cache.lock().await.get_participants_targets(
            &topic,
            &handle,
            &relevant_people,
        );
        self.identity
            .send_message(
                topic,
                IDSSendMessage {
                    sender: handle.clone(),
                    raw: Raw::Builder(Box::new(move |target| {
                        let mut update_context = ConversationParticipantDidJoinContext::default();
                        update_context.members = builder_session
                            .members
                            .iter()
                            .map(|a| a.to_conversation())
                            .collect::<Vec<_>>();

                        let mut message = ConversationMessage::default();
                        // ring not sending to ourselves
                        if ring && target.participant != my_participant.handle {
                            message.set_type(ConversationMessageType::Invitation);
                        }
                        message.link = builder_session.link.clone();
                        message.report_data = Some(builder_session.get_report());
                        message.invitation_preferences = vec![
                            ConversationInvitationPreference {
                                version: 0,
                                handle_type: HandleType::PhoneNumber as i32,
                                notification_styles: 1,
                            },
                            ConversationInvitationPreference {
                                version: 0,
                                handle_type: HandleType::Generic as i32,
                                notification_styles: 1,
                            },
                            ConversationInvitationPreference {
                                version: 0,
                                handle_type: HandleType::EmailAddress as i32,
                                notification_styles: 1,
                            },
                        ];

                        configure_video_invitation(&mut message, &mut update_context);
                        update_context.message = Some(message);
                        update_context.is_moments_available = true;
                        update_context.provider_identifier =
                            "com.apple.telephonyutilities.callservicesd.FaceTimeProvider"
                                .to_string();
                        update_context.is_gft_downgrade_to_one_to_one_available = Some(false);
                        update_context.is_u_plus_n_downgrade_available = Some(false);
                        update_context.is_u_plus_one_av_less_available = Some(false);

                        update_context.is_screen_sharing_available = true;
                        update_context.is_gondola_calling_available = true;
                        update_context.share_play_protocol_version = 4;

                        let participant_map: HashMap<String, Vec<ParticipantID>> = builder_session
                            .participants
                            .values()
                            .fold(HashMap::new(), |mut a, i| {
                                a.entry(i.handle.clone())
                                    .or_default()
                                    .push(ParticipantID::Unsigned(i.participant_id));
                                a
                            });

                        let wire_message = FTWireMessage {
                            session: builder_session.group_id.clone(),
                            prekey: None,
                            prekey_wrap_mode: None,
                            fanout_groupid: builder_session.group_id.clone(),
                            client_context_data_key: Some(update_context.encode_to_vec().into()),
                            participant_data_key: Some(
                                include_bytes!("sampleavcdata.bplist").to_vec().into(),
                            ), // should be AV mode, hopefully this doens't give us trouble?
                            is_initiator_key: Some(is_initiator),
                            fanout_groupmembers: Some(
                                builder_session
                                    .members
                                    .iter()
                                    .map(|a| a.handle.clone())
                                    .collect(),
                            ),
                            is_u_plus_one_key: Some(is_u_plus_one),
                            join_notification_key: Some(1),
                            participant_id_key: Some(ParticipantID::Unsigned(
                                my_participant.participant_id,
                            )),
                            uri_to_participant_id_key: Some(participant_map),
                        };
                        Some(plist_to_bin(&wire_message).expect("Failed to serialize plist"))
                    })),
                    send_delivered: false,
                    command: 207,
                    no_response: false,
                    id: Uuid::new_v4().to_string().to_uppercase(),
                    scheduled_ms: None,
                    queue_id: None,
                    relay: None,
                    extras: Dictionary::from_iter([
                        ("is-initiator-key", Value::Boolean(is_initiator)),
                        ("up1", Value::Boolean(is_u_plus_one)),
                    ]),
                },
                targets,
            )
            .await?;

        session.is_propped = true;

        Ok(())
    }

    pub async fn decline_invite(&self, session: &mut FTSession) -> Result<(), PushError> {
        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::Decline);
        message.conversation_group_uuid_string = session.group_id.clone();

        let my_handle = session.my_handles.first().expect("No Handle??").clone();

        let alive_tokens: Vec<MessageTarget> = session
            .participants
            .values()
            .filter(|a| a.active.is_some())
            .filter_map(|a| {
                a.token
                    .as_ref()
                    .map(|a| MessageTarget::Token(base64_decode(a)))
            })
            .collect();
        let relevant_people: Vec<String> =
            session.members.iter().map(|m| m.handle.clone()).collect();
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                &relevant_people,
                &my_handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;

        let targets = self.identity.cache.lock().await.get_targets(
            &topic,
            &my_handle,
            &relevant_people,
            &alive_tokens,
        )?;
        self.identity
            .send_message(topic, send_for_message(my_handle, message, None), targets)
            .await?;
        Ok(())
    }

    pub async fn unprop_conv(&self, session: &mut FTSession) -> Result<(), PushError> {
        let my_participant = session
            .get_participant(self.conn.get_token().await)
            .ok_or(PushError::NoParticipantTokenIndex)?;
        let is_initiator = true; // todo, what does this mean
        let is_u_plus_one = true; // new user flag (one on one downgrade??)
        let wire_message = FTWireMessage {
            session: session.group_id.clone(),
            prekey: None,
            prekey_wrap_mode: None,
            fanout_groupid: session.group_id.clone(),
            client_context_data_key: Some(vec![16, 0].into()),
            participant_data_key: None, // should be AV mode, hopefully this doens't give us trouble?
            is_initiator_key: Some(is_initiator),
            fanout_groupmembers: Some(session.members.iter().map(|a| a.handle.clone()).collect()),
            is_u_plus_one_key: Some(is_u_plus_one),
            join_notification_key: Some(2),
            participant_id_key: Some(ParticipantID::Unsigned(my_participant.participant_id)),
            uri_to_participant_id_key: Some(session.participants.values().fold(
                HashMap::new(),
                |mut a, i| {
                    a.entry(i.handle.clone())
                        .or_default()
                        .push(ParticipantID::Unsigned(i.participant_id));
                    a
                },
            )),
        };

        let relevant_people: Vec<String> = session
            .members
            .union(&session.members)
            .map(|m| m.handle.clone())
            .collect();
        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                &relevant_people,
                &handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;

        let targets = self.identity.cache.lock().await.get_participants_targets(
            &topic,
            &handle,
            &relevant_people,
        );
        self.identity
            .send_message(
                topic,
                IDSSendMessage {
                    sender: handle.clone(),
                    raw: Raw::Body(plist_to_bin(&wire_message)?),
                    send_delivered: false,
                    command: 208,
                    no_response: false,
                    id: Uuid::new_v4().to_string().to_uppercase(),
                    scheduled_ms: None,
                    queue_id: None,
                    relay: None,
                    extras: Dictionary::from_iter([
                        ("is-initiator-key", Value::Boolean(is_initiator)),
                        ("up1", Value::Boolean(is_u_plus_one)),
                        // context
                        ("cc", Value::Integer(1.into())),
                        // storage flags
                        ("H", Value::Integer(3.into())),
                    ]),
                },
                targets,
            )
            .await?;

        let base64_encoded = Some(base64_encode(&self.conn.get_token().await));
        let my_participant = session
            .participants
            .values_mut()
            .find(|p| &p.token == &base64_encoded)
            .ok_or(PushError::NoParticipantTokenIndex)?;
        my_participant.active = None; // we left, remember?

        session.is_propped = false;
        Ok(())
    }

    pub async fn add_members(
        &self,
        session: &mut FTSession,
        mut new_members: Vec<FTMember>,
        letmein: bool,
        to_members: Option<Vec<String>>,
    ) -> Result<(), PushError> {
        // if to_members is some this is a re-broadcast and they will already be in the call
        if to_members.is_none() {
            new_members
                .retain(|member| !session.members.iter().any(|m| &m.handle == &member.handle));
            if new_members.is_empty() {
                warn!("(add_members) all new members already in call!");
                return Ok(());
            }
        }

        info!(
            "Adding members {new_members:?} for session {}",
            session.group_id
        );

        // make sure we have quickrelay ids for our new guest!
        self.ensure_allocations(session, &new_members).await?;

        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::AddMember);
        message.active_participants = session
            .participants
            .values()
            .filter_map(|a| a.active.clone())
            .collect();
        message.conversation_group_uuid_string = session.group_id.clone();
        message.added_members = new_members.iter().map(|a| a.to_conversation()).collect();
        message.link = session.link.clone();
        message.report_data = Some(session.get_report());
        message.is_let_me_in_approved = if letmein { Some(true) } else { None };
        message.invitation_preferences = vec![
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::PhoneNumber as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::Generic as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::EmailAddress as i32,
                notification_styles: 1,
            },
        ];

        let mut all_members_inclusive = session.members.clone();
        all_members_inclusive.extend(new_members.clone());

        let to_members = if let Some(members) = to_members {
            members
        } else {
            all_members_inclusive
                .clone()
                .into_iter()
                .map(|a| a.handle)
                .collect()
        };

        let mut before_members = session.members.clone();
        before_members.retain(|m| !new_members.contains(m));

        self.update_conversation(session, 3, message, &before_members, &to_members)
            .await?;

        let added_time = duration_since_epoch().as_millis() as u64;
        for new_member in new_members {
            session
                .recent_member_adds
                .insert(new_member.handle, added_time);
        }

        session.members = all_members_inclusive;
        Ok(())
    }

    pub async fn remove_members(
        &self,
        session: &mut FTSession,
        mut remove: Vec<FTMember>,
    ) -> Result<(), PushError> {
        remove.retain(|member| session.members.contains(member));
        if remove.is_empty() {
            warn!("(remove_members) all members are not in call!");
            return Ok(());
        }

        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::RemoveMember);
        message.removed_members = remove.iter().map(|a| a.to_conversation()).collect();

        let new = session.members.clone();
        let new_members = session
            .members
            .iter()
            .map(|m| m.handle.clone())
            .collect::<Vec<_>>();

        self.update_conversation(session, 3, message, &new, &new_members)
            .await?;

        session.members = new;
        Ok(())
    }

    async fn handle_letmein(
        &self,
        target: &str,
        sender: &str,
        token: Vec<u8>,
        encrypted: EncryptedConversationMessage,
    ) -> Result<LetMeInRequest, PushError> {
        let state = self.state.read().await;
        let Some(link) = &state.links.get(target) else {
            warn!("Link not found!");
            return Err(PushError::BadMsg);
        };

        let other_pubkey =
            CompactECKey::decompress(encrypted.public_key.try_into().expect("Bad pubkey length!"));
        info!("A");

        let a = link.key.get_pkey();
        let b = other_pubkey.get_pkey();
        let mut deriver = Deriver::new(&a)?;
        deriver.set_peer(&b)?;
        let letmein_secret = deriver.derive_to_vec()?;

        info!("B");

        let hk = Hkdf::<Sha256>::new(None, &letmein_secret);
        let mut key = [0u8; 32];
        hk.expand("FT-LMI-RequestKey".as_bytes(), &mut key)
            .expect("Failed to expand key!");
        info!("C");

        let nonce = &encrypted.conversation_message_bytes[..NONCE_COUNT];
        let body = &encrypted.conversation_message_bytes[NONCE_COUNT..];

        let cipher = Aes256Gcm::new(&key.into());
        let decrypted = cipher
            .decrypt(Nonce::from_slice(nonce), body)
            .map_err(|_| PushError::AESGCMError)?;

        info!(
            "Decrypted FaceTime admission request bytes={}",
            decrypted.len()
        );
        let decoded = ConversationMessage::decode(&mut Cursor::new(&decrypted))?;

        let mut request = LetMeInRequest {
            shared_secret: letmein_secret,
            pseud: target.to_string(),
            requestor: sender.to_string(),
            nickname: decoded.nickname.clone(),
            token,
            delegation_uuid: None,
            usage: link.usage.clone(),
        };

        if let Some(session) = link
            .session_link
            .as_ref()
            .and_then(|session| state.sessions.get(session))
        {
            // delegate
            let delegate_uuid = Uuid::new_v4().to_string().to_uppercase();

            let mut delegate = ConversationMessage::default();
            delegate.set_type(ConversationMessageType::LetMeInDelegation);
            delegate.nickname = decoded.nickname.clone();
            delegate.conversation_group_uuid_string = session.group_id.clone();
            delegate.let_me_in_delegation_handle = request.requestor.clone();
            delegate.let_me_in_delegation_uuid = delegate_uuid.clone();
            let my_handle = session.my_handles.first().expect("No Handle??");
            // context if missing is
            //  6045   0    callservicesd: [com.apple.calls.callservicesd:Default] [WARN] Dropping let me in delegation request or response because it has the wrong intent {publicIntentAction: (null)}
            self.message_session(my_handle.clone(), delegate, session, Some(20001))
                .await?;

            request.delegation_uuid = Some(delegate_uuid.clone());

            let mut delegated_lock = self.delegated_requests.lock().await;
            delegated_lock.insert(delegate_uuid, request.clone());
        }

        Ok(request)
    }

    pub async fn respond_letmein(
        &self,
        letmein: LetMeInRequest,
        approved_group: Option<&str>,
    ) -> Result<(), PushError> {
        if let Some(delegation) = letmein.delegation_uuid {
            let mut shared_lock = self.delegated_requests.lock().await;
            let removed = shared_lock.remove(&delegation);
            if removed.is_none() {
                warn!("Already responded to letmein, ignoring request!");
                return Ok(()); // already responded
            }
        }
        if let Some(approved) = approved_group {
            let mut state = self.state.write().await;
            let session = state
                .sessions
                .get_mut(approved)
                .expect("Approved session not found!");
            // MUST prop before we create a session link so caller associates our session properly

            // this is for when the call is in a OneOnOne mode AND there is only ONE participant in the call
            // in callservicesd -[CSDAVCSession addParticipant:withVideoEnabled:audioPaused:screenEnabled:] counts remote [other] participants
            // if it is not 1, it will not properly kick us out of OneOnOne mode. Since we are joining with a web client that does not support
            // OneOnOne mode, we must trigger this condition. If said device is the only one in the call (ringing), it sees zero (0) remote participants,
            // thus the condition fails; OneOnOne mode is not exited, and the call fails. We solve this by "joining" the call until the web client
            // has an opportunity to join, and then leaving ASAP.
            // AFAICT this condition is only triggered when ringing
            let needs_prop = session.is_ringing_inaccurate
                && session
                    .participants
                    .values()
                    .filter(|a| a.active.is_some())
                    .count()
                    == 1;
            if needs_prop {
                info!("Propping conversation");
                self.ensure_allocations(session, &[]).await?;
                self.prop_up_conv(session, false).await?;
                // return Err(PushError::AESGCMError);
            }
            drop(state);

            // for native links
            // info!("Ensuring letmein group has link!");
            // let a = self.get_session_link(approved).await?;
            // info!("Adding to group with link {a}");
        }
        let mut state = self.state.write().await;
        let Some(link) = &state.links.get(&letmein.pseud) else {
            warn!("Link not found!");
            return Err(PushError::BadMsg);
        };
        let mut response = ConversationMessage::default();
        response.is_let_me_in_approved = Some(approved_group.is_some());
        response.set_type(ConversationMessageType::LetMeInResponse);
        let mut link_data = ConversationLink::default();
        link_data.set_link_lifetime_scope(ConversationLinkLifetimeScope::Indefinite);
        link_data.pseudonym = link.pseud.clone();
        link_data.public_key = link.key.compress().to_vec();
        if let Some(to_group) = approved_group {
            response.conversation_group_uuid_string = to_group.to_string();
            link_data.group_uuid_string = to_group.to_string();
            link_data.originator_handle = Some(handle_from_ids(&link.handle));
        }
        response.link = Some(link_data.clone());

        let encoded = response.encode_to_vec();
        let hk = Hkdf::<Sha256>::new(None, &letmein.shared_secret);
        let mut key = [0u8; 32];
        hk.expand("FT-LMI-ResponseKey".as_bytes(), &mut key)
            .expect("Failed to expand key!");

        let nonce: [u8; NONCE_COUNT] = rand::random();
        let cipher = Aes256Gcm::new(&key.into());
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), &encoded[..])
            .map_err(|_| PushError::AESGCMError)?;

        let mut encrypted_message = ConversationMessage::default();
        encrypted_message.set_type(ConversationMessageType::EncryptedMessage);
        encrypted_message.set_enclosed_encrypted_type(ConversationMessageType::LetMeInResponse);
        link_data.originator_handle = None;
        link_data.group_uuid_string = "".to_string();
        encrypted_message.link = Some(link_data);
        encrypted_message.encrypted_message = Some(EncryptedConversationMessage {
            public_key: link.key.compress().to_vec(),
            conversation_message_bytes: [nonce.to_vec(), encrypted].concat(),
        });

        let topic = "com.apple.private.alloy.facetime.multi";
        let targets = self.identity.cache.lock().await.get_targets(
            &topic,
            &letmein.pseud,
            &[letmein.requestor.clone()],
            &[MessageTarget::Token(letmein.token)],
        )?;
        self.identity
            .send_message(
                topic,
                send_for_message(letmein.pseud.clone(), encrypted_message, None),
                targets,
            )
            .await?;

        let Some(to_group) = approved_group else {
            return Ok(());
        };

        // doesn't currently work for native FT, see in callservicesd -[CSDFaceTimeConversationProviderDelegate handleInvitationMessage:forConversation:fromHandle:]
        // at the bottom removePendingConversationWithPseudonym, uses the link field of the LMI request
        // but we don't currently assign our link to the conversation. FT Web doesn't care

        let session = state.sessions.get_mut(to_group).expect("No session");
        let member = FTMember {
            handle: letmein.requestor.clone(),
            nickname: letmein.nickname.clone(),
        };
        if session.members.contains(&member) {
            self.ring(session, &[letmein.requestor.clone()], true)
                .await?;
        } else {
            self.add_members(session, vec![member], true, None).await?;
            (self.update_state)(&state);
        }
        Ok(())
    }

    pub async fn ring(
        &self,
        session: &FTSession,
        targets: &[String],
        letmein: bool,
    ) -> Result<(), PushError> {
        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::Invitation);
        message.conversation_group_uuid_string = session.group_id.to_string();
        message.link = session.link.clone();
        message.is_let_me_in_approved = if letmein { Some(true) } else { None };
        message.invitation_preferences = vec![
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::PhoneNumber as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::Generic as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::EmailAddress as i32,
                notification_styles: 1,
            },
        ];

        let handle = session.my_handles.first().unwrap();
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                targets,
                handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;
        let targets = self
            .identity
            .cache
            .lock()
            .await
            .get_participants_targets(&topic, handle, targets);
        self.identity
            .send_message(
                topic,
                send_for_message(handle.clone(), message, None),
                targets,
            )
            .await?;
        Ok(())
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<Option<FTMessage>, PushError> {
        let Some(IDSRecvMessage {
            message_unenc: Some(message),
            target: Some(target),
            command,
            token: Some(token),
            sender: Some(sender),
            ns_since_epoch: Some(ns_since_epoch),
            ..
        }) = self
            .identity
            .receive_message(
                msg,
                &[
                    "com.apple.private.alloy.facetime.multi",
                    "com.apple.private.alloy.facetime.video",
                ],
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(if command == 242 {
            // NiceData
            let bytes = message.bytes()?;
            debug!("FaceTime IDS conversation message bytes={}", bytes.len());
            let decoded = ConversationMessage::decode(&mut Cursor::new(&bytes))?;
            debug!(
                "Decoded FaceTime conversation message type={} active_participants={}",
                decoded.r#type,
                decoded.active_participants.len(),
            );

            match decoded.r#type() {
                ConversationMessageType::LinkChanged | ConversationMessageType::LinkCreated => {
                    let mut state = self.state.write().await;
                    let session = state
                        .sessions
                        .entry(decoded.conversation_group_uuid_string.clone())
                        .or_default();
                    session.link = decoded.link.clone();
                    let guid = session.group_id.clone();
                    (self.update_state)(&state);
                    Some(FTMessage::LinkChanged { guid })
                }
                ConversationMessageType::EncryptedMessage => {
                    match decoded.enclosed_encrypted_type() {
                        ConversationMessageType::LetMeInRequest => {
                            let request = self
                                .handle_letmein(
                                    &target,
                                    &sender,
                                    token,
                                    decoded.encrypted_message.clone().expect("No encrypted?"),
                                )
                                .await?;
                            Some(FTMessage::LetMeInRequest(request))
                        }
                        _type => {
                            warn!("Couldn't handle encrypted message type {_type:?}");
                            None
                        }
                    }
                }
                ConversationMessageType::Decline => {
                    let mut state = self.state.write().await;
                    if let Some(session) = state
                        .sessions
                        .get_mut(&decoded.conversation_group_uuid_string)
                    {
                        session.is_ringing_inaccurate = false;
                        session.mode = Some(FTMode::MissedOutgoing); // mark as incoming
                        self.unprop_conv(session).await?;
                        (self.update_state)(&state);
                    }
                    Some(FTMessage::Decline {
                        guid: decoded.conversation_group_uuid_string.clone(),
                    })
                }
                ConversationMessageType::LetMeInDelegationResponse => {
                    let requests = self.delegated_requests.lock().await;
                    let Some(request) = requests.get(&decoded.let_me_in_delegation_uuid) else {
                        return Ok(None);
                    };
                    info!("Handling let me in delegation!");
                    let response = request.clone();
                    drop(requests);
                    self.respond_letmein(
                        response,
                        if decoded.is_let_me_in_approved == Some(true) {
                            Some(&decoded.conversation_group_uuid_string)
                        } else {
                            None
                        },
                    )
                    .await?;
                    None
                }
                ConversationMessageType::Invitation => {
                    let mut state = self.state.write().await;
                    if let Some(session) = state
                        .sessions
                        .get_mut(&decoded.conversation_group_uuid_string)
                    {
                        session.is_ringing_inaccurate = true;
                        session.mode = Some(FTMode::Incoming); // mark as incoming
                        (self.update_state)(&state);
                    }
                    Some(FTMessage::Ring {
                        guid: decoded.conversation_group_uuid_string.clone(),
                    })
                }
                ConversationMessageType::RespondedElsewhere => {
                    let mut state = self.state.write().await;
                    if let Some(session) = state
                        .sessions
                        .get_mut(&decoded.conversation_group_uuid_string)
                    {
                        session.is_ringing_inaccurate = false;
                        (self.update_state)(&state);
                    }
                    Some(FTMessage::RespondedElsewhere {
                        guid: decoded.conversation_group_uuid_string.clone(),
                    })
                }
                _type => {
                    // `r#type()` is prost's accessor, which maps any wire value
                    // outside ConversationMessageType back to the default
                    // variant. That makes every unrecognised type log
                    // identically as `Unknown` and discards the one piece of
                    // information needed to identify it. 17, 18 and everything
                    // above 30 are absent from the enum, so a real type Apple
                    // sends is indistinguishable here from a genuine zero.
                    warn!(
                        "Couldn't handle message type {_type:?} (wire value {})",
                        decoded.r#type
                    );
                    None
                }
            }
        } else {
            let received: Value = message.plist()?;
            let mut received: FTWireMessage = plist::from_value(&received)?;
            let mut state = self.state.write().await;
            let session = state.sessions.entry(received.session.clone()).or_default();
            session.group_id = received.session.clone();
            if !session.my_handles.contains(&target) {
                session.my_handles.push(target.clone());
            }
            let context = received.client_context_data_key.take();
            let participant_meta = received.participant_data_key.take(); // BORING
            match (command, context, participant_meta, &received) {
                (
                    207,
                    context,
                    avc_data,
                    FTWireMessage {
                        participant_id_key: Some(participant),
                        ..
                    },
                ) => {
                    info!("Someone joined!");
                    let participant = *participant;
                    let participant_key = participant.to_string();
                    let known_before = session.participants.contains_key(&participant_key);
                    let context_present = context.is_some();
                    let avc_data_present = avc_data.is_some();
                    let canonical_sender = canonicalize_ids_handle(&sender);
                    let Some(join) = session.apply_participant_join_wire(
                        participant,
                        &token,
                        &canonical_sender,
                        avc_data,
                        context,
                        ns_since_epoch / 1000000,
                    )?
                    else {
                        warn!(
                            "FaceTime signal command=207 outcome=ignored_missing_context id_encoding={} avc_data={} participants={} active={}",
                            participant.encoding(),
                            avc_data_present,
                            session.participants.len(),
                            session
                                .participants
                                .values()
                                .filter(|participant| participant.active.is_some())
                                .count(),
                        );
                        return Ok(None);
                    };
                    let message_type = join.message_type;
                    if !join.nested_message {
                        // Apple may omit the nested ConversationMessage from a
                        // participant-state update. The participant and AVC
                        // metadata are still usable, so do not discard the
                        // entire join event.
                        warn!("FaceTime command 207 omitted conversation metadata");
                    }
                    warn!(
                        "FaceTime signal command=207 id_encoding={} known_before={} known_after=true context={} avc_data={} nested_message={} message_type={} participants={} active={}",
                        participant.encoding(),
                        known_before,
                        context_present,
                        avc_data_present,
                        join.nested_message,
                        message_type as i32,
                        session.participants.len(),
                        session
                            .participants
                            .values()
                            .filter(|participant| participant.active.is_some())
                            .count(),
                    );

                    // if we propped it up for a join, someone else (or us) have joined
                    // so we don't need to prop it anymore
                    // make sure web client to not hang up on people who are picking up for us
                    if session.is_propped && canonical_sender.starts_with("temp:") {
                        self.unprop_conv(session).await?;
                    }

                    if message_type == ConversationMessageType::Invitation {
                        if canonical_sender != canonicalize_ids_handle(&target) {
                            session.mode = Some(FTMode::Incoming)
                        } else {
                            session.mode = Some(FTMode::Outgoing)
                        }
                    }

                    let guid = session.group_id.clone();
                    (self.update_state)(&state);

                    Some(FTMessage::JoinEvent {
                        guid,
                        participant: participant.into(),
                        handle: canonical_sender.clone(),
                        ring: message_type == ConversationMessageType::Invitation
                            && canonical_sender != canonicalize_ids_handle(&target),
                    })
                }
                (209, Some(context), _meta, _) => {
                    info!("Group Updated!");
                    let decoded_context = ConversationParticipantDidJoinContext::decode(
                        &mut Cursor::new(context.as_ref()),
                    )?;
                    let stand_up_for = session.unpack_members(&decoded_context.members);

                    let message = decoded_context.message.as_ref();
                    if message.is_none() {
                        // A membership snapshot without a nested message is a
                        // valid partial update. Keep the member state and wait
                        // for a later typed update instead of surfacing the
                        // generic BadMsg error and losing the snapshot.
                        warn!("FaceTime command 209 omitted conversation metadata");
                    }
                    let message_type = apply_conversation_message_metadata(session, message);
                    if let Some(message) = message {
                        session.unpack_participants(
                            &message.active_participants,
                            &self.conn.get_token().await,
                        );
                    }
                    warn!(
                        "FaceTime signal command=209 nested_message={} message_type={} snapshot_participants={} participants={} active={}",
                        message.is_some(),
                        message_type as i32,
                        message.map_or(0, |value| value.active_participants.len()),
                        session.participants.len(),
                        session
                            .participants
                            .values()
                            .filter(|participant| participant.active.is_some())
                            .count(),
                    );
                    let result: Option<FTMessage> = match (message_type, message) {
                        (ConversationMessageType::AddMember, Some(message)) => {
                            info!("Added a member!");
                            let new = session.new_members(&message.added_members);

                            if !stand_up_for.is_empty() {
                                info!("Standing up for {:?} to {:?}", stand_up_for, new);
                                // if some members we recently added were left out of this state change, we must tell
                                // the new member that these members *do* exist and should be included in the session
                                self.add_members(
                                    session,
                                    stand_up_for,
                                    false,
                                    Some(new.iter().map(|a| a.handle.clone()).collect()),
                                )
                                .await?;
                            }

                            // if we were added, ring
                            let ring = new.iter().any(|i| session.my_handles.contains(&i.handle));
                            session.mode = Some(FTMode::Incoming);
                            Some(FTMessage::AddMembers {
                                guid: session.group_id.clone(),
                                members: new,
                                ring,
                            })
                        }
                        (ConversationMessageType::RemoveMember, Some(message)) => {
                            info!("Removed a member!");
                            Some(FTMessage::RemoveMembers {
                                guid: session.group_id.clone(),
                                members: session.remove_members(&message.removed_members),
                            })
                        }
                        _ => None,
                    };
                    (self.update_state)(&state);

                    result
                }
                (210, _, _, _) => {
                    // we don't have any realtime connection so we use the peridic rekeys as heartbeats
                    session.last_rekey = Some(ns_since_epoch / 1000000);
                    (self.update_state)(&state);
                    None
                }
                (
                    208,
                    _a,
                    _b,
                    FTWireMessage {
                        participant_id_key: Some(participant),
                        uri_to_participant_id_key: participant_map,
                        ..
                    },
                ) => {
                    let announced_id = *participant;
                    let id = session
                        .resolve_participant_leave_id(announced_id, participant_map.as_ref());
                    let fallback_used = id.to_string() != announced_id.to_string();
                    info!("Group member left!");
                    let leave = session.apply_participant_leave(id, ns_since_epoch / 1000000);
                    let (handle_left, no_active_participants) = match leave {
                        ParticipantLeaveOutcome::Unknown => {
                            warn!(
                                "FaceTime signal command=208 outcome=unknown id_encoding={} fallback_used={} participants={} active={}",
                                id.encoding(),
                                fallback_used,
                                session.participants.len(),
                                session
                                    .participants
                                    .values()
                                    .filter(|participant| participant.active.is_some())
                                    .count(),
                            );
                            return Ok(None);
                        }
                        ParticipantLeaveOutcome::Stale => {
                            warn!(
                                "FaceTime signal command=208 outcome=stale id_encoding={} fallback_used={} participants={} active={}",
                                id.encoding(),
                                fallback_used,
                                session.participants.len(),
                                session
                                    .participants
                                    .values()
                                    .filter(|participant| participant.active.is_some())
                                    .count(),
                            );
                            return Ok(None);
                        }
                        ParticipantLeaveOutcome::Applied {
                            handle,
                            no_active_participants,
                        } => (handle, no_active_participants),
                    };

                    let guid = session.group_id.clone();

                    if no_active_participants {
                        if session.is_ringing_inaccurate {
                            if canonicalize_ids_handle(&sender) == canonicalize_ids_handle(&target)
                            {
                                session.mode = Some(FTMode::MissedOutgoing);
                            } else {
                                session.mode = Some(FTMode::Missed);
                            }
                        }
                        session.is_ringing_inaccurate = false;
                    }
                    warn!(
                        "FaceTime signal command=208 outcome=applied id_encoding={} fallback_used={} participants={} active={}",
                        id.encoding(),
                        fallback_used,
                        session.participants.len(),
                        session
                            .participants
                            .values()
                            .filter(|participant| participant.active.is_some())
                            .count(),
                    );
                    (self.update_state)(&state);
                    Some(FTMessage::LeaveEvent {
                        guid,
                        participant: id.into(),
                        handle: handle_left,
                    })
                }
                (207, context, avc_data, _) => {
                    warn!(
                        "FaceTime signal command=207 outcome=ignored_missing_participant_id context={} avc_data={} participants={} active={}",
                        context.is_some(),
                        avc_data.is_some(),
                        session.participants.len(),
                        session
                            .participants
                            .values()
                            .filter(|participant| participant.active.is_some())
                            .count(),
                    );
                    None
                }
                (209, None, _, _) => {
                    warn!(
                        "FaceTime signal command=209 outcome=ignored_missing_context participants={} active={}",
                        session.participants.len(),
                        session
                            .participants
                            .values()
                            .filter(|participant| participant.active.is_some())
                            .count(),
                    );
                    None
                }
                (_c, a, b, _) => {
                    info!(
                        "Received unknown FaceTime command={} context_bytes={} avc_bytes={} participant_id={} members={}",
                        _c,
                        a.as_ref().map_or(0, |data| data.as_ref().len()),
                        b.as_ref().map_or(0, |data| data.as_ref().len()),
                        received.participant_id_key.is_some(),
                        received.fanout_groupmembers.as_ref().map_or(0, Vec::len),
                    );
                    None
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_video_invitation_sets_consistent_av_metadata() {
        let mut message = ConversationMessage::default();
        let mut context = ConversationParticipantDidJoinContext::default();

        configure_video_invitation(&mut message, &mut context);
        context.message = Some(message);

        let wire = context.encode_to_vec();
        let decoded = ConversationParticipantDidJoinContext::decode(wire.as_slice())
            .expect("video invitation context should round-trip through protobuf");
        let decoded_message = decoded
            .message
            .expect("video invitation should carry a conversation message");

        assert_eq!(decoded_message.av_mode, Some(FACETIME_VIDEO_AV_MODE));
        assert_eq!(decoded.video, Some(true));
        assert_eq!(decoded.video_enabled, Some(true));
        assert_eq!(decoded.av_mode, Some(FACETIME_VIDEO_AV_MODE as u32));
    }

    #[test]
    fn omitted_conversation_metadata_is_a_nonfatal_partial_update() {
        let mut session = FTSession {
            group_id: "test-session".to_string(),
            report_id: "existing-report".to_string(),
            start_time: Some(42),
            ..Default::default()
        };

        let message_type = apply_conversation_message_metadata(&mut session, None);

        assert_eq!(message_type, ConversationMessageType::Unknown);
        assert_eq!(session.report_id, "existing-report");
        assert_eq!(session.start_time, Some(42));
        assert!(session.link.is_none());
    }

    #[test]
    fn current_shareplay_wire_value_is_known() {
        assert_eq!(
            ConversationMessageType::try_from(37),
            Ok(ConversationMessageType::SharePlayAvailable)
        );
    }

    fn context_with_message(
        message_type: ConversationMessageType,
    ) -> ConversationParticipantDidJoinContext {
        let mut message = ConversationMessage::default();
        message.set_type(message_type);
        ConversationParticipantDidJoinContext {
            version: 1,
            message: Some(message),
            ..Default::default()
        }
    }

    #[test]
    fn participant_ids_normalize_across_signed_and_unsigned_plists() {
        assert_eq!(
            ParticipantID::Signed(-1).to_string(),
            ParticipantID::Unsigned(u64::MAX).to_string(),
        );
        assert_eq!(
            ParticipantID::Signed(42).to_string(),
            ParticipantID::Unsigned(42).to_string(),
        );
    }

    #[test]
    fn replays_join_snapshot_and_leave_without_orphaning_participant() {
        let mut session = FTSession::default();
        let context = context_with_message(ConversationMessageType::Invitation);
        let token = [7_u8; 32];

        let message_type = session.apply_participant_join(
            ParticipantID::Unsigned(42),
            &token,
            "mailto:guest@example.invalid",
            vec![1, 2, 3],
            &context,
            1_000,
        );
        assert_eq!(message_type, ConversationMessageType::Invitation);
        assert!(session.participants["42"].active.is_some());

        let snapshot = session.participants["42"].active.clone().unwrap();
        session.unpack_participants(&[snapshot], &[9_u8; 32]);
        assert!(session.participants["42"].active.is_some());

        assert_eq!(
            session.apply_participant_leave(ParticipantID::Signed(42), 1_001),
            ParticipantLeaveOutcome::Applied {
                handle: "mailto:guest@example.invalid".to_string(),
                no_active_participants: true,
            },
        );
        assert!(session.participants["42"].active.is_none());
    }

    #[test]
    fn join_context_without_nested_message_still_establishes_participant() {
        let mut session = FTSession::default();
        let context = ConversationParticipantDidJoinContext::default();

        let message_type = session.apply_participant_join(
            ParticipantID::Unsigned(7),
            &[1_u8; 32],
            "temp:guest",
            vec![4, 5, 6],
            &context,
            500,
        );

        assert_eq!(message_type, ConversationMessageType::Unknown);
        assert!(session.participants["7"].active.is_some());
        assert_eq!(
            session.apply_participant_leave(ParticipantID::Unsigned(7), 501),
            ParticipantLeaveOutcome::Applied {
                handle: "temp:guest".to_string(),
                no_active_participants: true,
            },
        );
        assert!(!session.participants.contains_key("7"));
    }

    #[test]
    fn wire_join_requires_context_but_accepts_missing_avc_metadata() {
        let mut session = FTSession::default();
        let participant = ParticipantID::Unsigned(8);
        let token = [2_u8; 32];

        let ignored = session
            .apply_participant_join_wire(
                participant,
                &token,
                "guest@example.invalid",
                None,
                None,
                500,
            )
            .expect("missing context should be handled without a decode failure");
        assert!(ignored.is_none());
        assert!(!session.participants.contains_key("8"));

        let context = context_with_message(ConversationMessageType::Invitation);
        let applied = session
            .apply_participant_join_wire(
                participant,
                &token,
                "guest@example.invalid",
                None,
                Some(context.encode_to_vec().into()),
                501,
            )
            .expect("valid context should decode")
            .expect("valid context should establish the participant");

        assert_eq!(applied.message_type, ConversationMessageType::Invitation);
        assert!(applied.nested_message);
        assert_eq!(
            session.participants["8"].handle,
            "mailto:guest@example.invalid",
        );
        assert_eq!(
            session.participants["8"]
                .active
                .as_ref()
                .expect("participant should be active")
                .avc_data,
            Vec::<u8>::new(),
        );
    }

    #[test]
    fn stale_leave_after_rejoin_does_not_clear_active_participant() {
        let mut session = FTSession::default();
        let context = context_with_message(ConversationMessageType::Invitation);
        session.apply_participant_join(
            ParticipantID::Unsigned(9),
            &[2_u8; 32],
            "mailto:guest@example.invalid",
            vec![],
            &context,
            2_000,
        );

        assert_eq!(
            session.apply_participant_leave(ParticipantID::Unsigned(9), 1_999),
            ParticipantLeaveOutcome::Stale,
        );
        assert!(session.participants["9"].active.is_some());
    }

    #[test]
    fn unknown_leave_does_not_corrupt_known_participants() {
        let mut session = FTSession::default();
        let context = context_with_message(ConversationMessageType::Invitation);
        session.apply_participant_join(
            ParticipantID::Unsigned(11),
            &[3_u8; 32],
            "mailto:guest@example.invalid",
            vec![],
            &context,
            100,
        );

        assert_eq!(
            session.apply_participant_leave(ParticipantID::Unsigned(12), 101),
            ParticipantLeaveOutcome::Unknown,
        );
        assert!(session.participants["11"].active.is_some());
    }

    #[test]
    fn empty_partial_membership_snapshot_preserves_joined_participant() {
        let mut session = FTSession::default();
        let context = context_with_message(ConversationMessageType::Invitation);
        session.apply_participant_join(
            ParticipantID::Unsigned(13),
            &[4_u8; 32],
            "mailto:guest@example.invalid",
            vec![],
            &context,
            100,
        );

        let stood_up = session.unpack_members(&[]);

        assert!(stood_up.is_empty());
        assert!(session.participants.contains_key("13"));
        assert!(session.participants["13"].active.is_some());
    }

    #[test]
    fn empty_partial_active_snapshot_does_not_end_call() {
        let mut session = FTSession::default();
        let context = context_with_message(ConversationMessageType::Invitation);
        session.apply_participant_join(
            ParticipantID::Unsigned(14),
            &[5_u8; 32],
            "mailto:guest@example.invalid",
            vec![],
            &context,
            100,
        );

        session.unpack_participants(&[], &[6_u8; 32]);

        assert!(session.participants["14"].active.is_some());
    }

    #[test]
    fn nonempty_partial_snapshots_preserve_omitted_member_and_participant() {
        let mut session = FTSession::default();
        let context = context_with_message(ConversationMessageType::Invitation);
        let first_member = FTMember {
            nickname: None,
            handle: "mailto:first@example.invalid".to_string(),
        }
        .to_conversation();
        let second_member = FTMember {
            nickname: None,
            handle: "mailto:second@example.invalid".to_string(),
        }
        .to_conversation();
        session.new_members(&[first_member.clone(), second_member]);
        session.apply_participant_join(
            ParticipantID::Unsigned(21),
            &[1_u8; 32],
            "first@example.invalid",
            vec![],
            &context,
            100,
        );
        session.apply_participant_join(
            ParticipantID::Unsigned(22),
            &[2_u8; 32],
            "second@example.invalid",
            vec![],
            &context,
            100,
        );

        session.unpack_members(&[first_member]);
        let first_participant = session.participants["21"].active.clone().unwrap();
        session.unpack_participants(&[first_participant], &[9_u8; 32]);

        assert!(session
            .members
            .iter()
            .any(|member| member.handle == "mailto:second@example.invalid"));
        assert!(session.participants["21"].active.is_some());
        assert!(session.participants["22"].active.is_some());
    }

    #[test]
    fn unknown_leave_id_resolves_through_uri_participant_map() {
        let mut session = FTSession::default();
        let context = context_with_message(ConversationMessageType::Invitation);
        session.apply_participant_join(
            ParticipantID::Unsigned(42),
            &[3_u8; 32],
            "guest@example.invalid",
            vec![],
            &context,
            100,
        );
        let uri_map = HashMap::from([(
            "guest@example.invalid".to_string(),
            vec![ParticipantID::Unsigned(99)],
        )]);

        let resolved =
            session.resolve_participant_leave_id(ParticipantID::Unsigned(99), Some(&uri_map));

        assert_eq!(resolved.to_string(), "42");
        assert_eq!(
            session.apply_participant_leave(resolved, 101),
            ParticipantLeaveOutcome::Applied {
                handle: "mailto:guest@example.invalid".to_string(),
                no_active_participants: true,
            },
        );
    }

    #[test]
    fn raw_email_sender_is_canonicalized_before_snapshot_cleanup() {
        let mut session = FTSession::default();
        let mut context = context_with_message(ConversationMessageType::Invitation);
        context.members.push(
            FTMember {
                nickname: None,
                handle: "mailto:guest@example.invalid".to_string(),
            }
            .to_conversation(),
        );

        session.apply_participant_join(
            ParticipantID::Unsigned(15),
            &[7_u8; 32],
            "guest@example.invalid",
            vec![],
            &context,
            100,
        );
        session.unpack_members(&context.members);

        assert_eq!(
            session.participants["15"].handle,
            "mailto:guest@example.invalid",
        );
        assert!(session.participants.contains_key("15"));
    }

    #[test]
    fn duplicate_join_replaces_same_participant_without_duplication() {
        let mut session = FTSession::default();
        let context = context_with_message(ConversationMessageType::Invitation);

        for joined_ms in [100, 200] {
            session.apply_participant_join(
                ParticipantID::Unsigned(16),
                &[8_u8; 32],
                "mailto:guest@example.invalid",
                vec![],
                &context,
                joined_ms,
            );
        }

        assert_eq!(session.participants.len(), 1);
        assert_eq!(session.participants["16"].last_join_date, Some(200));
    }

    #[test]
    fn plist_round_trip_preserves_partial_join_and_signed_participant_id() {
        let wire = FTWireMessage {
            session: "fixture-session".to_string(),
            prekey: None,
            prekey_wrap_mode: None,
            fanout_groupid: "fixture-session".to_string(),
            client_context_data_key: None,
            participant_data_key: None,
            is_initiator_key: Some(false),
            fanout_groupmembers: None,
            is_u_plus_one_key: None,
            join_notification_key: Some(1),
            participant_id_key: Some(ParticipantID::Signed(-1)),
            uri_to_participant_id_key: None,
        };

        let encoded = plist_to_bin(&wire).expect("fixture should serialize");
        let decoded: FTWireMessage =
            plist::from_bytes(&encoded).expect("fixture should deserialize");

        assert!(decoded.client_context_data_key.is_none());
        assert!(decoded.participant_data_key.is_none());
        assert_eq!(
            decoded.participant_id_key.unwrap().to_string(),
            u64::MAX.to_string(),
        );
    }
}
