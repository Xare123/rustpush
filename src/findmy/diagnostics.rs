//! Opt-in, value-free diagnostics for FMF/FMIP responses and Items refreshes.
//! Also IDS 242 shape observations (fixed categories only, never values).
//! Native compilation: OPENBUBBLES_FINDMY_VERBOSE_DIAGNOSTICS=true.
//! No runtime environment reads, requests, logger configuration, or retained rows.
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};

use plist::stream::{Event, Reader};
use serde_json::Value;

use crate::ids::{IDSRecvMessage, MessageBody};

const ROW_LIMIT: usize = 256;
const REQUEST_LIMIT: usize = 12;
static FMF_REQUESTS: AtomicUsize = AtomicUsize::new(0);
static FMIP_REQUESTS: AtomicUsize = AtomicUsize::new(0);
static ITEMS_REQUESTS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy)]
pub(super) enum Service {
    Fmf,
    Fmip,
    Items,
}

#[derive(Debug, PartialEq, Eq)]
enum Phase {
    Init,
    Refresh,
    Selected,
}

fn phase(path: &str) -> Option<Phase> {
    match path {
        "initClient" | "first/initClient" => Some(Phase::Init),
        "refreshClient" | "minCallback/refreshClient" | "items" => Some(Phase::Refresh),
        "minCallback/selFriend/refreshClient" => Some(Phase::Selected),
        _ => None,
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
enum Shape {
    #[default]
    Unobserved,
    Absent,
    Null,
    Object,
    Array(usize),
    Bool,
    Number,
    String,
}

fn shape(value: Option<&Value>) -> Shape {
    match value {
        None => Shape::Absent,
        Some(Value::Null) => Shape::Null,
        Some(Value::Object(_)) => Shape::Object,
        Some(Value::Array(rows)) => Shape::Array(rows.len().min(ROW_LIMIT)),
        Some(Value::Bool(_)) => Shape::Bool,
        Some(Value::Number(_)) => Shape::Number,
        Some(Value::String(_)) => Shape::String,
    }
}

#[derive(Debug, Default)]
struct RawShape {
    root: Shape,
    following: Shape,
    locations: Shape,
    content: Shape,
    location_absent: usize,
    location_null: usize,
    location_object: usize,
    location_other: usize,
    non_object_rows: usize,
    truncated: bool,
}

impl RawShape {
    fn read(raw: &Value, service: Service) -> Self {
        let mut result = Self {
            root: shape(Some(raw)),
            following: shape(raw.get("following")),
            locations: shape(raw.get("locations")),
            content: shape(raw.get("content")),
            ..Self::default()
        };
        result.truncated = raw.as_array().is_some_and(|rows| rows.len() > ROW_LIMIT)
            || ["following", "locations", "content"].iter().any(|key| {
                raw.get(*key)
                    .and_then(Value::as_array)
                    .is_some_and(|rows| rows.len() > ROW_LIMIT)
            });
        let key = match service {
            Service::Fmf => "locations",
            Service::Fmip => "content",
            Service::Items => return result, // Items never inspect response payloads.
        };
        if let Some(rows) = raw.get(key).and_then(Value::as_array) {
            for row in rows.iter().take(ROW_LIMIT) {
                if !row.is_object() {
                    result.non_object_rows += 1;
                    continue;
                }
                match shape(row.get("location")) {
                    Shape::Absent => result.location_absent += 1,
                    Shape::Null => result.location_null += 1,
                    Shape::Object => result.location_object += 1,
                    _ => result.location_other += 1,
                }
            }
        }
        result
    }
}

#[derive(Debug, Default)]
pub(super) struct Snapshot {
    observed: bool,
    rows: usize,
    locations: usize,
    truncated: bool,
}

impl Snapshot {
    pub(super) fn read<T>(rows: &[T], has_location: impl Fn(&T) -> bool) -> Self {
        Self {
            observed: true,
            rows: rows.len().min(ROW_LIMIT),
            locations: rows
                .iter()
                .take(ROW_LIMIT)
                .filter(|row| has_location(row))
                .count(),
            truncated: rows.len() > ROW_LIMIT,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Outcome {
    Incomplete,
    HttpRejected,
    BodyReadFailed,
    JsonDecodeFailed,
    TypedDecodeFailed,
    ReturnDecodeFailed,
    Merged,
    ItemsFailed,
    ItemsSucceeded,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) enum ItemsStage {
    #[default]
    WriterGate,
    Inventory,
    Retrieval,
    AlignmentWrite,
    Publish,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) enum StepOutcome {
    #[default]
    NotReached,
    Pending,
    Succeeded,
    Failed,
    NotNeeded,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct CappedCount {
    rows: usize,
    truncated: bool,
}

impl CappedCount {
    pub(super) fn new(rows: usize) -> Self {
        Self {
            rows: rows.min(ROW_LIMIT),
            truncated: rows > ROW_LIMIT,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct ItemsProgress {
    pub(super) stage: ItemsStage,
    pub(super) writer_gate: StepOutcome,
    pub(super) alignment_write: StepOutcome,
    pub(super) inventory_owned: Option<CappedCount>,
    pub(super) inventory_shared_circles: Option<CappedCount>,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum JoinOutcome {
    #[default]
    NotReached,
    NotApplicable,
    NoLocations,
    Complete,
    Unmatched,
}

#[derive(Debug, Default)]
struct Join {
    outcome: JoinOutcome,
    matched: usize,
    unmatched: usize,
    // Typed None includes raw absent AND null; RawShape separates those cases.
    typed_none: usize,
    sampled: usize,
    truncated: bool,
}

impl Join {
    fn record(&mut self, matched: bool, has_location: bool) {
        if !matched {
            self.outcome = JoinOutcome::Unmatched;
        }
        if self.sampled == ROW_LIMIT {
            self.truncated = true;
            return;
        }
        self.sampled += 1;
        if matched {
            self.matched += 1;
            if !has_location {
                self.typed_none += 1;
            }
        } else {
            self.unmatched += 1;
        }
    }
}

// This type intentionally cannot hold a response, identity, location, or error.
#[derive(Debug)]
pub(super) struct Observation {
    service: Service,
    phase: Phase,
    pub(super) outcome: Outcome,
    raw: RawShape,
    before: Snapshot,
    pub(super) after: Snapshot,
    join: Join,
    items: Option<ItemsProgress>,
}

pub(super) fn items(observation: &mut Option<Observation>) -> Option<&mut ItemsProgress> {
    observation.as_mut()?.items.as_mut()
}

fn admit(enabled: bool, daemon: bool, path: &str, budget: &AtomicUsize) -> Option<Phase> {
    if !enabled || daemon {
        return None;
    }
    let phase = phase(path)?;
    budget
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            (used < REQUEST_LIMIT).then_some(used + 1)
        })
        .ok()?;
    Some(phase)
}

impl Observation {
    pub(super) fn start(
        service: Service,
        path: &str,
        daemon: bool,
        before: impl FnOnce() -> Snapshot,
    ) -> Option<Self> {
        // Check the gate before consulting the sink/budget or computing any counts.
        let enabled = option_env!("OPENBUBBLES_FINDMY_VERBOSE_DIAGNOSTICS") == Some("true");
        if !enabled {
            return None;
        }
        if !log::log_enabled!(target: "findmy_diagnostic", log::Level::Warn) {
            return None;
        }
        let budget = match service {
            Service::Fmf => &FMF_REQUESTS,
            Service::Fmip => &FMIP_REQUESTS,
            Service::Items => &ITEMS_REQUESTS,
        };
        let phase = admit(enabled, daemon, path, budget)?;
        Some(Self {
            service,
            phase,
            outcome: Outcome::Incomplete,
            raw: RawShape::default(),
            before: before(),
            after: Snapshot::default(),
            join: Join::default(),
            items: matches!(service, Service::Items).then(|| ItemsProgress {
                writer_gate: StepOutcome::Pending,
                ..Default::default()
            }),
        })
    }

    pub(super) fn raw(&mut self, raw: &Value) {
        self.raw = RawShape::read(raw, self.service);
    }

    pub(super) fn begin_join(&mut self, locations_present: bool) {
        self.join.outcome = match self.service {
            Service::Fmip | Service::Items => JoinOutcome::NotApplicable,
            Service::Fmf if locations_present => JoinOutcome::Complete,
            Service::Fmf => JoinOutcome::NoLocations,
        };
    }

    pub(super) fn join(&mut self, matched: bool, has_location: bool) {
        self.join.record(matched, has_location);
    }
}

// Record only an actual error, not a pending await that might be cancelled.
// E has no Display/Debug bound: private error values cannot be formatted here.
pub(super) fn result<T, E>(
    observation: &mut Option<Observation>,
    result: Result<T, E>,
    failure: Outcome,
) -> Result<T, E> {
    if let Some(record) = observation.as_mut() {
        if result.is_err() {
            record.outcome = failure;
        }
    }
    result
}

pub(super) fn body<T>(
    observation: &mut Option<Observation>,
    response: Result<T, reqwest::Error>,
) -> Result<T, reqwest::Error> {
    if observation.is_none() {
        return response;
    }
    let failure = if response
        .as_ref()
        .err()
        .is_some_and(|error| error.is_decode())
    {
        Outcome::JsonDecodeFailed
    } else {
        Outcome::BodyReadFailed
    };
    result(observation, response, failure)
}

impl Drop for Observation {
    fn drop(&mut self) {
        // Existing WARN sink is a transport, not a claim that Merged is an error.
        // One fixed-size aggregate record per admitted request, never broad DEBUG.
        log::warn!(target: "findmy_diagnostic", "Find My diagnostic {self:?}");
    }
}

// ---- IDS 242 shape-only observer ----
// Logs-only: fixed topic category, command, presence booleans, allowlisted
// T/V codes and P length buckets. Never values, ids, names, keys, tokens
// or error strings. Never acks, persists, requests keys or affects dispatch.
// Body-shape parsing runs only on command 242, a known topic and verified
// fresh-decrypt provenance; anything else is presence-only or skipped.
const IDS242_COMMAND: u8 = 242;
const IDS242_BODY_LIMIT: usize = 64 * 1024;
const IDS242_DEPTH_LIMIT: usize = 16;
const IDS242_EVENT_LIMIT: usize = 256;
const IDS242_DICT_KEYS: usize = 64;
static IDS242_SHAPES: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ids242Topic {
    Fmf,
    Fmd,
    ItemSharing,
}

fn ids242_topic(topic: &str) -> Option<Ids242Topic> {
    match topic {
        "com.apple.private.alloy.fmf" => Some(Ids242Topic::Fmf),
        "com.apple.private.alloy.fmd" => Some(Ids242Topic::Fmd),
        "com.apple.private.alloy.findmy.itemsharing-crossaccount" => Some(Ids242Topic::ItemSharing),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Ids242Presence {
    uuid: bool,
    sender: bool,
    target: bool,
    token: bool,
    time: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LenBucket {
    Empty,
    Tiny,
    Small,
    Medium,
    Large,
    XLarge,
    Over,
}

fn len_bucket(len: usize) -> LenBucket {
    match len {
        0 => LenBucket::Empty,
        1..=32 => LenBucket::Tiny,
        33..=64 => LenBucket::Small,
        65..=256 => LenBucket::Medium,
        257..=1024 => LenBucket::Large,
        1025..=65536 => LenBucket::XLarge,
        _ => LenBucket::Over,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ids242Key {
    P,
    T,
    V,
    Mapping,
    Other,
}

// Key names are compared, never stored: unknown names collapse to Other.
fn ids242_key(name: &str) -> Ids242Key {
    match name {
        "P" => Ids242Key::P,
        "T" => Ids242Key::T,
        "V" => Ids242Key::V,
        "kFMFServicePayloadKey" => Ids242Key::Mapping,
        _ => Ids242Key::Other,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntShape {
    Allowlisted(u32),
    Other,
}

// Only protocol type codes on T/V keys are ever recorded numerically;
// every other integer is class-only.
fn allowlisted_int(key: Ids242Key, value: u64) -> IntShape {
    let allowed = matches!(
        (key, value),
        (Ids242Key::T, 2 | 4 | 5 | 7 | 10) | (Ids242Key::V, 1)
    );
    match (allowed, u32::try_from(value)) {
        (true, Ok(exact)) => IntShape::Allowlisted(exact),
        _ => IntShape::Other,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueShape {
    Bool,
    Int(IntShape),
    Real,
    Date,
    Data(LenBucket),
    Text,
    Uid,
    Array,
    Dict,
    Other,
}

#[derive(Debug, Clone, Default)]
struct DictShape {
    entries: Vec<(Ids242Key, ValueShape)>,
    truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlistEncoding {
    Binary,
    Xml,
    Other,
}

fn sniff_plist_encoding(bytes: &[u8]) -> PlistEncoding {
    if bytes.starts_with(b"bplist00") {
        PlistEncoding::Binary
    } else if bytes.starts_with(b"<?xml") || bytes.starts_with(b"<plist") {
        PlistEncoding::Xml
    } else {
        PlistEncoding::Other
    }
}

#[derive(Debug, Clone)]
enum Ids242Body {
    // Provenance gate failed: presence only, no body inspection at all.
    Skipped,
    // Bytes exceeded the cap: length bucket only, no decode attempted.
    OverSize(LenBucket),
    // Magic sniff only (or undecodable input): encoding plus length bucket.
    Encoded(PlistEncoding, LenBucket),
    // Budgets tripped mid-walk: byte shape only.
    OverBudget(PlistEncoding, LenBucket),
    // Non-dict root: scalar class only, no further reads.
    Scalar(ValueShape),
    // Dict root walked within budgets. `inner` is Some only for the
    // single-P-Data envelope hop; `inner_budget` marks an inner walk
    // that tripped the shared event budget.
    Dict {
        outer: DictShape,
        inner: Option<DictShape>,
        inner_budget: bool,
    },
}

#[derive(Debug, Clone)]
struct Ids242Record {
    topic: Ids242Topic,
    command: u8,
    provenance: bool,
    presence: Ids242Presence,
    body: Ids242Body,
}

enum WalkFail {
    OverBudget,
    Malformed,
}

// Single-level walk result: a dict shape with retained first-P bytes for
// one envelope hop, or a scalar root class with nothing further to walk.
enum LevelShape {
    Dict(DictShape, Option<Vec<u8>>),
    Scalar(ValueShape),
}

fn push_shaped_entry(
    entries: &mut Vec<(Ids242Key, ValueShape)>,
    truncated: &mut bool,
    key: Ids242Key,
    value: ValueShape,
) {
    if entries.len() >= IDS242_DICT_KEYS {
        *truncated = true;
        return;
    }
    entries.push((key, value));
}

fn scalar_shape(event: &Event<'_>) -> ValueShape {
    match event {
        Event::Boolean(_) => ValueShape::Bool,
        Event::Integer(_) => ValueShape::Int(IntShape::Other),
        Event::Real(_) => ValueShape::Real,
        Event::Date(_) => ValueShape::Date,
        Event::Data(data) => ValueShape::Data(len_bucket(data.len())),
        Event::String(_) => ValueShape::Text,
        Event::Uid(_) => ValueShape::Uid,
        Event::StartArray(_) => ValueShape::Array,
        Event::StartDictionary(_) => ValueShape::Dict,
        Event::EndCollection => ValueShape::Other,
        // Non-exhaustive upstream enum: unknown future kinds stay class-only.
        _ => ValueShape::Other,
    }
}

// Bounded streaming preflight over plist bytes: no Value is ever built
// here. The caller caps input size; this walk additionally caps depth,
// events and recorded dict entries. Depth is per document; the driver
// allows at most one single-envelope inner hop sharing the same event
// budget, so total work stays bounded. Any trip degrades to
// byte-shape-only at the call site.
fn walk_plist_level(bytes: &[u8], budget: &mut usize) -> Result<LevelShape, WalkFail> {
    let mut reader = Reader::new(Cursor::new(bytes));
    // Root dispatch consumes one budgeted event: only dictionaries get a
    // shape walk. Any other root is a scalar record with no further reads.
    if *budget == 0 {
        return Err(WalkFail::OverBudget);
    }
    *budget -= 1;
    match reader.next() {
        None | Some(Err(_)) => return Err(WalkFail::Malformed),
        Some(Ok(Event::StartDictionary(_))) => {}
        Some(Ok(first)) => return Ok(LevelShape::Scalar(scalar_shape(&first))),
    }

    let mut depth = 1usize;
    let mut entries: Vec<(Ids242Key, ValueShape)> = Vec::new();
    let mut pending: Option<Ids242Key> = None;
    let mut truncated = false;
    let mut inner: Option<Vec<u8>> = None;
    let mut root_complete = false;
    let mut saw_end = false;
    while *budget > 0 && !root_complete {
        *budget -= 1;
        match reader.next() {
            None => {
                saw_end = true;
                break;
            }
            Some(Err(_)) => return Err(WalkFail::Malformed),
            Some(Ok(Event::StartDictionary(_))) => {
                if depth >= IDS242_DEPTH_LIMIT {
                    return Err(WalkFail::OverBudget);
                }
                if depth == 1 && pending.is_none() {
                    return Err(WalkFail::Malformed);
                }
                depth += 1;
                if let Some(key) = pending.take() {
                    push_shaped_entry(&mut entries, &mut truncated, key, ValueShape::Dict);
                }
            }
            Some(Ok(Event::StartArray(_))) => {
                if depth >= IDS242_DEPTH_LIMIT {
                    return Err(WalkFail::OverBudget);
                }
                if depth == 1 && pending.is_none() {
                    return Err(WalkFail::Malformed);
                }
                depth += 1;
                if let Some(key) = pending.take() {
                    push_shaped_entry(&mut entries, &mut truncated, key, ValueShape::Array);
                }
            }
            Some(Ok(Event::EndCollection)) => {
                if depth == 0 {
                    return Err(WalkFail::Malformed);
                }
                depth -= 1;
                if depth == 0 {
                    root_complete = true;
                }
            }
            Some(Ok(Event::String(text))) => {
                if depth != 1 {
                    continue;
                }
                if let Some(key) = pending.take() {
                    push_shaped_entry(&mut entries, &mut truncated, key, ValueShape::Text);
                } else {
                    pending = Some(ids242_key(&text));
                }
            }
            Some(Ok(Event::Boolean(_))) => {
                if depth != 1 {
                    continue;
                }
                let Some(key) = pending.take() else {
                    return Err(WalkFail::Malformed);
                };
                push_shaped_entry(&mut entries, &mut truncated, key, ValueShape::Bool);
            }
            Some(Ok(Event::Integer(number))) => {
                if depth != 1 {
                    continue;
                }
                let Some(key) = pending.take() else {
                    return Err(WalkFail::Malformed);
                };
                let shape = match number.as_unsigned() {
                    Some(raw) => allowlisted_int(key, raw),
                    None => IntShape::Other,
                };
                push_shaped_entry(&mut entries, &mut truncated, key, ValueShape::Int(shape));
            }
            Some(Ok(Event::Real(_))) => {
                if depth != 1 {
                    continue;
                }
                let Some(key) = pending.take() else {
                    return Err(WalkFail::Malformed);
                };
                push_shaped_entry(&mut entries, &mut truncated, key, ValueShape::Real);
            }
            Some(Ok(Event::Date(_))) => {
                if depth != 1 {
                    continue;
                }
                let Some(key) = pending.take() else {
                    return Err(WalkFail::Malformed);
                };
                push_shaped_entry(&mut entries, &mut truncated, key, ValueShape::Date);
            }
            Some(Ok(Event::Data(data))) => {
                if depth != 1 {
                    continue;
                }
                let Some(key) = pending.take() else {
                    return Err(WalkFail::Malformed);
                };
                let bucket = len_bucket(data.len());
                if key == Ids242Key::P && inner.is_none() {
                    inner = Some(data.into_owned());
                }
                push_shaped_entry(&mut entries, &mut truncated, key, ValueShape::Data(bucket));
            }
            Some(Ok(Event::Uid(_))) => {
                if depth != 1 {
                    continue;
                }
                let Some(key) = pending.take() else {
                    return Err(WalkFail::Malformed);
                };
                push_shaped_entry(&mut entries, &mut truncated, key, ValueShape::Uid);
            }
            // Non-exhaustive upstream enum: unknown future kinds cannot be
            // reasoned about, so degrade to byte-shape-only at the call site.
            _ => return Err(WalkFail::Malformed),
        }
    }
    if !root_complete {
        if saw_end {
            return Err(WalkFail::Malformed);
        }
        // Budget exhausted with the stream still open: a single peek
        // keeps an exact budget-sized fit honest without spending events.
        match reader.next() {
            None => return Err(WalkFail::Malformed),
            Some(_) => return Err(WalkFail::OverBudget),
        }
    }
    Ok(LevelShape::Dict(DictShape { entries, truncated }, inner))
}

fn shape_of_plist_bytes(bytes: &[u8]) -> Ids242Body {
    let total = len_bucket(bytes.len());
    if bytes.len() > IDS242_BODY_LIMIT {
        return Ids242Body::OverSize(total);
    }
    let encoding = sniff_plist_encoding(bytes);
    if encoding == PlistEncoding::Other {
        return Ids242Body::Encoded(encoding, total);
    }
    let mut budget = IDS242_EVENT_LIMIT;
    let (outer, inner_bytes) = match walk_plist_level(bytes, &mut budget) {
        Ok(LevelShape::Dict(shape, pending_inner)) => (shape, pending_inner),
        Ok(LevelShape::Scalar(class)) => return Ids242Body::Scalar(class),
        Err(WalkFail::OverBudget) => return Ids242Body::OverBudget(encoding, total),
        Err(WalkFail::Malformed) => return Ids242Body::Encoded(encoding, total),
    };
    // One single-P-Data envelope hop at most; anything else leaves inner empty.
    let single_envelope = outer.entries.len() == 1
        && matches!(
            outer.entries.first(),
            Some((Ids242Key::P, ValueShape::Data(_)))
        );
    let (inner, inner_budget) = match (single_envelope, inner_bytes) {
        (true, Some(nested)) => match walk_plist_level(&nested, &mut budget) {
            Ok(LevelShape::Dict(nested_shape, _)) => (Some(nested_shape), false),
            Ok(LevelShape::Scalar(_)) | Err(WalkFail::Malformed) => (None, false),
            Err(WalkFail::OverBudget) => (None, true),
        },
        _ => (None, false),
    };
    Ids242Body::Dict {
        outer,
        inner,
        inner_budget,
    }
}

impl Ids242Record {
    fn read(topic: Ids242Topic, msg: &IDSRecvMessage) -> Self {
        // Fresh-decrypt provenance plus the live encrypted-envelope
        // fields plus a resolved sender must all still hold at inspection time:
        // a reused or mutated message reaching body parsing. Wire `p`
        // bodies never satisfy this gate.
        let envelope = msg.fresh_decrypt
            && !msg.verification_failed
            && msg.sender.is_some()
            && msg.message.is_some()
            && msg.encryption.is_some();
        let body = if envelope {
            match &msg.message_unenc {
                Some(MessageBody::Bytes(bytes)) => shape_of_plist_bytes(bytes),
                // Provenance without the decrypt-produced byte form is
                // unexpected: observe presence only.
                _ => Ids242Body::Skipped,
            }
        } else {
            Ids242Body::Skipped
        };
        Self {
            topic,
            command: msg.command,
            provenance: msg.fresh_decrypt,
            presence: Ids242Presence {
                uuid: msg.uuid.is_some(),
                sender: msg.sender.is_some(),
                target: msg.target.is_some(),
                token: msg.token.is_some(),
                time: msg.ns_since_epoch.is_some(),
            },
            body,
        }
    }
}

fn admit_observe_ids242(command: u8, topic: &str) -> Option<Ids242Topic> {
    if command != IDS242_COMMAND {
        return None;
    }
    ids242_topic(topic)
}

fn admit_ids242_shape(budget: &AtomicUsize) -> bool {
    budget
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            (used < REQUEST_LIMIT).then_some(used + 1)
        })
        .is_ok()
}

pub(super) fn observe_ids242_shape(msg: Option<&IDSRecvMessage>) {
    if option_env!("OPENBUBBLES_FINDMY_VERBOSE_DIAGNOSTICS") != Some("true") {
        return;
    }
    if !log::log_enabled!(target: "findmy_diagnostic", log::Level::Warn) {
        return;
    }
    let Some(msg) = msg else { return };
    let Some(topic) = admit_observe_ids242(msg.command, msg.topic) else {
        return;
    };
    if !admit_ids242_shape(&IDS242_SHAPES) {
        return;
    }
    let record = Ids242Record::read(topic, msg);
    log::warn!(target: "findmy_diagnostic", "Find My IDS 242 shape {record:?}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn items_default_off_and_request_cap_use_existing_admission() {
        let budget = AtomicUsize::new(0);
        assert!(admit(false, false, "items", &budget).is_none());
        assert_eq!(budget.load(Ordering::Relaxed), 0);
        if option_env!("OPENBUBBLES_FINDMY_VERBOSE_DIAGNOSTICS") != Some("true") {
            assert!(Observation::start(Service::Items, "items", false, || {
                panic!("disabled Items diagnostics evaluated counts")
            })
            .is_none());
        }
        for _ in 0..REQUEST_LIMIT {
            assert!(admit(true, false, "items", &budget).is_some());
        }
        assert!(admit(true, false, "items", &budget).is_none());
    }

    #[test]
    fn items_counts_saturate_without_overflow_and_unobserved_is_not_zero() {
        for rows in [0, ROW_LIMIT, ROW_LIMIT + 1, usize::MAX] {
            let count = CappedCount::new(rows);
            assert_eq!(count.rows, rows.min(ROW_LIMIT));
            assert_eq!(count.truncated, rows > ROW_LIMIT);
        }
        let mut progress = ItemsProgress::default();
        assert!(progress.inventory_owned.is_none());
        assert_eq!(progress.alignment_write, StepOutcome::NotReached);
        progress.inventory_owned = Some(CappedCount::new(0));
        progress.inventory_shared_circles = Some(CappedCount::new(usize::MAX));
        let output = format!("{progress:?}");
        assert!(output.contains("rows: 0"));
        assert!(output.contains("rows: 256, truncated: true"));
        assert!(output.len() < 512);
    }

    #[test]
    fn items_error_keeps_fixed_stage_and_never_retains_the_error_value() {
        struct PrivateError;
        let mut observation = Some(Observation {
            service: Service::Items,
            phase: Phase::Refresh,
            outcome: Outcome::Incomplete,
            raw: RawShape::default(),
            before: Snapshot::default(),
            after: Snapshot::default(),
            join: Join::default(),
            items: Some(ItemsProgress {
                stage: ItemsStage::AlignmentWrite,
                writer_gate: StepOutcome::Succeeded,
                alignment_write: StepOutcome::Failed,
                inventory_owned: Some(CappedCount::new(usize::MAX)),
                inventory_shared_circles: Some(CappedCount::new(usize::MAX)),
            }),
        });
        assert!(result(
            &mut observation,
            Err::<(), _>(PrivateError),
            Outcome::ItemsFailed
        )
        .is_err());
        assert_eq!(
            items(&mut observation).unwrap().stage,
            ItemsStage::AlignmentWrite
        );
        let output = format!("Find My diagnostic {:?}", observation.as_ref().unwrap());
        assert!(output.contains("ItemsFailed"));
        assert!(!output.contains("PrivateError"));
        assert!(output.len() < 1024);
    }

    #[test]
    fn raw_shapes_separate_absent_null_object_and_never_echo_values() {
        let raw = RawShape::read(
            &json!({"locations": [
                {"id": "private-id"}, {"location": null},
                {"location": {"latitude": 12, "token": "private-token"}},
                {"location": "private-body"}, false
            ]}),
            Service::Fmf,
        );
        assert_eq!(
            (
                raw.location_absent,
                raw.location_null,
                raw.location_object,
                raw.location_other,
                raw.non_object_rows
            ),
            (1, 1, 1, 1, 1)
        );
        assert_eq!(raw.following, Shape::Absent);
        assert_eq!(shape(Some(&Value::Null)), Shape::Null);
        assert_eq!(shape(Some(&json!([]))), Shape::Array(0));
        let output = format!("{raw:?}");
        for forbidden in ["private", "latitude", "token", "id:"] {
            assert!(!output.contains(forbidden));
        }
    }

    #[test]
    fn counts_and_work_are_bounded() {
        let raw = RawShape::read(&json!({"locations": vec![json!({}); 300]}), Service::Fmf);
        assert_eq!(raw.location_absent, ROW_LIMIT);
        assert!(raw.truncated);
        let calls = std::cell::Cell::new(0);
        let snapshot = Snapshot::read(&vec![true; 300], |value| {
            calls.set(calls.get() + 1);
            *value
        });
        assert_eq!(calls.get(), ROW_LIMIT);
        assert_eq!((snapshot.rows, snapshot.locations), (ROW_LIMIT, ROW_LIMIT));
        assert!(snapshot.truncated);
        let mut join = Join::default();
        for _ in 0..300 {
            join.record(false, false);
        }
        assert_eq!(join.unmatched, ROW_LIMIT);
        assert!(join.truncated);
    }

    #[test]
    fn gate_daemon_and_unknown_paths_do_not_consume_budget() {
        let budget = AtomicUsize::new(0);
        assert!(admit(false, false, "initClient", &budget).is_none());
        assert!(admit(true, true, "initClient", &budget).is_none());
        assert!(admit(true, false, "private-path", &budget).is_none());
        assert_eq!(budget.load(Ordering::Relaxed), 0);
        for _ in 0..REQUEST_LIMIT {
            assert!(admit(true, false, "initClient", &budget).is_some());
        }
        assert!(admit(true, false, "initClient", &budget).is_none());
    }

    #[test]
    fn join_outcome_distinguishes_unmatched_and_typed_none() {
        let mut join = Join {
            outcome: JoinOutcome::Complete,
            ..Join::default()
        };
        join.record(true, true);
        join.record(true, false);
        join.record(false, true);
        assert_eq!((join.matched, join.unmatched, join.typed_none), (2, 1, 1));
        assert_eq!(join.outcome, JoinOutcome::Unmatched);
    }

    #[test]
    fn actual_response_model_distinguishes_decode_failure_from_absent_data() {
        use super::super::FindMyFriendsStateUpdate;
        assert!(serde_json::from_value::<FindMyFriendsStateUpdate>(json!({
            "dataContext": {}, "serverContext": {}
        }))
        .unwrap()
        .locations
        .is_none());
        for locations in [
            json!(null),
            json!([]),
            json!([{"id": "synthetic"}]),
            json!([{"id": "synthetic", "location": null}]),
        ] {
            let decoded = serde_json::from_value::<FindMyFriendsStateUpdate>(json!({
                "locations": locations, "dataContext": {}, "serverContext": {}
            }));
            assert!(decoded.is_ok());
        }
        let decoded = serde_json::from_value::<FindMyFriendsStateUpdate>(json!({
            "locations": [{"id": "synthetic", "location": {}}], "dataContext": {}, "serverContext": {}
        }));
        assert!(decoded.is_err());
    }

    #[test]
    fn failure_preserves_non_formattable_errors_and_success_values() {
        struct PrivateError;
        let mut disabled = None;
        assert!(result(
            &mut disabled,
            Err::<(), _>(PrivateError),
            Outcome::TypedDecodeFailed
        )
        .is_err());
        assert_eq!(
            result(
                &mut disabled,
                Ok::<_, PrivateError>(7),
                Outcome::TypedDecodeFailed
            )
            .ok(),
            Some(7)
        );
    }

    #[test]
    fn output_is_bounded_and_error_outcomes_require_an_actual_error() {
        let mut observation = Some(Observation {
            service: Service::Fmf,
            phase: Phase::Init,
            outcome: Outcome::Incomplete,
            raw: RawShape::default(),
            before: Snapshot::default(),
            after: Snapshot::default(),
            join: Join::default(),
            items: None,
        });
        assert!(result(
            &mut observation,
            Ok::<_, ()>(()),
            Outcome::TypedDecodeFailed
        )
        .is_ok());
        assert!(matches!(
            observation.as_ref().unwrap().outcome,
            Outcome::Incomplete
        ));
        assert!(result(
            &mut observation,
            Err::<(), _>(()),
            Outcome::TypedDecodeFailed
        )
        .is_err());
        assert!(matches!(
            observation.as_ref().unwrap().outcome,
            Outcome::TypedDecodeFailed
        ));
        assert!(format!("Find My diagnostic {:?}", observation.as_ref().unwrap()).len() < 1024);
    }

    use crate::ids::{IDSRecvMessage, MessageBody};

    const IDS242_SECRET: &str = "SECRET-marker";

    fn test_242_message(body: Option<MessageBody>, fresh_decrypt: bool) -> IDSRecvMessage {
        IDSRecvMessage {
            command: 242,
            ns_since_epoch: None,
            uuid: None,
            sender: Some("synthetic-sender".to_string()),
            token: None,
            target: Some("synthetic-target".to_string()),
            no_reply: None,
            is_typing: None,
            send_delivered: None,
            message_unenc: body,
            // Post-decrypt envelope state: encrypted bytes plus mode.
            // Tests that need them absent clear them explicitly.
            message: Some(vec![9u8; 16]),
            encryption: Some("synthetic-encryption".to_string()),
            status: None,
            error_for: None,
            error_string: None,
            error_status: None,
            error_for_str: None,
            certified_delivery_version: None,
            certified_delivery_receipt: None,
            verification_failed: false,
            fresh_decrypt,
            topic: "com.apple.private.alloy.fmf",
        }
    }

    fn bplist_bytes(value: &plist::Value) -> Vec<u8> {
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, value).unwrap();
        buf
    }

    fn plist_dict(pairs: Vec<(&str, plist::Value)>) -> plist::Value {
        let mut dict = plist::Dictionary::new();
        for (key, value) in pairs {
            dict.insert(key.to_string(), value);
        }
        plist::Value::Dictionary(dict)
    }

    fn secret_plist_body() -> MessageBody {
        // Spoof-shaped wire `p`: secrets in keys, values and bytes.
        let mut dict = plist::Dictionary::new();
        dict.insert(
            format!("{}-key", IDS242_SECRET),
            plist::Value::String(format!("{}-value", IDS242_SECRET)),
        );
        dict.insert("T".to_string(), plist::to_value(&10).unwrap());
        MessageBody::Plist(plist::Value::Dictionary(dict))
    }

    #[test]
    fn ids242_spoofed_wire_p_body_is_presence_only() {
        // Wire-supplied `p` with no fresh-decrypt provenance: the body is
        // never inspected, but missing uuid/token/time stay observable.
        let msg = test_242_message(Some(secret_plist_body()), false);
        let record = Ids242Record::read(Ids242Topic::Fmf, &msg);
        assert!(!record.provenance);
        assert!(matches!(record.body, Ids242Body::Skipped));
        assert!(!record.presence.uuid);
        assert!(!record.presence.token);
        assert!(!record.presence.time);
        assert!(record.presence.sender);
        assert!(record.presence.target);
        let output = format!("{record:?}");
        assert!(!output.contains(IDS242_SECRET));
        assert!(output.len() < 1024);
    }

    #[test]
    fn ids242_key_failure_bytes_are_not_parsed() {
        // Decrypt/identity failure leaves provenance false: even byte
        // bodies stay unparsed.
        let body = plist_dict(vec![("P", plist::Value::Data(vec![7u8; 28]))]);
        let msg = test_242_message(Some(MessageBody::Bytes(bplist_bytes(&body))), false);
        let record = Ids242Record::read(Ids242Topic::Fmf, &msg);
        assert!(matches!(record.body, Ids242Body::Skipped));
    }

    #[test]
    fn ids242_reused_mutated_message_stays_skipped() {
        // Fresh provenance but a later mutation tripped the verification
        // flag or dropped the envelope fields: body parsing must not run.
        let mut dict = plist::Dictionary::new();
        dict.insert("T".to_string(), plist::to_value(&10).unwrap());
        let body = plist::Value::Dictionary(dict);
        let mut tripped = test_242_message(Some(MessageBody::Bytes(bplist_bytes(&body))), true);
        tripped.verification_failed = true;
        assert!(matches!(
            Ids242Record::read(Ids242Topic::Fmf, &tripped).body,
            Ids242Body::Skipped
        ));
        let mut dropped = test_242_message(Some(MessageBody::Bytes(bplist_bytes(&body))), true);
        dropped.message = None;
        dropped.encryption = None;
        assert!(matches!(
            Ids242Record::read(Ids242Topic::Fmf, &dropped).body,
            Ids242Body::Skipped
        ));
    }

    #[test]
    fn ids242_provenance_true_parses_tv_and_p_bucket() {
        let mut dict = plist::Dictionary::new();
        dict.insert("T".to_string(), plist::to_value(&10).unwrap());
        dict.insert("V".to_string(), plist::to_value(&1).unwrap());
        dict.insert("P".to_string(), plist::Value::Data(vec![0u8; 28]));
        let body = plist::Value::Dictionary(dict);
        let msg = test_242_message(Some(MessageBody::Bytes(bplist_bytes(&body))), true);
        let record = Ids242Record::read(Ids242Topic::ItemSharing, &msg);
        assert!(record.provenance);
        match record.body {
            Ids242Body::Dict {
                outer,
                inner,
                inner_budget,
            } => {
                assert_eq!(outer.entries.len(), 3);
                assert!(outer
                    .entries
                    .contains(&(Ids242Key::T, ValueShape::Int(IntShape::Allowlisted(10)))));
                assert!(outer
                    .entries
                    .contains(&(Ids242Key::V, ValueShape::Int(IntShape::Allowlisted(1)))));
                assert!(outer
                    .entries
                    .contains(&(Ids242Key::P, ValueShape::Data(LenBucket::Tiny))));
                assert!(inner.is_none());
                assert!(!inner_budget);
            }
            other => panic!("expected dict body, got {other:?}"),
        }
    }

    #[test]
    fn ids242_allowlist_rejects_unknown_codes() {
        let mut dict = plist::Dictionary::new();
        dict.insert("T".to_string(), plist::to_value(&99).unwrap());
        dict.insert("V".to_string(), plist::to_value(&7).unwrap());
        let body = plist::Value::Dictionary(dict);
        let msg = test_242_message(Some(MessageBody::Bytes(bplist_bytes(&body))), true);
        let record = Ids242Record::read(Ids242Topic::Fmf, &msg);
        match &record.body {
            Ids242Body::Dict { outer, .. } => {
                assert!(outer
                    .entries
                    .contains(&(Ids242Key::T, ValueShape::Int(IntShape::Other))));
                assert!(outer
                    .entries
                    .contains(&(Ids242Key::V, ValueShape::Int(IntShape::Other))));
            }
            other => panic!("expected dict body, got {other:?}"),
        }
        let output = format!("{record:?}");
        assert!(!output.contains("99"));
    }

    #[test]
    fn ids242_envelope_inner_dict_parsed() {
        let mut inner = plist::Dictionary::new();
        inner.insert("T".to_string(), plist::to_value(&4).unwrap());
        inner.insert("V".to_string(), plist::to_value(&1).unwrap());
        let inner_bytes = bplist_bytes(&plist::Value::Dictionary(inner));
        let outer = plist_dict(vec![("P", plist::Value::Data(inner_bytes))]);
        let msg = test_242_message(Some(MessageBody::Bytes(bplist_bytes(&outer))), true);
        let record = Ids242Record::read(Ids242Topic::Fmf, &msg);
        match record.body {
            Ids242Body::Dict {
                outer,
                inner,
                inner_budget,
            } => {
                assert_eq!(outer.entries.len(), 1);
                assert!(!inner_budget);
                match inner {
                    Some(nested) => {
                        assert!(nested
                            .entries
                            .contains(&(Ids242Key::T, ValueShape::Int(IntShape::Allowlisted(4)))));
                        assert!(nested
                            .entries
                            .contains(&(Ids242Key::V, ValueShape::Int(IntShape::Allowlisted(1)))));
                    }
                    None => panic!("expected nested inner"),
                }
            }
            other => panic!("expected dict body, got {other:?}"),
        }
    }

    #[test]
    fn ids242_oversize_reports_bytes_only() {
        let record = Ids242Record::read(
            Ids242Topic::Fmf,
            &test_242_message(Some(MessageBody::Bytes(vec![0u8; 65537])), true),
        );
        assert!(matches!(record.body, Ids242Body::OverSize(LenBucket::Over)));
    }

    #[test]
    fn ids242_garbage_reports_encoding_only() {
        let bytes = b"definitely-not-a-plist-payload".to_vec();
        let record = Ids242Record::read(
            Ids242Topic::Fmd,
            &test_242_message(Some(MessageBody::Bytes(bytes)), true),
        );
        assert!(matches!(
            record.body,
            Ids242Body::Encoded(PlistEncoding::Other, LenBucket::Tiny)
        ));
    }

    #[test]
    fn ids242_deep_nesting_trips_budget() {
        let mut nested = serde_json::json!({"leaf": 1});
        for _ in 0..20 {
            nested = serde_json::json!({"k": nested});
        }
        let body = plist::to_value(&nested).unwrap();
        let msg = test_242_message(Some(MessageBody::Bytes(bplist_bytes(&body))), true);
        let record = Ids242Record::read(Ids242Topic::Fmf, &msg);
        assert!(matches!(record.body, Ids242Body::OverBudget(_, _)));
    }

    #[test]
    fn ids242_malformed_binary_length_stays_bounded() {
        let mut dict = plist::Dictionary::new();
        dict.insert("T".to_string(), plist::to_value(&10).unwrap());
        dict.insert("P".to_string(), plist::Value::Data(vec![7u8; 64]));
        let mut full = bplist_bytes(&plist::Value::Dictionary(dict));
        full.truncate(full.len().saturating_sub(24));
        let record = Ids242Record::read(
            Ids242Topic::Fmf,
            &test_242_message(Some(MessageBody::Bytes(full)), true),
        );
        assert!(matches!(record.body, Ids242Body::Encoded(_, _)));
        let output = format!("{record:?}");
        assert!(output.len() < 1024);
        let short = b"bplist00".to_vec();
        let record = Ids242Record::read(
            Ids242Topic::Fmf,
            &test_242_message(Some(MessageBody::Bytes(short)), true),
        );
        assert!(matches!(record.body, Ids242Body::Encoded(_, _)));
    }

    #[test]
    fn ids242_non_dict_root_is_scalar() {
        let body = plist::to_value(&serde_json::json!([1, 2, 3])).unwrap();
        let msg = test_242_message(Some(MessageBody::Bytes(bplist_bytes(&body))), true);
        let record = Ids242Record::read(Ids242Topic::Fmf, &msg);
        match record.body {
            Ids242Body::Scalar(ValueShape::Array) => {}
            other => panic!("expected scalar body, got {other:?}"),
        }
    }

    #[test]
    fn ids242_command_and_topic_gate() {
        assert!(admit_observe_ids242(100, "com.apple.private.alloy.fmf").is_none());
        assert!(admit_observe_ids242(242, "com.apple.private.alloy.unknown").is_none());
        assert_eq!(
            admit_observe_ids242(242, "com.apple.private.alloy.fmd"),
            Some(Ids242Topic::Fmd)
        );
    }

    #[test]
    fn ids242_budget_caps_records() {
        let budget = AtomicUsize::new(0);
        for _ in 0..REQUEST_LIMIT {
            assert!(admit_ids242_shape(&budget));
        }
        assert!(!admit_ids242_shape(&budget));
    }

    #[test]
    fn ids242_no_secret_output_on_hostile_bytes() {
        // Secrets in envelope fields, dict keys/values and P bytes must
        // never appear in the fixed-size record.
        let mut hostile = test_242_message(
            Some(MessageBody::Bytes({
                let mut dict = plist::Dictionary::new();
                dict.insert(
                    format!("{}-key", IDS242_SECRET),
                    plist::Value::String(format!("{}-value", IDS242_SECRET)),
                );
                dict.insert("T".to_string(), plist::to_value(&10).unwrap());
                dict.insert("V".to_string(), plist::to_value(&1).unwrap());
                dict.insert(
                    "P".to_string(),
                    plist::Value::Data(format!("{}-bytes", IDS242_SECRET).into_bytes()),
                );
                bplist_bytes(&plist::Value::Dictionary(dict))
            })),
            true,
        );
        hostile.sender = Some(format!("{}-sender", IDS242_SECRET));
        hostile.uuid = Some(format!("{}-uuid", IDS242_SECRET).into_bytes());
        hostile.error_string = Some(format!("{}-error", IDS242_SECRET));
        let record = Ids242Record::read(Ids242Topic::Fmf, &hostile);
        let output = format!("{record:?}");
        assert!(!output.contains(IDS242_SECRET));
        assert!(output.len() < 1024);
    }
}
