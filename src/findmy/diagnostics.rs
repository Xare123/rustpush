//! Opt-in, value-free diagnostics for FMF/FMIP responses and Items refreshes.
//! Native compilation: OPENBUBBLES_FINDMY_VERBOSE_DIAGNOSTICS=true.
//! No runtime environment reads, requests, logger configuration, or retained rows.
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

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
        Self { rows: rows.min(ROW_LIMIT), truncated: rows > ROW_LIMIT }
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
            }).is_none());
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
            service: Service::Items, phase: Phase::Refresh, outcome: Outcome::Incomplete,
            raw: RawShape::default(), before: Snapshot::default(), after: Snapshot::default(),
            join: Join::default(), items: Some(ItemsProgress {
                stage: ItemsStage::AlignmentWrite,
                writer_gate: StepOutcome::Succeeded,
                alignment_write: StepOutcome::Failed,
                inventory_owned: Some(CappedCount::new(usize::MAX)),
                inventory_shared_circles: Some(CappedCount::new(usize::MAX)),
            }),
        });
        assert!(result(&mut observation, Err::<(), _>(PrivateError), Outcome::ItemsFailed).is_err());
        assert_eq!(items(&mut observation).unwrap().stage, ItemsStage::AlignmentWrite);
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
}
