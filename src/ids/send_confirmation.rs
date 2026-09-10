//! Positive IDS acknowledgment evidence, separate from a SendJob finishing.
//! One accepted device per intended participant is sufficient; an offline
//! sibling device must not erase a participant's actual acceptance. This is
//! server acceptance evidence, not a read receipt or independent UI proof.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use crate::PushError;

#[derive(Clone)]
pub struct SendConfirmation {
    required: Arc<HashSet<String>>,
    accepted: Arc<Mutex<HashSet<String>>>,
    supports_confirmation: bool,
}

impl SendConfirmation {
    pub(crate) fn new<'a>(
        sender: &str,
        participants: impl Iterator<Item = &'a str>,
        supports_confirmation: bool,
    ) -> Self {
        let mut required: HashSet<String> = participants.map(str::to_owned).collect();
        // Self-device fanout is not an additional remote recipient. A genuine
        // self-only send still requires acceptance from another target device.
        if required.iter().any(|participant| participant != sender) {
            required.remove(sender);
        }
        Self {
            required: Arc::new(required),
            accepted: Arc::new(Mutex::new(HashSet::new())),
            supports_confirmation,
        }
    }

    pub(crate) fn record_status(&self, participant: &str, status: i64) {
        // Match the send path's existing accepted statuses. Refresh requests,
        // missing responses and APSError progress are not positive evidence.
        if matches!(status, 0 | 5008) && self.required.contains(participant) {
            if let Ok(mut accepted) = self.accepted.lock() {
                accepted.insert(participant.to_owned());
            }
        }
    }

    pub(crate) fn requiring_participants<'a>(
        mut self,
        participants: impl Iterator<Item = &'a str>,
    ) -> Self {
        // The caller knows the intended route before target lookup. Retain
        // recipients with no cached device, rather than shrinking a group to
        // whichever participants happened to produce DeliveryHandles.
        Arc::make_mut(&mut self.required).extend(participants.map(str::to_owned));
        self
    }

    /// Call after the send job completes successfully, never instead of
    /// waiting for it. Failure is intentionally content-free. Ordinary IDS
    /// progress reporting is unchanged; strict CloudKit callers opt in.
    pub fn require_confirmed(&self) -> Result<(), PushError> {
        if !self.supports_confirmation || self.required.is_empty() {
            return Err(PushError::NoValidTargets);
        }
        let accepted = self.accepted.lock().map_err(|_| PushError::BadMsg)?;
        if !self.required.is_subset(&accepted) {
            return Err(PushError::SendTimedOut);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(participants: &[&str]) -> SendConfirmation {
        SendConfirmation::new("sender", participants.iter().copied(), true)
    }

    #[test]
    fn empty_targets_and_unanswered_jobs_never_confirm() {
        assert!(proof(&[]).require_confirmed().is_err());
        assert!(proof(&["recipient"]).require_confirmed().is_err());
    }

    #[test]
    fn all_external_participants_need_positive_acceptance() {
        let evidence = proof(&["sender", "first", "first", "second"]);
        evidence.record_status("first", 0);
        evidence.record_status("sender", 0);
        assert!(evidence.require_confirmed().is_err());
        evidence.record_status("second", 5008);
        assert!(evidence.require_confirmed().is_ok());
    }

    #[test]
    fn no_response_and_relay_modes_cannot_manufacture_confirmation() {
        let evidence = SendConfirmation::new("sender", ["recipient"].into_iter(), false);
        evidence.record_status("recipient", 0);
        assert!(evidence.require_confirmed().is_err());
    }

    #[test]
    fn errors_refresh_and_foreign_acknowledgments_are_not_acceptance() {
        let evidence = proof(&["recipient"]);
        evidence.record_status("foreign", 0);
        evidence.record_status("recipient", 5032);
        evidence.record_status("recipient", 6005);
        assert!(evidence.require_confirmed().is_err());
    }

    #[test]
    fn retry_clones_retain_acceptance_without_erasing_other_participants() {
        let evidence = proof(&["first", "second"]);
        evidence.record_status("first", 0);
        let retry = evidence.clone();
        retry.record_status("second", 0);
        retry.record_status("first", 6005);
        assert!(evidence.require_confirmed().is_ok());
    }

    #[test]
    fn self_only_send_requires_an_actual_other_device_acknowledgment() {
        let evidence = proof(&["sender"]);
        assert!(evidence.require_confirmed().is_err());
        evidence.record_status("sender", 0);
        assert!(evidence.require_confirmed().is_ok());
    }

    #[test]
    fn missing_group_target_cannot_shrink_the_required_route() {
        let dispatched = proof(&["first"]);
        dispatched.record_status("first", 0);
        assert!(dispatched.require_confirmed().is_ok());
        let complete_route = dispatched.requiring_participants(["first", "second"].into_iter());
        assert!(complete_route.require_confirmed().is_err());
    }
}
