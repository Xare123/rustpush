use uuid::Uuid;

/// Process/client-owned notification admission, not a CloudKit cursor or permit.
/// Keep a warm binding while reconfiguring, but never accept its old nonce.
pub(super) struct ChangeNotificationState<T> {
    requested: Option<String>,
    pub(super) active: Option<(String, T)>,
}

impl<T> Default for ChangeNotificationState<T> {
    fn default() -> Self {
        Self {
            requested: None,
            active: None,
        }
    }
}

impl<T> ChangeNotificationState<T> {
    pub(super) fn begin(&mut self) -> String {
        let nonce = Uuid::new_v4().to_string();
        self.requested = Some(nonce.clone());
        nonce
    }

    pub(super) fn requested(&self, nonce: &str) -> bool {
        !nonce.is_empty() && self.requested.as_deref() == Some(nonce)
    }

    pub(super) fn current(&self, nonce: &str) -> bool {
        self.requested(nonce)
            && self
                .active
                .as_ref()
                .is_some_and(|(active, _)| active == nonce)
    }

    pub(super) fn install(&mut self, nonce: &str, binding: T) -> bool {
        if !self.requested(nonce) {
            return false;
        }
        self.active = Some((nonce.to_owned(), binding));
        true
    }

    pub(super) fn adopt_warm(&mut self, nonce: &str) -> bool {
        if !self.requested(nonce) {
            return false;
        }
        let Some((active, _)) = self.active.as_mut() else {
            return false;
        };
        *active = nonce.to_owned();
        true
    }

    /// A late failed setup may retire only its own request, never a successor.
    pub(super) fn disable(&mut self, expected: Option<&str>) -> bool {
        if expected.is_some_and(|nonce| !self.requested(nonce)) {
            return false;
        }
        self.requested = None;
        self.active = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct DropBinding(Arc<AtomicUsize>);
    impl Drop for DropBinding {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn default_and_empty_nonce_do_not_admit_notifications() {
        let state = ChangeNotificationState::<()>::default();
        assert!(!state.current(""));
        assert!(!state.current("unregistered"));
    }

    #[test]
    fn request_alone_is_not_a_completed_registration() {
        let mut state = ChangeNotificationState::default();
        let nonce = state.begin();
        assert!(state.requested(&nonce));
        assert!(!state.current(&nonce));
        assert!(state.install(&nonce, ()));
        assert!(state.current(&nonce));
    }

    #[test]
    fn replacement_revokes_old_admission_but_retains_warm_binding() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut state = ChangeNotificationState::default();
        let first = state.begin();
        assert!(state.install(&first, DropBinding(drops.clone())));
        let second = state.begin();
        assert_ne!(first, second);
        assert!(!state.current(&first));
        assert!(!state.current(&second));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(state.adopt_warm(&second));
        assert!(state.current(&second));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn stale_completion_cannot_replace_newer_binding() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut state = ChangeNotificationState::default();
        let first = state.begin();
        let second = state.begin();
        assert!(state.install(&second, DropBinding(drops.clone())));
        assert!(!state.install(&first, DropBinding(drops.clone())));
        assert!(state.current(&second));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn late_failure_cannot_disable_a_newer_setup() {
        let mut state = ChangeNotificationState::default();
        let first = state.begin();
        let second = state.begin();
        assert!(state.install(&second, ()));
        assert!(!state.disable(Some(&first)));
        assert!(state.current(&second));
    }

    #[test]
    fn disable_drops_owned_binding_and_fences_late_completion() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut state = ChangeNotificationState::default();
        let nonce = state.begin();
        assert!(state.install(&nonce, DropBinding(drops.clone())));
        assert!(state.disable(None));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(!state.current(&nonce));
        assert!(!state.install(&nonce, DropBinding(drops.clone())));
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn exact_failure_disables_only_the_current_request() {
        let mut state = ChangeNotificationState::default();
        let nonce = state.begin();
        assert!(state.install(&nonce, ()));
        assert!(state.disable(Some(&nonce)));
        assert!(!state.current(&nonce));
        assert!(!state.adopt_warm(&nonce));
    }
}
