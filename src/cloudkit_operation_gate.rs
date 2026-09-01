use std::{
    collections::VecDeque,
    future::Future,
    io::ErrorKind,
    sync::{Arc, LazyLock, Mutex, MutexGuard},
    time::Duration,
};

use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use crate::PushError;

tokio::task_local! {
    static CLOUDKIT_WRITER_OPERATION_SCOPE: ();
}

const PAUSE_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);
const OPERATION_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_TERMINAL_PAUSE_TOKENS: usize = 64;

/// Opaque permit held for the complete duration of a native CloudKit writer operation.
pub struct CloudKitWriterOperationPermit {
    _permit: OwnedRwLockReadGuard<()>,
}

struct CloudKitWriterPause {
    token: u64,
    generation: u64,
    _permit: OwnedRwLockWriteGuard<()>,
}

struct CloudKitWriterPauseState {
    pending: Option<u64>,
    active: Option<CloudKitWriterPause>,
    active_read_authentication_scopes: usize,
    next_pause_generation: u64,
    terminal_tokens: VecDeque<u64>,
    last_terminal_token: Option<u64>,
}

/// Non-cloneable capability for the three allowlisted CloudKit read-auth
/// container initializations owned by one exact native writer pause.
pub struct CloudKitReadAuthenticationPermit<'a> {
    gate: &'a CloudKitWriterOperationGate,
    token: u64,
    generation: u64,
}

impl CloudKitReadAuthenticationPermit<'_> {
    pub(crate) fn validate(&self) -> Result<(), PushError> {
        self.gate
            .validate_read_authentication(self.token, self.generation)
    }
}

impl Drop for CloudKitReadAuthenticationPermit<'_> {
    fn drop(&mut self) {
        let mut pause = self.gate.pause_state();
        let still_owned = pause.active.as_ref().is_some_and(|active| {
            active.token == self.token && active.generation == self.generation
        });
        debug_assert!(
            still_owned,
            "CloudKit read-authentication permit lost its pause"
        );
        if !still_owned {
            return;
        }
        pause.active_read_authentication_scopes = pause
            .active_read_authentication_scopes
            .checked_sub(1)
            .expect("CloudKit read-authentication scope underflow");
    }
}

impl CloudKitWriterPauseState {
    fn remember_terminal_token(&mut self, token: u64) {
        if let Some(index) = self
            .terminal_tokens
            .iter()
            .position(|candidate| *candidate == token)
        {
            self.terminal_tokens.remove(index);
        }
        self.terminal_tokens.push_back(token);
        self.last_terminal_token = Some(token);
        while self.terminal_tokens.len() > MAX_TERMINAL_PAUSE_TOKENS {
            self.terminal_tokens.pop_front();
        }
    }
}

struct CloudKitWriterOperationGate {
    // Tokio's RwLock uses a fair, write-preferring FIFO policy. Once a pause is waiting,
    // later writer operations cannot starve it by entering ahead of the write permit.
    operations: Arc<RwLock<()>>,
    // This synchronous admission lock makes the pending-state check and try-read acquisition
    // one critical section. It must never be held across an await.
    pause: Mutex<CloudKitWriterPauseState>,
    pause_acquire_timeout: Duration,
    operation_acquire_timeout: Duration,
}

struct PendingCloudKitWriterPause<'a> {
    gate: &'a CloudKitWriterOperationGate,
    token: u64,
    armed: bool,
}

impl PendingCloudKitWriterPause<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingCloudKitWriterPause<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut pause = self.gate.pause_state();
            if pause.pending == Some(self.token) {
                pause.pending = None;
            }
        }
    }
}

impl CloudKitWriterOperationGate {
    fn new(pause_acquire_timeout: Duration, operation_acquire_timeout: Duration) -> Self {
        Self {
            operations: Arc::new(RwLock::new(())),
            pause: Mutex::new(CloudKitWriterPauseState {
                pending: None,
                active: None,
                active_read_authentication_scopes: 0,
                next_pause_generation: 0,
                terminal_tokens: VecDeque::new(),
                last_terminal_token: None,
            }),
            pause_acquire_timeout,
            operation_acquire_timeout,
        }
    }

    fn pause_state(&self) -> MutexGuard<'_, CloudKitWriterPauseState> {
        self.pause
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn begin_pause(&self, token: u64) -> Result<Option<PendingCloudKitWriterPause<'_>>, PushError> {
        if token == 0 {
            return invalid_pause_token();
        }

        let mut pause = self.pause_state();
        if let Some(active) = pause.active.as_ref() {
            if active.token == token {
                return Ok(None);
            }
            return Err(pause_conflict(
                "CloudKit writer operations are already paused",
            ));
        }

        if let Some(pending) = pause.pending {
            if pending == token {
                return Err(PushError::IoError(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    "CloudKit writer pause is already pending for this token",
                )));
            }
            return Err(pause_conflict(
                "CloudKit writer operations already have a different pending pause",
            ));
        }

        if pause.terminal_tokens.contains(&token) {
            return invalid_pause_token();
        }

        pause.pending = Some(token);
        Ok(Some(PendingCloudKitWriterPause {
            gate: self,
            token,
            armed: true,
        }))
    }

    async fn acquire_operation(&self) -> Result<CloudKitWriterOperationPermit, PushError> {
        tokio::time::timeout(
            self.operation_acquire_timeout,
            self.operations.clone().read_owned(),
        )
        .await
        .map(|permit| CloudKitWriterOperationPermit { _permit: permit })
        .map_err(|_| {
            PushError::IoError(std::io::Error::new(
                ErrorKind::TimedOut,
                "CloudKit writer operations are paused",
            ))
        })
    }

    fn try_acquire_operation(&self) -> Result<CloudKitWriterOperationPermit, PushError> {
        let pause = self.pause_state();
        if pause.pending.is_some() || pause.active.is_some() {
            return Err(PushError::IoError(std::io::Error::new(
                ErrorKind::WouldBlock,
                "CloudKit writer operations are paused or pause is pending",
            )));
        }

        self.operations
            .clone()
            .try_read_owned()
            .map(|permit| CloudKitWriterOperationPermit { _permit: permit })
            .map_err(|_| {
                PushError::IoError(std::io::Error::new(
                    ErrorKind::WouldBlock,
                    "CloudKit writer operation is unavailable",
                ))
            })
    }

    fn begin_read_authentication(
        &self,
        token: u64,
    ) -> Result<CloudKitReadAuthenticationPermit<'_>, PushError> {
        if token == 0 {
            return invalid_pause_token();
        }
        let mut pause = self.pause_state();
        let generation = match pause.active.as_ref() {
            Some(active) if active.token == token => active.generation,
            _ => return invalid_pause_token(),
        };
        pause.active_read_authentication_scopes = pause
            .active_read_authentication_scopes
            .checked_add(1)
            .ok_or_else(|| {
                PushError::IoError(std::io::Error::new(
                    ErrorKind::WouldBlock,
                    "too many CloudKit read-authentication scopes",
                ))
            })?;
        Ok(CloudKitReadAuthenticationPermit {
            gate: self,
            token,
            generation,
        })
    }

    fn validate_read_authentication(&self, token: u64, generation: u64) -> Result<(), PushError> {
        let pause = self.pause_state();
        if pause.active_read_authentication_scopes == 0
            || !pause
                .active
                .as_ref()
                .is_some_and(|active| active.token == token && active.generation == generation)
        {
            return invalid_pause_token();
        }
        Ok(())
    }

    async fn pause(&self, token: u64) -> Result<u64, PushError> {
        if token == 0 {
            return invalid_pause_token();
        }

        let deadline = tokio::time::Instant::now() + self.pause_acquire_timeout;
        let Some(mut pending) = self.begin_pause(token)? else {
            return Ok(token);
        };

        let permit = tokio::time::timeout_at(deadline, self.operations.clone().write_owned())
            .await
            .map_err(|_| {
                PushError::IoError(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "timed out waiting to pause CloudKit writer operations",
                ))
            })?;

        {
            let mut pause = self.pause_state();
            if pause.pending == Some(token) && pause.active.is_none() {
                let generation = pause.next_pause_generation.checked_add(1).ok_or_else(|| {
                    PushError::IoError(std::io::Error::new(
                        ErrorKind::WouldBlock,
                        "CloudKit writer pause generation exhausted",
                    ))
                })?;
                pause.next_pause_generation = generation;
                pause.pending = None;
                pause.active = Some(CloudKitWriterPause {
                    token,
                    generation,
                    _permit: permit,
                });
                pending.disarm();
                return Ok(token);
            }
        }

        Err(PushError::IoError(std::io::Error::new(
            ErrorKind::Interrupted,
            "CloudKit writer pause was canceled before activation",
        )))
    }

    async fn resume(&self, token: u64) -> Result<(), PushError> {
        let mut pause = self.pause_state();
        if token == 0 {
            return invalid_pause_token();
        }

        if pause.active.as_ref().map(|active| active.token) == Some(token) {
            if pause.active_read_authentication_scopes != 0 {
                return Err(PushError::IoError(std::io::Error::new(
                    ErrorKind::WouldBlock,
                    "CloudKit read authentication is still active",
                )));
            }
            drop(pause.active.take());
            pause.remember_terminal_token(token);
            return Ok(());
        }

        if pause.pending == Some(token) {
            pause.pending = None;
            pause.remember_terminal_token(token);
            return Ok(());
        }

        if pause.pending.is_none() && pause.active.is_none() {
            if pause.last_terminal_token == Some(token) {
                return Ok(());
            }
            if pause.terminal_tokens.contains(&token) {
                return invalid_pause_token();
            }
            // A bridge timeout does not cancel the underlying native call. If
            // cleanup reaches an idle gate before that delayed call begins,
            // tombstone the caller-owned token so it cannot activate later and
            // strand every writer until process restart. This also makes exact
            // duplicate cleanup idempotent.
            pause.remember_terminal_token(token);
            return Ok(());
        }

        invalid_pause_token()
    }
}

fn pause_conflict(message: &'static str) -> PushError {
    PushError::IoError(std::io::Error::new(ErrorKind::WouldBlock, message))
}

fn invalid_pause_token<T>() -> Result<T, PushError> {
    Err(PushError::IoError(std::io::Error::new(
        ErrorKind::PermissionDenied,
        "invalid CloudKit writer pause token",
    )))
}

static CLOUDKIT_WRITER_OPERATION_GATE: LazyLock<CloudKitWriterOperationGate> =
    LazyLock::new(|| {
        CloudKitWriterOperationGate::new(PAUSE_ACQUIRE_TIMEOUT, OPERATION_ACQUIRE_TIMEOUT)
    });

pub async fn acquire_cloudkit_writer_operation() -> Result<CloudKitWriterOperationPermit, PushError>
{
    CLOUDKIT_WRITER_OPERATION_GATE.acquire_operation().await
}

pub(crate) fn cloudkit_writer_operation_is_held() -> bool {
    CLOUDKIT_WRITER_OPERATION_SCOPE.try_with(|_| ()).is_ok()
}

/// Runs a complete native CloudKit writer workflow under one operation permit.
///
/// The task-local marker lets the shared transport recognize a caller-held
/// permit without trying to acquire a second read lock behind a pending pause.
/// Nested workflows in the same task reuse the outer permit.
pub fn with_cloudkit_writer_operation<F, T, E>(operation: F) -> impl Future<Output = Result<T, E>>
where
    F: Future<Output = Result<T, E>>,
    E: From<PushError>,
{
    // Some CloudKit workflows contain very large debug-mode async state
    // machines. Keeping `F` inline in another generic async function made each
    // nested writer scope add that state to the polling stack. ARM64 Android's
    // smaller worker stacks then overflowed during the initial Passwords sync.
    // Pin the operation before returning so both the reentrant and permit-
    // acquiring paths have a pointer-sized outer future.
    let operation = Box::pin(operation);

    Box::pin(async move {
        if cloudkit_writer_operation_is_held() {
            return operation.await;
        }

        let permit = acquire_cloudkit_writer_operation().await.map_err(E::from)?;
        CLOUDKIT_WRITER_OPERATION_SCOPE
            .scope((), async move {
                let result = operation.await;
                drop(permit);
                result
            })
            .await
    })
}

/// Acquires a non-cloneable read-authentication capability for one exact,
/// already-active writer pause. Absence, pending state, stale tokens, and
/// tokens owned by another pause all fail before any authentication work runs.
pub fn acquire_cloudkit_read_authentication(
    token: u64,
) -> Result<CloudKitReadAuthenticationPermit<'static>, PushError> {
    CLOUDKIT_WRITER_OPERATION_GATE.begin_read_authentication(token)
}

/// Fails immediately when a native CloudKit writer pause is pending or active.
pub fn try_acquire_cloudkit_operation() -> Result<CloudKitWriterOperationPermit, PushError> {
    CLOUDKIT_WRITER_OPERATION_GATE.try_acquire_operation()
}

/// Pauses native CloudKit writer work after in-flight operations finish.
pub async fn pause_cloudkit_writer_operations(token: u64) -> Result<u64, PushError> {
    CLOUDKIT_WRITER_OPERATION_GATE.pause(token).await
}

/// Resumes native CloudKit writer work paused by the matching token.
pub async fn resume_cloudkit_writer_operations(token: u64) -> Result<(), PushError> {
    CLOUDKIT_WRITER_OPERATION_GATE.resume(token).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_millis(100);
    const TEST_WAIT: Duration = Duration::from_millis(20);

    fn test_gate() -> Arc<CloudKitWriterOperationGate> {
        Arc::new(CloudKitWriterOperationGate::new(TEST_TIMEOUT, TEST_TIMEOUT))
    }

    async fn wait_until_pause_pending(gate: &CloudKitWriterOperationGate) {
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if gate.pause_state().pending.is_some() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pause did not become pending");
    }

    #[tokio::test]
    async fn pause_waits_for_active_operation() {
        let gate = test_gate();
        let operation = gate.acquire_operation().await.unwrap();
        let pause_gate = gate.clone();
        let mut pause_task = tokio::spawn(async move { pause_gate.pause(101).await });

        assert!(tokio::time::timeout(TEST_WAIT, &mut pause_task)
            .await
            .is_err());

        drop(operation);
        let token = tokio::time::timeout(TEST_TIMEOUT, pause_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        gate.resume(token).await.unwrap();
    }

    #[tokio::test]
    async fn paused_gate_blocks_new_operations() {
        let gate = test_gate();
        let token = gate.pause(102).await.unwrap();
        let operation_gate = gate.clone();
        let mut operation_task =
            tokio::spawn(async move { operation_gate.acquire_operation().await });

        assert!(tokio::time::timeout(TEST_WAIT, &mut operation_task)
            .await
            .is_err());

        gate.resume(token).await.unwrap();
        let operation = tokio::time::timeout(TEST_TIMEOUT, operation_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(operation);
    }

    #[tokio::test]
    async fn read_authentication_scope_requires_pause_and_delays_resume() {
        let gate = test_gate();
        assert!(matches!(
            gate.begin_read_authentication(110),
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));

        let token = gate.pause(110).await.unwrap();
        assert!(matches!(
            gate.begin_read_authentication(111),
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
        let permit = gate
            .begin_read_authentication(token)
            .expect("an exact active pause token must admit read authentication");
        permit.validate().unwrap();
        assert_eq!(gate.pause_state().active_read_authentication_scopes, 1);
        assert!(matches!(
            gate.resume(token).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::WouldBlock
        ));

        drop(permit);
        assert_eq!(gate.pause_state().active_read_authentication_scopes, 0);
        gate.resume(token).await.unwrap();
    }

    #[tokio::test]
    async fn nested_read_authentication_permits_remain_bound_to_one_pause() {
        let gate = test_gate();
        let token = gate.pause(112).await.unwrap();
        let first = gate.begin_read_authentication(token).unwrap();
        let second = gate.begin_read_authentication(token).unwrap();
        assert_eq!(gate.pause_state().active_read_authentication_scopes, 2);

        drop(first);
        assert_eq!(gate.pause_state().active_read_authentication_scopes, 1);
        assert!(matches!(
            gate.resume(token).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::WouldBlock
        ));

        drop(second);
        gate.resume(token).await.unwrap();
        assert!(matches!(
            gate.begin_read_authentication(token),
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
    }

    #[tokio::test]
    async fn sequential_read_authentication_permits_have_no_eight_pass_limit() {
        let gate = test_gate();
        let token = gate.pause(115).await.unwrap();

        for _ in 0..16 {
            let permit = gate
                .begin_read_authentication(token)
                .expect("active pause must admit each sequential read");
            permit
                .validate()
                .expect("sequential permit must remain valid");
            drop(permit);
            assert_eq!(gate.pause_state().active_read_authentication_scopes, 0);
        }

        gate.resume(token).await.unwrap();
    }

    #[tokio::test]
    async fn canceled_read_authentication_future_releases_its_permit() {
        let gate = test_gate();
        let token = gate.pause(113).await.unwrap();
        let (started_tx, mut started_rx) = tokio::sync::oneshot::channel();
        let authentication_gate = gate.clone();
        let mut pending_authentication = Box::pin(async move {
            let _permit = authentication_gate
                .begin_read_authentication(token)
                .unwrap();
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });

        tokio::select! {
            _ = pending_authentication.as_mut() => panic!("authentication unexpectedly completed"),
            started = &mut started_rx => started.unwrap(),
        }
        assert_eq!(gate.pause_state().active_read_authentication_scopes, 1);
        drop(pending_authentication);
        assert_eq!(gate.pause_state().active_read_authentication_scopes, 0);
        gate.resume(token).await.unwrap();
    }

    #[tokio::test]
    async fn panicking_read_authentication_scope_releases_its_permit() {
        let gate = test_gate();
        let token = gate.pause(114).await.unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = gate.begin_read_authentication(token).unwrap();
            panic!("test panic while read authentication owns its permit");
        }));

        assert!(result.is_err());
        assert_eq!(gate.pause_state().active_read_authentication_scopes, 0);
        gate.resume(token).await.unwrap();
    }

    #[tokio::test]
    async fn try_acquire_fails_fast_while_pause_is_pending_or_active() {
        let gate = test_gate();
        let active_operation = gate.acquire_operation().await.unwrap();
        let pause_gate = gate.clone();
        let pause_task = tokio::spawn(async move { pause_gate.pause(103).await });
        wait_until_pause_pending(&gate).await;

        assert!(matches!(
            gate.try_acquire_operation(),
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::WouldBlock
        ));

        drop(active_operation);
        let token = pause_task.await.unwrap().unwrap();
        assert!(matches!(
            gate.try_acquire_operation(),
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::WouldBlock
        ));

        gate.resume(token).await.unwrap();
        drop(gate.try_acquire_operation().unwrap());
    }

    #[tokio::test]
    async fn try_acquire_cannot_slip_past_pause_admission() {
        let gate = test_gate();
        let active_operation = gate.acquire_operation().await.unwrap();
        let pause_gate = gate.clone();
        let pause_task = tokio::spawn(async move { pause_gate.pause(104).await });
        wait_until_pause_pending(&gate).await;

        for _ in 0..16 {
            assert!(matches!(
                gate.try_acquire_operation(),
                Err(PushError::IoError(error)) if error.kind() == ErrorKind::WouldBlock
            ));
        }

        drop(active_operation);
        let token = pause_task.await.unwrap().unwrap();
        gate.resume(token).await.unwrap();
    }

    #[tokio::test]
    async fn resume_releases_exactly_one_pause_token() {
        let gate = test_gate();
        let first_token = gate.pause(105).await.unwrap();
        gate.resume(first_token).await.unwrap();
        gate.resume(first_token).await.unwrap();

        let second_token = gate.pause(106).await.unwrap();
        assert_ne!(first_token, second_token);
        assert!(matches!(
            gate.resume(first_token).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
        gate.resume(second_token).await.unwrap();
        assert!(matches!(
            gate.resume(first_token).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
    }

    #[tokio::test]
    async fn invalid_resume_fails_and_exact_duplicate_resume_recovers() {
        let gate = test_gate();
        assert!(matches!(
            gate.resume(0).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));

        let token = gate.pause(107).await.unwrap();
        let invalid_token = token.checked_add(1).unwrap_or(token - 1);
        assert!(matches!(
            gate.resume(invalid_token).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
        gate.resume(token).await.unwrap();
        gate.resume(token).await.unwrap();
    }

    #[tokio::test]
    async fn pause_timeout_leaves_no_orphan_pause() {
        let gate = Arc::new(CloudKitWriterOperationGate::new(TEST_WAIT, TEST_TIMEOUT));
        let operation = gate.acquire_operation().await.unwrap();

        assert!(matches!(
            gate.pause(108).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::TimedOut
        ));
        assert!(gate.pause_state().pending.is_none());

        drop(operation);
        let operation = tokio::time::timeout(TEST_TIMEOUT, gate.acquire_operation())
            .await
            .unwrap()
            .unwrap();
        drop(operation);

        let token = gate.pause(109).await.unwrap();
        gate.resume(token).await.unwrap();
    }

    #[tokio::test]
    async fn lost_pause_response_retries_idempotently_while_active() {
        let gate = test_gate();
        let token = 201;

        // Model a bridge response being lost after native activation: the caller repeats its
        // request with the token it generated before the first call.
        assert_eq!(gate.pause(token).await.unwrap(), token);
        assert_eq!(gate.pause(token).await.unwrap(), token);
        gate.resume(token).await.unwrap();
    }

    #[tokio::test]
    async fn resume_cancels_pending_pause_before_acquisition() {
        let gate = test_gate();
        let operation = gate.acquire_operation().await.unwrap();
        let token = 202;
        let pause_gate = gate.clone();
        let pause_task = tokio::spawn(async move { pause_gate.pause(token).await });
        wait_until_pause_pending(&gate).await;

        gate.resume(token).await.unwrap();
        assert_eq!(gate.pause_state().pending, None);
        drop(operation);

        assert!(matches!(
            pause_task.await.unwrap(),
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::Interrupted
        ));
        drop(gate.acquire_operation().await.unwrap());
    }

    #[tokio::test]
    async fn canceled_waiter_cannot_clear_or_activate_newer_pause() {
        let gate = test_gate();
        let operation = gate.acquire_operation().await.unwrap();
        let canceled_token = 203;
        let next_token = 204;

        let old_gate = gate.clone();
        let old_waiter = tokio::spawn(async move { old_gate.pause(canceled_token).await });
        wait_until_pause_pending(&gate).await;
        gate.resume(canceled_token).await.unwrap();

        let next_gate = gate.clone();
        let next_waiter = tokio::spawn(async move { next_gate.pause(next_token).await });
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if gate.pause_state().pending == Some(next_token) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("newer pause did not become pending");

        drop(operation);
        assert!(matches!(
            old_waiter.await.unwrap(),
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::Interrupted
        ));
        assert_eq!(next_waiter.await.unwrap().unwrap(), next_token);
        assert_eq!(
            gate.pause_state()
                .active
                .as_ref()
                .map(|active| active.token),
            Some(next_token)
        );
        gate.resume(next_token).await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_pending_token_does_not_create_second_waiter() {
        let gate = test_gate();
        let operation = gate.acquire_operation().await.unwrap();
        let token = 205;
        let pause_gate = gate.clone();
        let pause_task = tokio::spawn(async move { pause_gate.pause(token).await });
        wait_until_pause_pending(&gate).await;

        assert!(matches!(
            gate.pause(token).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::AlreadyExists
        ));
        assert_eq!(gate.pause_state().pending, Some(token));

        gate.resume(token).await.unwrap();
        drop(operation);
        assert!(matches!(
            pause_task.await.unwrap(),
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::Interrupted
        ));
    }

    #[tokio::test]
    async fn stale_and_zero_tokens_cannot_pause_or_release_newer_pause() {
        let gate = test_gate();
        let stale_token = 206;
        let active_token = 207;

        gate.pause(stale_token).await.unwrap();
        gate.resume(stale_token).await.unwrap();
        gate.resume(stale_token).await.unwrap();
        assert!(matches!(
            gate.pause(stale_token).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));

        gate.pause(active_token).await.unwrap();
        for token in [0, stale_token] {
            assert!(matches!(
                gate.resume(token).await,
                Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
            ));
        }
        assert_eq!(
            gate.pause_state()
                .active
                .as_ref()
                .map(|active| active.token),
            Some(active_token)
        );
        gate.resume(active_token).await.unwrap();
    }

    #[tokio::test]
    async fn cleanup_before_delayed_pause_tombstones_the_token() {
        let gate = test_gate();
        let delayed_token = 208;

        gate.resume(delayed_token).await.unwrap();
        gate.resume(delayed_token).await.unwrap();
        assert!(matches!(
            gate.pause(delayed_token).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
        drop(gate.acquire_operation().await.unwrap());
    }

    #[tokio::test]
    async fn terminal_pause_tombstones_are_bounded() {
        let gate = test_gate();
        let first_token = 300;

        for token in first_token..first_token + MAX_TERMINAL_PAUSE_TOKENS as u64 + 1 {
            gate.resume(token).await.unwrap();
        }

        let active = gate.pause(first_token).await.unwrap();
        gate.resume(active).await.unwrap();
        assert!(matches!(
            gate.pause(first_token + MAX_TERMINAL_PAUSE_TOKENS as u64).await,
            Err(PushError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
    }

    #[tokio::test]
    async fn writer_scope_is_reentrant_and_clears_after_completion() {
        assert!(!cloudkit_writer_operation_is_held());

        let value = with_cloudkit_writer_operation(async {
            assert!(cloudkit_writer_operation_is_held());
            let nested = with_cloudkit_writer_operation(async {
                assert!(cloudkit_writer_operation_is_held());
                Ok::<u8, PushError>(17)
            })
            .await?;
            Ok::<u8, PushError>(nested)
        })
        .await
        .unwrap();

        assert_eq!(value, 17);
        assert!(!cloudkit_writer_operation_is_held());
    }

    #[tokio::test]
    async fn writer_scope_state_is_checked_when_future_is_polled() {
        let scoped = CLOUDKIT_WRITER_OPERATION_SCOPE
            .scope((), async {
                assert!(cloudkit_writer_operation_is_held());
                with_cloudkit_writer_operation(async {
                    assert!(cloudkit_writer_operation_is_held());
                    Ok::<(), PushError>(())
                })
            })
            .await;

        assert!(!cloudkit_writer_operation_is_held());
        scoped.await.unwrap();
        assert!(!cloudkit_writer_operation_is_held());
    }

    #[test]
    fn writer_scope_keeps_large_operation_off_the_outer_future() {
        let large_capture = [0u8; 256 * 1024];
        let scoped = with_cloudkit_writer_operation(async move {
            std::hint::black_box(large_capture);
            Ok::<(), PushError>(())
        });

        assert!(
            std::mem::size_of_val(&scoped) <= 64,
            "writer scope future unexpectedly grew to {} bytes",
            std::mem::size_of_val(&scoped)
        );
    }
}
