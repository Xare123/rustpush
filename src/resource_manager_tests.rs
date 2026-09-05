use super::*;
use crate::ids::user::IDSError;
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;

// Exercises the real worker and refresh paths without credentials or network.
struct ScriptedResource {
    outcomes: Mutex<VecDeque<Result<(), PushError>>>,
    calls: AtomicUsize,
}

impl Resource for ScriptedResource {
    async fn generate(self: &Arc<Self>) -> Result<JoinHandle<()>, PushError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcomes
            .lock()
            .await
            .pop_front()
            .expect("unexpected regeneration")?;
        Ok(tokio::spawn(std::future::pending()))
    }
}

fn manager(outcomes: Vec<Result<(), PushError>>) -> Arc<ResourceManager<ScriptedResource>> {
    ResourceManager::new(
        "synthetic-registration",
        Arc::new(ScriptedResource {
            outcomes: Mutex::new(outcomes.into()),
            calls: AtomicUsize::new(0),
        }),
        ExponentialBuilder::default()
            .with_min_delay(Duration::from_secs(60))
            .with_max_delay(Duration::from_secs(60))
            .with_max_times(usize::MAX),
        Duration::from_secs(5),
        None,
    )
}

fn invalid_auth() -> PushError {
    PushError::DoNotRetry(Box::new(PushError::AuthInvalid(IDSError(6005))))
}

async fn worker_finished(manager: &ResourceManager<ScriptedResource>) {
    tokio::time::timeout(Duration::from_secs(2), manager.death_signal.closed())
        .await
        .expect("resource worker did not exit");
}

async fn wait_for_state(
    manager: &ResourceManager<ScriptedResource>,
    predicate: impl FnMut(&ResourceState) -> bool,
) {
    let mut state = manager.resource_state.subscribe();
    tokio::time::timeout(Duration::from_secs(2), state.wait_for(predicate))
        .await
        .expect("resource state did not arrive")
        .expect("resource state channel closed");
}

fn assert_invalid_auth(error: PushError) {
    let PushError::ResourceFailure(failure) = error else {
        panic!("expected preserved resource failure, got {error}");
    };
    assert_eq!(failure.retry_wait, None);
    let PushError::DoNotRetry(cause) = failure.error.as_ref() else {
        panic!("non-retryable cause was lost");
    };
    assert!(matches!(
        cause.as_ref(),
        PushError::AuthInvalid(IDSError(6005))
    ));
}

#[tokio::test]
async fn terminal_registration_cause_survives_worker_exit_and_late_subscription() {
    let manager = manager(vec![Err(invalid_auth())]);
    worker_finished(&manager).await;

    let late_observer = manager.resource_state.subscribe();
    assert!(matches!(
        &*late_observer.borrow(),
        ResourceState::Failed(ResourceFailure {
            retry_wait: None,
            ..
        })
    ));
    assert_invalid_auth(manager.ensure_not_failed().unwrap_err());
    assert_invalid_auth(manager.ensure_ready().await.unwrap_err());
    assert_eq!(manager.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn terminal_registration_refresh_returns_original_cause_without_retrying() {
    let manager = manager(vec![Err(invalid_auth())]);
    worker_finished(&manager).await;

    for immediate in [false, true] {
        let result =
            tokio::time::timeout(Duration::from_secs(2), manager.refresh_option(immediate))
                .await
                .expect("terminal refresh waited for a worker that has exited");
        assert_invalid_auth(result.unwrap_err());
    }
    manager.request_update_now().await;
    manager.close();
    tokio::task::yield_now().await;
    assert_invalid_auth(manager.ensure_not_failed().unwrap_err());
    assert_eq!(manager.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn transient_failure_still_recovers_on_immediate_retry() {
    let manager = manager(vec![Err(PushError::ResourceGenTimeout), Ok(())]);
    wait_for_state(&manager, |state| {
        matches!(
            state,
            ResourceState::Failed(ResourceFailure {
                retry_wait: Some(_),
                ..
            })
        )
    })
    .await;

    manager.refresh_now().await.unwrap();
    assert!(matches!(
        &*manager.resource_state.borrow(),
        ResourceState::Generated
    ));
    manager.ensure_ready().await.unwrap();
    assert_eq!(manager.calls.load(Ordering::SeqCst), 2);
    manager.close();
    worker_finished(&manager).await;
}

#[tokio::test]
async fn terminal_failure_after_a_transient_retry_keeps_its_cause() {
    let manager = manager(vec![
        Err(PushError::ResourceGenTimeout),
        Err(invalid_auth()),
    ]);
    wait_for_state(&manager, |state| matches!(state, ResourceState::Failed(_))).await;
    assert_invalid_auth(manager.refresh_now().await.unwrap_err());
    worker_finished(&manager).await;
    assert_invalid_auth(manager.ensure_not_failed().unwrap_err());
    assert_eq!(manager.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn explicit_close_of_healthy_resource_is_closed_even_when_recently_refreshed() {
    let manager = manager(vec![Ok(())]);
    manager.ensure_ready().await.unwrap();
    manager.close();
    worker_finished(&manager).await;

    assert!(matches!(
        &*manager.resource_state.borrow(),
        ResourceState::Closed
    ));
    assert!(matches!(
        manager.ensure_ready().await,
        Err(PushError::ResourceClosed)
    ));
    for immediate in [false, true] {
        assert!(matches!(
            manager.refresh_option(immediate).await,
            Err(PushError::ResourceClosed)
        ));
    }
    assert_eq!(manager.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn explicit_close_during_backoff_does_not_become_terminal_auth_failure() {
    let manager = manager(vec![Err(PushError::ResourceGenTimeout)]);
    wait_for_state(&manager, |state| matches!(state, ResourceState::Failed(_))).await;
    manager.close();
    worker_finished(&manager).await;

    assert!(matches!(
        &*manager.resource_state.borrow(),
        ResourceState::Closed
    ));
    assert!(matches!(
        manager.refresh_now().await,
        Err(PushError::ResourceClosed)
    ));
    assert_eq!(manager.calls.load(Ordering::SeqCst), 1);
}
