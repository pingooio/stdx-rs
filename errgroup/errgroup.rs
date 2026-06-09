/// Async task group with error propagation and optional concurrency limiting.
///
/// A [`Group`] spawns multiple concurrent tasks. If any task returns an error,
/// the group remembers the first error. When all tasks finish, [`wait`] returns
/// that error (or `Ok(())` if all succeeded).
///
/// Optionally, [`set_limit`] restricts how many tasks run concurrently. Tasks
/// beyond the limit block inside the spawned task until a slot opens.
///
/// # Panics
///
/// Tasks **must not panic**. If a task panics, the panic is silently caught and
/// ignored (the overall result is unaffected, but the panic is lost). This
/// matches [`JoinSet`]'s behaviour.
///
/// # Example
///
/// ```rust
/// use errgroup::Group;
///
/// # async fn example() -> Result<(), String> {
/// let group = Group::new();
///
/// for url in ["http://example.com/a", "http://example.com/b"] {
///     group.spawn(move || async move {
///         // simulate a fetch
///         if url.contains("b") {
///             Err("failed".to_string())
///         } else {
///             Ok(())
///         }
///     });
/// }
///
/// let result = group.wait().await;
/// assert!(result.is_err());
/// # Ok(())
/// # }
/// ```
///
/// [`wait`]: Group::wait
/// [`set_limit`]: Group::set_limit
use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use tokio::{sync::Semaphore, task::JoinSet};

/// A group of concurrent tasks that propagates the first error.
///
/// Create a new group with [`Group::new`], spawn tasks with [`spawn`] or
/// [`try_spawn`], and collect results with [`wait`].
///
/// [`spawn`]: Group::spawn
/// [`try_spawn`]: Group::try_spawn
/// [`wait`]: Group::wait
pub struct Group<E> {
    tasks: Mutex<JoinSet<Result<(), E>>>,
    sem: Option<Arc<Semaphore>>,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl<E> Group<E>
where
    E: Send + 'static,
{
    /// Creates a new `Group` with no concurrency limit.
    pub fn new() -> Self {
        Group {
            tasks: Mutex::new(JoinSet::new()),
            sem: None,
        }
    }

    /// Limits the number of tasks that may run concurrently to at most `n`.
    ///
    /// A limit of `0` prevents any new task from running. A negative value
    /// would indicate no limit, but since this is `usize`, no limit is the
    /// default (created by [`new`][Group::new]).
    ///
    /// # Panics
    ///
    /// Must not be called while any tasks are active.
    pub fn set_limit(&mut self, n: usize) {
        self.sem = Some(Arc::new(Semaphore::new(n)));
    }
}

impl<E> Default for Group<E>
where
    E: Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Spawning
// ---------------------------------------------------------------------------

impl<E> Group<E>
where
    E: Send + 'static,
{
    /// Spawns a new task.
    ///
    /// If a concurrency limit was set with [`set_limit`] and the maximum
    /// number of tasks is already running, the newly spawned task will block
    /// **inside** itself (not the caller) until a slot opens up.
    ///
    /// This method returns immediately and never blocks the caller.
    ///
    /// # Panics
    ///
    /// The task **must not panic**. See the [crate-level docs][crate#panics].
    ///
    /// [`set_limit`]: Group::set_limit
    pub fn spawn<F, Fut>(&self, f: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
    {
        let sem = self.sem.clone();
        self.tasks.lock().unwrap().spawn(async move {
            let _permit = match sem {
                Some(ref sem) => Some(sem.clone().acquire_owned().await.expect("semaphore closed")),
                None => None,
            };
            f().await
        });
    }

    /// Tries to spawn a new task without waiting for a concurrency slot.
    ///
    /// If a limit is set and the maximum number of tasks is running, returns
    /// `false` without spawning the task. Otherwise spawns the task and
    /// returns `true`.
    ///
    /// If no limit was set, this is equivalent to [`spawn`][Group::spawn]
    /// and always returns `true`.
    pub fn try_spawn<F, Fut>(&self, f: F) -> bool
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
    {
        let permit = match self.sem.as_ref() {
            Some(sem) => match sem.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => return false,
            },
            None => None,
        };

        self.tasks.lock().unwrap().spawn(async move {
            let _permit = permit;
            f().await
        });
        true
    }
}

// ---------------------------------------------------------------------------
// Wait
// ---------------------------------------------------------------------------

impl<E> Group<E>
where
    E: Send + 'static,
{
    /// Waits for all spawned tasks to complete.
    ///
    /// Returns the first error encountered, or `Ok(())` if all tasks succeeded.
    ///
    /// Consumes the group — no more tasks can be spawned after calling this.
    pub async fn wait(self) -> Result<(), E> {
        let mut tasks = self.tasks.into_inner().unwrap();
        let mut first_error = None;

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => { /* success – nothing to do */ }
                Ok(Err(e)) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
                Err(_) => {
                    // Task panicked – silently ignored (documented).
                }
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn no_tasks_returns_ok() {
        let group = Group::<&str>::new();
        assert_eq!(group.wait().await, Ok(()));
    }

    #[tokio::test]
    async fn single_task_ok() {
        let group = Group::<&str>::new();
        group.spawn(|| async { Ok(()) });
        assert_eq!(group.wait().await, Ok(()));
    }

    #[tokio::test]
    async fn single_task_error() {
        let group = Group::new();
        group.spawn(|| async { Err("oops") });
        assert_eq!(group.wait().await, Err("oops"));
    }

    #[tokio::test]
    async fn multiple_tasks_all_ok() {
        let group = Group::<&str>::new();
        for _ in 0..10 {
            group.spawn(|| async { Ok(()) });
        }
        assert_eq!(group.wait().await, Ok(()));
    }

    #[tokio::test]
    async fn first_error_wins() {
        let group = Group::<&str>::new();

        let barrier = Arc::new(tokio::sync::Barrier::new(10));

        for i in 0..10 {
            let b = barrier.clone();
            group.spawn(move || async move {
                b.wait().await;
                if i == 5 {
                    Err("task 5 failed")
                } else {
                    // Sleep tasks long enough so the error doesn't race
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Ok(())
                }
            });
        }

        let result = group.wait().await;
        assert_eq!(result, Err("task 5 failed"));
    }

    #[tokio::test]
    async fn concurrency_limit_is_enforced() {
        let mut group = Group::<String>::new();
        group.set_limit(3);

        let running = Arc::new(AtomicUsize::new(0));
        let max_running = Arc::new(AtomicUsize::new(0));

        for _ in 0..20 {
            let running = running.clone();
            let max_running = max_running.clone();
            group.spawn(move || async move {
                let prev = running.fetch_add(1, Ordering::SeqCst);
                max_running.fetch_max(prev + 1, Ordering::SeqCst);

                tokio::time::sleep(std::time::Duration::from_millis(30)).await;

                running.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            });
        }

        group.wait().await.unwrap();
        assert!(
            max_running.load(Ordering::SeqCst) <= 3,
            "max was {}",
            max_running.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn try_spawn_rejected_at_limit() {
        let mut group = Group::<&str>::new();
        group.set_limit(2);

        // First two should succeed
        assert!(group.try_spawn(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            Ok(())
        }));

        assert!(group.try_spawn(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            Ok(())
        }));

        // Third should be rejected
        assert!(!group.try_spawn(|| async { Ok(()) }));

        group.wait().await.unwrap();
    }

    #[tokio::test]
    async fn try_spawn_without_limit_always_succeeds() {
        let group = Group::<&str>::new();
        assert!(group.try_spawn(|| async { Ok(()) }));
        assert!(group.try_spawn(|| async { Ok(()) }));
        group.wait().await.unwrap();
    }

    #[tokio::test]
    async fn high_concurrency_stress() {
        let mut group = Group::<String>::new();
        group.set_limit(10);

        let n = 500;
        let counter = Arc::new(AtomicUsize::new(0));

        for _i in 0..n {
            let c = counter.clone();
            group.spawn(move || async move {
                tokio::time::sleep(std::time::Duration::from_micros(10)).await;
                c.fetch_add(1, Ordering::SeqCst);
                Ok::<(), String>(())
            });
        }

        group.wait().await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), n);
    }

    /// When a task panics, the group should not propagate the panic
    /// and should still be able to wait for remaining tasks.
    #[tokio::test]
    async fn panicking_task_is_ignored() {
        let group = Group::new();

        group.spawn(|| async {
            panic!("this should be caught");
        });

        group.spawn(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Ok::<(), &str>(())
        });

        // Should not propagate the panic.
        let result = group.wait().await;
        assert_eq!(result, Ok(()));
    }
}
