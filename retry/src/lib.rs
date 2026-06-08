//! Retry async operations with configurable backoff strategies.
//!
//! This crate provides a single [`retry`] function backed by a [`Config`]
//! that controls how many attempts are made and the delay between them.
//!
//! # Example
//!
//! ```rust
//! use std::time::Duration;
//! use retry::{retry, Config};
//! use retry::delay::{Exponential, Fixed};
//!
//! # async fn example() -> Result<(), retry::Error<&'static str>> {
//! // Exponential backoff, max 5 attempts, with jitter
//! let result = retry(
//!     || async { Ok::<_, &'static str>(42) },
//!     Config::new(
//!         Exponential::new(Duration::from_millis(100))
//!             .with_max(Duration::from_secs(5))
//!             .with_jitter(),
//!     )
//!     .with_attempts(5),
//! )
//! .await?;
//!
//! // Fixed delay, 3 attempts, with on_retry callback
//! let result = retry(
//!     || async { Ok::<_, &'static str>(42) },
//!     Config::new(Fixed::new(Duration::from_secs(1)))
//!         .with_attempts(3)
//!         .with_on_retry(|attempt, delay| {
//!             eprintln!("retry #{attempt} in {delay:?}");
//!         }),
//! )
//! .await?;
//! # Ok(())
//! # }
//! ```

use std::{future::Future, time::Duration};

pub mod delay;
pub mod error;

use delay::Delay;
pub use error::Error;

/// Configuration for the [`retry`] function.
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use retry::Config;
/// use retry::delay::Fixed;
///
/// let config: Config<_> = Config::new(Fixed::new(Duration::from_secs(1)))
///     .with_attempts(5)
///     .with_on_retry(|attempt, delay| {
///         eprintln!("Attempt {attempt} failed, retrying in {delay:?}");
///     });
/// ```
pub struct Config<D> {
    /// Number of attempts. `0` means retry forever (until success).
    /// Includes the initial call. E.g. `attempts: 5` = 1 initial + 4 retries.
    pub attempts: usize,
    /// The delay strategy used between retries.
    pub delay: D,
    /// Optional callback invoked before each retry.
    /// Receives the attempt number (1-based) and the delay duration.
    pub on_retry: Option<Box<dyn FnMut(usize, Duration) + 'static>>,
}

impl<D> Config<D> {
    /// Creates a new config with infinite retries and the given delay strategy.
    pub const fn new(delay: D) -> Self {
        Self {
            attempts: 0,
            delay,
            on_retry: None,
        }
    }

    /// Sets the maximum number of attempts.
    ///
    /// `0` means infinite retries. An attempt count of `5` means
    /// 1 initial call + up to 4 retries.
    pub const fn with_attempts(mut self, attempts: usize) -> Self {
        self.attempts = attempts;
        self
    }

    /// Sets a callback that is invoked before each retry.
    ///
    /// The callback receives the attempt number (1-based) and
    /// the delay that will be waited before retrying.
    pub fn with_on_retry(mut self, f: impl FnMut(usize, Duration) + 'static) -> Self {
        self.on_retry = Some(Box::new(f));
        self
    }
}

/// Retries a fallible async operation with the given configuration.
///
/// The operation `f` is called repeatedly. On success the value is returned.
/// On failure the config's delay strategy determines how long to wait before
/// retrying. Once the configured number of attempts is exhausted, the last
/// error is returned wrapped in [`Error`].
///
/// If `attempts` is `0` (the default), the operation is retried forever
/// until it succeeds.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use retry::{retry, Config};
/// use retry::delay::Fixed;
///
/// # async fn example() -> Result<(), retry::Error<&'static str>> {
/// let result = retry(
///     || async { Ok::<_, &'static str>("hello") },
///     Config::new(Fixed::new(Duration::from_millis(10))).with_attempts(3),
/// )
/// .await?;
/// assert_eq!(result, "hello");
/// # Ok(())
/// # }
/// ```
pub async fn retry<F, Fut, T, E, D>(mut f: F, config: Config<D>) -> Result<T, Error<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    D: Delay,
{
    let Config {
        attempts,
        mut delay,
        mut on_retry,
    } = config;

    let mut attempt = 0;

    loop {
        attempt += 1;

        match f().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempts > 0 && attempt >= attempts {
                    return Err(Error::new(err, attempt));
                }

                let d = delay.next_delay();

                if let Some(ref mut cb) = on_retry {
                    cb(attempt, d);
                }

                tokio::time::sleep(d).await;
            }
        }
    }
}
