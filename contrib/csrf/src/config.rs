use rocket::serde::{Deserialize, Serialize};
use rocket::time::Duration;

/// CSRF configuration loaded from the `csrf` figment profile section.
///
/// All values in this structure have sensible defaults. In particular, if the
/// default configuration is acceptable, attaching [`crate::Csrf::fairing()`] is
/// sufficient and no explicit configuration is required.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Config {
    /// Enables installation of CSRF managed state.
    ///
    /// When `false`, [`crate::Csrf::fairing()`] does not install any CSRF
    /// state. Routes using [`crate::CsrfToken`], [`crate::CsrfForm<T>`],
    /// [`crate::XsrfToken`], or [`crate::VerifiedXsrf`] will then fail their
    /// launch-time sentinel checks.
    pub enable: bool,

    /// The lifetime, in hours, of the private CSRF session cookies.
    pub session_hours: u16,

    /// Configuration for signing key rotation.
    pub rotate: Rotate,
}

/// Signing key rotation configuration.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Rotate {
    /// The total rotation period, in hours.
    pub period: u16,

    /// The overlap window, in hours, during which both the previous and current
    /// signing keys are accepted.
    pub window: u16,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum Phase {
    Epoch,
    Window,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable: true,
            session_hours: 24,
            rotate: Rotate::default(),
        }
    }
}

impl Default for Rotate {
    fn default() -> Self {
        Self { period: 24, window: 6 }
    }
}

impl Config {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.session_hours == 0 {
            return Err("`csrf.session_hours` must be greater than 0");
        }

        self.rotate.validate()
    }

    pub(crate) fn session_ttl(&self) -> Duration {
        Duration::hours(i64::from(self.session_hours))
    }
}

impl Rotate {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.period == 0 {
            return Err("`csrf.rotate.period` must be greater than 0");
        }

        if self.window == 0 {
            return Err("`csrf.rotate.window` must be greater than 0");
        }

        if self.period <= self.window {
            return Err("`csrf.rotate.period` must be greater than `csrf.rotate.window`");
        }

        Ok(())
    }

    pub(crate) fn epoch(&self) -> Duration {
        Duration::hours(i64::from(self.period - self.window))
    }

    pub(crate) fn window(&self) -> Duration {
        Duration::hours(i64::from(self.window))
    }
}

impl Phase {
    pub(crate) fn duration(self, rotate: Rotate) -> Duration {
        match self {
            Phase::Epoch => rotate.epoch(),
            Phase::Window => rotate.window(),
        }
    }

    pub(crate) fn next(self) -> Self {
        match self {
            Phase::Epoch => Phase::Window,
            Phase::Window => Phase::Epoch,
        }
    }
}
