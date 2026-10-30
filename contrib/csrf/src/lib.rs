//! Explicit CSRF protection for Rocket.
//!
//! This crate provides explicit, opt-in CSRF protection for two common request
//! styles:
//!
//!   * HTML forms via [`CsrfToken`] and [`CsrfForm<T>`]
//!   * JavaScript-driven API requests via [`XsrfToken`] and [`VerifiedXsrf`]
//!
//! Internally, both flows use signed, session-bound tokens issued by the
//! server. Tokens are scoped to a request context, so a token minted for form
//! submission cannot be replayed as an XSRF header token, and vice versa.
//!
//! Protection is opt-in per route: attaching the fairing alone does not protect
//! unsafe routes. Use the appropriate verification guard on every such route.
//!
//! ## Usage
//!
//! Attach [`Csrf::fairing()`] and use the guards that match your routes.
//!
//! ### Form Workflow
//!
//! Use [`CsrfToken`] on a safe route to mint a token and render it into a
//! hidden form field named [`FORM_FIELD`]. Then use [`CsrfForm<T>`] on the
//! unsafe route to validate the token and parse the remainder of the form as
//! `T`:
//!
//! ```rust
//! # #[macro_use] extern crate rocket;
//! use rocket::form::FromForm;
//! use rocket::response::content::RawHtml;
//! use rocket_csrf::{Csrf, CsrfForm, CsrfToken};
//!
//! #[derive(FromForm)]
//! struct Login<'r> {
//!     username: &'r str,
//!     password: &'r str,
//! }
//!
//! #[get("/login")]
//! fn login(csrf: CsrfToken) -> RawHtml<String> {
//!     RawHtml(format!(
//!         r#"<form action="/login" method="post">
//!             <input type="hidden" name="_authenticity_token" value="{csrf}">
//!             <input type="text" name="username">
//!             <input type="password" name="password">
//!             <button type="submit">Sign In</button>
//!         </form>"#,
//!     ))
//! }
//!
//! #[post("/login", data = "<form>")]
//! fn submit(form: CsrfForm<Login<'_>>) -> &'static str {
//!     let _login = form.into_inner();
//!     "ok"
//! }
//!
//! # #[launch]
//! fn rocket() -> _ {
//!     rocket::build()
//!         .attach(Csrf::fairing())
//!         .mount("/", routes![login, submit])
//! }
//! ```
//!
//! `CsrfForm<T>` behaves similarly to `rocket::form::Form<T>`: it forwards when
//! the content-type is not a form content-type, preserves ordinary form parsing
//! errors, and returns `403 Forbidden` for CSRF failures.
//!
//! ### JavaScript / XSRF Workflow
//!
//! For JavaScript clients, use [`XsrfToken`] on a safe route or bootstrap
//! endpoint. This queues a readable [`XSRF_COOKIE`] cookie whose value should be
//! copied into the [`XSRF_HEADER`] or [`CSRF_HEADER`] header on subsequent
//! unsafe requests protected by [`VerifiedXsrf`]:
//!
//! ```rust
//! # #[macro_use] extern crate rocket;
//! use rocket::http::Status;
//! use rocket_csrf::{Csrf, VerifiedXsrf, XsrfToken};
//!
//! #[get("/api/bootstrap")]
//! fn bootstrap(_xsrf: XsrfToken) -> Status {
//!     Status::NoContent
//! }
//!
//! #[post("/api/update")]
//! fn update(_xsrf: VerifiedXsrf) -> Status {
//!     Status::Accepted
//! }
//!
//! # #[launch]
//! fn rocket() -> _ {
//!     rocket::build()
//!         .attach(Csrf::fairing())
//!         .mount("/", routes![bootstrap, update])
//! }
//! ```
//!
//! This pattern matches the conventions used by many JavaScript frameworks:
//! the server delivers a readable `XSRF-TOKEN` cookie and the client echoes that
//! value in an `X-XSRF-TOKEN` or `X-CSRF-Token` header.
//!
//! ### Templates and JSON
//!
//! Both token guards implement [`Serialize`](rocket::serde::Serialize) as an
//! opaque string. Pass them directly to a template context (for example,
//! `context! { csrf: csrf }`) and render `{{ csrf }}` as the value of a hidden
//! `_authenticity_token` input. Keep template autoescaping enabled.
//!
//! An SPA bootstrap endpoint can return `Json<XsrfToken>` or include an
//! `XsrfToken` in a serializable response structure. The client sends the
//! returned string in `X-XSRF-TOKEN`; it need not read `document.cookie`.
//! Cookies must still accompany both bootstrap and protected requests.
//! Responses that issue tokens receive `Cache-Control: no-store`. A rejected
//! [`VerifiedXsrf`] guard defaults to `403` without a retry marker: Rocket lets
//! routes absorb guard failures with `Option` or `Result`, so a response fairing
//! cannot safely infer that the handler did not run. Routes that want an SPA
//! retry signal should return [`CsrfGuardError`] explicitly, and propagate the
//! guard result with `xsrf?` before any side effects. Only its rejection
//! responder sets [`CSRF_ERROR_HEADER`] to [`CSRF_ERROR_VALUE`]. Keep a
//! client-side single-flight promise around initial bootstrap calls: requests
//! arriving without a cookie cannot coordinate their session statelessly.
//!
//! ## Security Model
//!
//! This crate uses server-issued, cryptographically signed tokens bound to an
//! opaque private session cookie. Token validation checks:
//!
//!   * the token signature
//!   * the issuing session
//!   * the token context (form vs. header)
//!   * the active key rotation window
//!
//! Signing keys are domain-separated derivatives of Rocket's `secret_key`.
//! Replicas using the same persistent secret and CSRF configuration accept each
//! other's tokens, including after restarts; sticky routing is not required.
//! Rotation is anchored to UTC Unix-epoch periods rather than process startup.
//! Keep replica clocks synchronized. The previous period's tokens are accepted
//! only during the configured overlap window at the start of a new period.
//! Configure a stable `ROCKET_SECRET_KEY` (or `secret_key` in Rocket.toml) on
//! every replica. Debug-mode auto-generated secrets are intentionally ephemeral.
//! Changing the secret invalidates both existing tokens and private cookies.
//! Tokens are reusable until expiration, not one-time nonces. Use HTTPS in
//! production and do not expose bootstrap responses through permissive CORS.
//! The default cookies are host-only and SameSite=Strict: same-origin SPAs work
//! without extra configuration. Truly cross-site frontends require an explicit
//! cookie/CORS policy not provided by this crate.
//!
//! Tokens are not stored server-side. Instead, Rocket stores the CSRF session in
//! private cookies and validates the token against that session and the current
//! signing keys. Session cookies renew after half their configured lifetime on
//! requests that use a CSRF guard. A previous session ID remains valid only until
//! its original expiry; renewal never extends that ID, and browsers may discard
//! its cookie at that same expiry.
//!
//! ## Configuration
//!
//! This crate reads configuration from the `csrf` figment profile section via
//! [`Config`]. The defaults are generally suitable for development and can be
//! customized if needed.
//!
//! Setting [`Config::enable`] to `false` disables installation of CSRF state.
//! Applications that do so must also avoid mounting routes that use the guards
//! from this crate.

#![doc(html_root_url = "https://api.rocket.rs/master/rocket_csrf")]
#![doc(html_favicon_url = "https://rocket.rs/images/favicon.ico")]
#![doc(html_logo_url = "https://rocket.rs/images/logo-boxed.png")]

#[macro_use]
extern crate rocket;

mod config;
mod error;
mod fairing;
mod session;
mod token;

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use rocket::{Ignite, Phase, Request, Rocket, Sentinel};
use rocket::data::{self, Data, FromData};
use rocket::form::{self, FromForm, ParsedField, Parser};
use rocket::http::{Cookie, Status};
use rocket::request::{self, FromRequest};

use crate::error::{CsrfError, MissingFairing};
use crate::session::Session;
use crate::token::{Token, Tokenizer};

pub use crate::config::{Config, Rotate};

// Request-local marker used to avoid caching token-bearing responses.
struct IssuedToken(AtomicBool);

/// The hidden form field name used by [`CsrfToken`] and [`CsrfForm<T>`].
pub const FORM_FIELD: &str = "_authenticity_token";

/// The readable cookie name used by [`XsrfToken`].
pub const XSRF_COOKIE: &str = "XSRF-TOKEN";

/// The primary header name accepted by [`VerifiedXsrf`].
pub const XSRF_HEADER: &str = "X-XSRF-TOKEN";

/// A compatibility header name also accepted by [`VerifiedXsrf`].
pub const CSRF_HEADER: &str = "X-CSRF-Token";

/// Response header set by the explicit [`CsrfGuardError::Rejected`] responder.
///
/// A normal failed [`VerifiedXsrf`] guard does not set this header because
/// `Option` and `Result` guards can absorb failures and still run the handler.
pub const CSRF_ERROR_HEADER: &str = "X-Rocket-CSRF";

/// Value of [`CSRF_ERROR_HEADER`] for an explicitly returned CSRF rejection.
pub const CSRF_ERROR_VALUE: &str = "csrf-failure";

const MISSING_FAIRING_MESSAGE: &str = "uninitialized csrf context: missing `Csrf::fairing()`.
To use CSRF guards, you must attach `Csrf::fairing()`.";

#[derive(Debug)]
struct CsrfState {
    config: Config,
    tokenizer: OnceLock<Tokenizer>,
}

/// Entry point for attaching CSRF protection to a Rocket instance.
///
/// Attach [`Csrf::fairing()`] once during ignition to enable [`CsrfToken`],
/// [`CsrfForm<T>`], [`XsrfToken`], and [`VerifiedXsrf`]. These guards install a
/// launch-time sentinel and will abort launch when used without the fairing.
pub struct Csrf;

/// A request guard that mints a form-context CSRF token.
///
/// Use this on a safe route, typically a `GET`, and render the resulting token
/// into a hidden form field named [`FORM_FIELD`]. The token implements
/// [`Display`](std::fmt::Display), so `csrf.to_string()` or string formatting is
/// sufficient for rendering. It also implements [`Serialize`](rocket::serde::Serialize)
/// as a string for direct use in template contexts.
#[derive(Debug, Clone)]
pub struct CsrfToken(Token);

/// A request guard that mints a header-context XSRF token and queues the
/// [`XSRF_COOKIE`] cookie.
///
/// Use this on a safe route or bootstrap endpoint that is called before a
/// JavaScript client sends unsafe requests. The client should read the
/// [`XSRF_COOKIE`] cookie and send its value back in the [`XSRF_HEADER`] or
/// [`CSRF_HEADER`] header on routes protected by [`VerifiedXsrf`]. Alternatively,
/// serialize this guard directly in a JSON response; it serializes as a string.
#[derive(Debug, Clone)]
pub struct XsrfToken(Token);

/// A data guard that validates a form-context CSRF token and then parses the
/// remainder of the request body as `T`.
///
/// This guard is intended for routes that accept HTML form submissions. The
/// form must include a hidden [`FORM_FIELD`] field populated from a
/// [`CsrfToken`].
///
/// Semantics intentionally mirror `rocket::form::Form<T>` as closely as
/// possible:
///
///   * non-form content-types forward
///   * ordinary form validation errors are preserved
///   * CSRF failures return `403 Forbidden`
///
/// For multipart forms, the [`FORM_FIELD`] field must appear before any file or
/// data fields so the token can be validated before Rocket streams uploaded
/// data into the inner form parser.
#[derive(Debug)]
pub struct CsrfForm<T>(T);

/// A request guard that validates header-based XSRF protection.
///
/// This guard requires a token in either [`XSRF_HEADER`] or [`CSRF_HEADER`] and
/// validates that token against the active session and header-token context.
/// A failed guard returns `403` without a retry marker. See [`CsrfGuardError`]
/// for the explicit, safe-to-propagate response used by retry-capable routes.
#[derive(Debug, Copy, Clone)]
pub struct VerifiedXsrf;

/// An explicit response for a rejected XSRF guard or missing CSRF fairing.
///
/// Use this with `Result<VerifiedXsrf, CsrfGuardError>` and propagate the guard
/// result before performing side effects. Only [`Rejected`](Self::Rejected)
/// emits the CSRF retry marker. A missing fairing remains an internal-server
/// error and never emits a retry marker.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CsrfGuardError {
    /// The XSRF guard rejected the request.
    Rejected,
    /// The CSRF fairing is not attached.
    MissingFairing,
}

impl fmt::Display for CsrfGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rejected => "CSRF validation failed",
            Self::MissingFairing => "missing `Csrf::fairing()`",
        })
    }
}

impl std::error::Error for CsrfGuardError {}

impl<'r> rocket::response::Responder<'r, 'static> for CsrfGuardError {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = rocket::Response::build();
        match self {
            Self::Rejected => {
                response
                    .status(Status::Forbidden)
                    .raw_header(CSRF_ERROR_HEADER, CSRF_ERROR_VALUE);
            }
            Self::MissingFairing => {
                response.status(Status::InternalServerError);
            }
        }

        response.ok()
    }
}

impl Csrf {
    /// Returns the fairing that installs CSRF managed state.
    ///
    /// This fairing must be attached before any route uses [`CsrfToken`],
    /// [`CsrfForm<T>`], [`XsrfToken`], or [`VerifiedXsrf`].
    pub fn fairing() -> impl rocket::fairing::Fairing {
        fairing::fairing()
    }
}

impl CsrfState {
    fn new(config: Config) -> Self {
        Self {
            tokenizer: OnceLock::new(),
            config,
        }
    }

    fn tokenizer(&self, req: &Request<'_>) -> &Tokenizer {
        // The final secret (including debug-mode generation) is only available
        // after ignition, so do not derive from the figment in the fairing.
        self.tokenizer.get_or_init(|| {
            let root = req.rocket().config().secret_key
                .derive_key("rocket_csrf signing root v1");
            Tokenizer::new(self.config.rotate, root)
        })
    }
}

impl CsrfToken {
    fn issue(req: &Request<'_>, state: &CsrfState) -> Self {
        req.local_cache(|| IssuedToken(AtomicBool::new(false)))
            .0
            .store(true, Ordering::Relaxed);
        let session = Session::fetch(req, state.config.session_ttl());
        let session_id = session.id();
        Self(state.tokenizer(req).form_token(session_id))
    }
}

impl XsrfToken {
    fn issue(req: &Request<'_>, state: &CsrfState) -> Self {
        req.local_cache(|| IssuedToken(AtomicBool::new(false)))
            .0
            .store(true, Ordering::Relaxed);
        let session = Session::fetch(req, state.config.session_ttl());
        let token = state.tokenizer(req).header_token(session.id());
        req.cookies().add(
            Cookie::build((XSRF_COOKIE, token.to_string()))
                .http_only(false)
                .expires(now_plus(state)),
        );

        Self(token)
    }
}

impl<T> CsrfForm<T> {
    /// Consumes `self` and returns the parsed inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for CsrfForm<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for CsrfForm<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl rocket::serde::Serialize for CsrfToken {
    fn serialize<S: rocket::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl rocket::serde::Serialize for XsrfToken {
    fn serialize<S: rocket::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl fmt::Display for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for XsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CsrfToken {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match state(req.rocket()) {
            Some(state) => request::Outcome::Success(Self::issue(req, state)),
            None => {
                log_missing_fairing();
                request::Outcome::Error((Status::InternalServerError, ()))
            }
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for XsrfToken {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match state(req.rocket()) {
            Some(state) => request::Outcome::Success(Self::issue(req, state)),
            None => {
                log_missing_fairing();
                request::Outcome::Error((Status::InternalServerError, ()))
            }
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for VerifiedXsrf {
    type Error = CsrfGuardError;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let state = match state(req.rocket()) {
            Some(state) => state,
            None => {
                log_missing_fairing();
                return request::Outcome::Error((
                    Status::InternalServerError,
                    CsrfGuardError::MissingFairing,
                ));
            }
        };

        let session = match Session::find(req, state.config.session_ttl()) {
            Some(session) => session,
            None => return csrf_forbidden(),
        };

        let token = match header_token(req) {
            Ok(token) => token,
            Err(_) => return csrf_forbidden(),
        };

        match state.tokenizer(req).verify_header(&token, &session) {
            Ok(()) => request::Outcome::Success(VerifiedXsrf),
            Err(_) => csrf_forbidden(),
        }
    }
}

#[rocket::async_trait]
impl<'r, T: FromForm<'r>> FromData<'r> for CsrfForm<T> {
    type Error = form::Errors<'r>;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
        let state = match state(req.rocket()) {
            Some(state) => state,
            None => {
                log_missing_fairing();
                return data::Outcome::Error((
                    Status::InternalServerError,
                    MissingFairing::into_form_errors(),
                ));
            }
        };

        let mut parser = match Parser::new(req, data).await {
            data::Outcome::Success(parser) => parser,
            data::Outcome::Error((status, errors)) => return data::Outcome::Error((status, errors)),
            data::Outcome::Forward(forward) => return data::Outcome::Forward(forward),
        };

        let session = match Session::find(req, state.config.session_ttl()) {
            Some(session) => session,
            None => {
                let errors = form::Errors::from(CsrfError::MissingSession.into_form_error());
                return data::Outcome::Error((Status::Forbidden, errors));
            }
        };

        let mut context = T::init(form::Options::Lenient);
        let mut token_verified = false;
        let mut token_error = None;

        while let Some(field) = parser.next().await {
            match field {
                Ok(ParsedField::Value(value)) if value.name == FORM_FIELD => {
                    if token_verified || token_error.is_some() {
                        token_error = Some(CsrfError::DuplicateToken);
                        continue;
                    }

                    match value.value.parse::<Token>() {
                        Ok(parsed) => match state.tokenizer(req).verify_form(&parsed, &session) {
                            Ok(()) => token_verified = true,
                            Err(error) => token_error = Some(error),
                        },
                        Err(_) => token_error = Some(CsrfError::InvalidToken),
                    }
                }
                Ok(ParsedField::Data(data)) if data.name == FORM_FIELD => {
                    token_error = Some(CsrfError::InvalidToken);
                }
                Ok(ParsedField::Data(_)) if !token_verified || token_error.is_some() => {
                    let error = token_error.take().unwrap_or(CsrfError::MissingToken);
                    let errors = form::Errors::from(error.into_form_error());
                    return data::Outcome::Error((Status::Forbidden, errors));
                }
                Ok(ParsedField::Value(value)) => T::push_value(&mut context, value),
                Ok(ParsedField::Data(data)) => T::push_data(&mut context, data).await,
                Err(e) => T::push_error(&mut context, e),
            }
        }

        if let Some(error) = token_error
            .or_else(|| (!token_verified).then_some(CsrfError::MissingToken))
        {
            let errors = form::Errors::from(error.into_form_error());
            return data::Outcome::Error((Status::Forbidden, errors));
        }

        match T::finalize(context) {
            Ok(value) => data::Outcome::Success(CsrfForm(value)),
            Err(e) => data::Outcome::Error((e.status(), e)),
        }
    }
}

impl Sentinel for CsrfToken {
    fn abort(rocket: &Rocket<Ignite>) -> bool {
        if state(rocket).is_none() {
            log_missing_fairing();
            return true;
        }

        false
    }
}

impl Sentinel for XsrfToken {
    fn abort(rocket: &Rocket<Ignite>) -> bool {
        if state(rocket).is_none() {
            log_missing_fairing();
            return true;
        }

        false
    }
}

impl<T> Sentinel for CsrfForm<T> {
    fn abort(rocket: &Rocket<Ignite>) -> bool {
        if state(rocket).is_none() {
            log_missing_fairing();
            return true;
        }

        false
    }
}

impl Sentinel for VerifiedXsrf {
    fn abort(rocket: &Rocket<Ignite>) -> bool {
        if state(rocket).is_none() {
            log_missing_fairing();
            return true;
        }

        false
    }
}

fn state<P: Phase>(rocket: &Rocket<P>) -> Option<&CsrfState> {
    rocket.state::<CsrfState>()
}

fn log_missing_fairing() {
    error!("{MISSING_FAIRING_MESSAGE}");
}

fn csrf_forbidden() -> request::Outcome<VerifiedXsrf, CsrfGuardError> {
    request::Outcome::Error((Status::Forbidden, CsrfGuardError::Rejected))
}

fn header_token(req: &Request<'_>) -> Result<Token, CsrfError> {
    let mut token = None;

    for header in [XSRF_HEADER, CSRF_HEADER] {
        for value in req.headers().get(header) {
            if token.is_some() {
                return Err(CsrfError::DuplicateToken);
            }

            token = Some(value.parse().map_err(|_| CsrfError::InvalidToken)?);
        }
    }

    token.ok_or(CsrfError::MissingToken)
}

fn now_plus(state: &CsrfState) -> rocket::time::OffsetDateTime {
    rocket::time::OffsetDateTime::now_utc() + state.config.session_ttl()
}
