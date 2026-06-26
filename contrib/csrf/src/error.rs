use std::fmt;

use rocket::form::error::Entity;
use rocket::form::{self, Error};
use rocket::http::Status;

use crate::FORM_FIELD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CsrfError {
    MissingToken,
    DuplicateToken,
    InvalidToken,
    MissingSession,
    InvalidSession,
    ExpiredToken,
    ContextMismatch,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MissingFairing;

impl CsrfError {
    pub(crate) fn into_form_error<'r>(self) -> Error<'r> {
        Error::from((Status::Forbidden, Box::new(self) as Box<dyn std::error::Error + Send>))
            .with_name(FORM_FIELD)
            .with_entity(Entity::Value)
    }
}

impl MissingFairing {
    pub(crate) fn into_form_errors<'r>() -> form::Errors<'r> {
        form::Errors::from(
            Error::from((
                Status::InternalServerError,
                Box::new(MissingFairing) as Box<dyn std::error::Error + Send>,
            ))
            .with_entity(Entity::Form),
        )
    }
}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            CsrfError::MissingToken => "missing CSRF token",
            CsrfError::DuplicateToken => "multiple CSRF tokens were submitted",
            CsrfError::InvalidToken => "invalid CSRF token",
            CsrfError::MissingSession => "missing CSRF session",
            CsrfError::InvalidSession => "CSRF token does not match the active session",
            CsrfError::ExpiredToken => "expired CSRF token",
            CsrfError::ContextMismatch => "CSRF token has the wrong request context",
        };

        f.write_str(message)
    }
}

impl std::error::Error for CsrfError {}

impl fmt::Display for MissingFairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("missing `Csrf::fairing()`")
    }
}

impl std::error::Error for MissingFairing {}
