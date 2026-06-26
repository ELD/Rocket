use std::fmt;
use std::str::FromStr;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD as ENCODING};
use rocket::Request;
use rocket::http::{Cookie, CookieJar};
use rocket::time::{Duration, OffsetDateTime};

const ENCODED_LEN: usize = 22;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct SessionId(u64);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct SessionCookie {
    id: SessionId,
    issued_at: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct Session {
    primary: SessionId,
    secondary: Option<SessionId>,
}

#[derive(Debug)]
enum SessionError {
    Missing,
    Invalid,
    Expired(SessionCookie, Duration),
}

impl Session {
    const PRIMARY_COOKIE: &'static str = "__rocket_csrf_session_a";
    const SECONDARY_COOKIE: &'static str = "__rocket_csrf_session_b";

    pub(crate) fn find(req: &Request<'_>, ttl: Duration) -> Option<Self> {
        req.local_cache(|| Self::read(req.cookies(), ttl)).clone()
    }

    pub(crate) fn fetch(req: &Request<'_>, ttl: Duration) -> Self {
        req.local_cache(|| Self::from_jar(req.cookies(), ttl)).clone()
    }

    pub(crate) fn id(&self) -> SessionId {
        self.primary
    }

    pub(crate) fn contains(&self, id: u64) -> bool {
        self.primary.value() == id || self.secondary.map_or(false, |other| other.value() == id)
    }

    fn from_jar(jar: &CookieJar<'_>, ttl: Duration) -> Self {
        let now = OffsetDateTime::now_utc();
        let secondary = read_cookie(Self::SECONDARY_COOKIE, jar, ttl, now);

        match SessionCookie::fetch(Self::PRIMARY_COOKIE, jar, ttl, now) {
            Ok(primary) => Session { primary: primary.id, secondary },
            Err(SessionError::Expired(expired, elapsed)) if elapsed <= ttl => {
                let primary = SessionCookie::new(now);
                let secondary_cookie = SessionCookie::carry(expired.id, now);
                primary.insert(Self::PRIMARY_COOKIE, jar, ttl, now);
                secondary_cookie.insert(Self::SECONDARY_COOKIE, jar, ttl, now);

                Session {
                    primary: primary.id,
                    secondary: Some(secondary_cookie.id),
                }
            }
            Err(_) => {
                let primary = SessionCookie::new(now);
                primary.insert(Self::PRIMARY_COOKIE, jar, ttl, now);
                Session { primary: primary.id, secondary }
            }
        }
    }

    fn read(jar: &CookieJar<'_>, ttl: Duration) -> Option<Self> {
        let now = OffsetDateTime::now_utc();
        let primary = read_cookie(Self::PRIMARY_COOKIE, jar, ttl, now);
        let secondary = read_cookie(Self::SECONDARY_COOKIE, jar, ttl, now);

        match (primary, secondary) {
            (Some(primary), Some(secondary)) => Some(Session {
                primary,
                secondary: Some(secondary),
            }),
            (Some(primary), None) => Some(Session { primary, secondary: None }),
            (None, Some(secondary)) => Some(Session { primary: secondary, secondary: None }),
            (None, None) => None,
        }
    }
}

impl SessionId {
    #[cfg(test)]
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) fn value(self) -> u64 {
        self.0
    }
}

impl SessionCookie {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            id: SessionId(rand::random()),
            issued_at: now.unix_timestamp(),
        }
    }

    fn carry(id: SessionId, now: OffsetDateTime) -> Self {
        Self { id, issued_at: now.unix_timestamp() }
    }

    fn fetch(
        name: &str,
        jar: &CookieJar<'_>,
        ttl: Duration,
        now: OffsetDateTime,
    ) -> Result<Self, SessionError> {
        let cookie = jar.get_private(name).ok_or(SessionError::Missing)?;
        let session = cookie.value().parse::<SessionCookie>().map_err(|_| SessionError::Invalid)?;
        let issued = OffsetDateTime::from_unix_timestamp(session.issued_at)
            .map_err(|_| SessionError::Invalid)?;

        let age = now - issued;
        if age > ttl {
            return Err(SessionError::Expired(session, age - ttl));
        }

        Ok(session)
    }

    fn insert(self, name: &'static str, jar: &CookieJar<'_>, ttl: Duration, now: OffsetDateTime) {
        let cookie = Cookie::build((name, self.to_string())).expires(now + ttl);
        jar.add_private(cookie);
    }
}

impl FromStr for SessionCookie {
    type Err = ();

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if string.len() != ENCODED_LEN {
            return Err(());
        }

        let bytes = ENCODING.decode(string).map_err(|_| ())?;
        if bytes.len() != 16 {
            return Err(());
        }

        let id = u64::from_be_bytes(bytes[0..8].try_into().map_err(|_| ())?);
        let issued_at = i64::from_be_bytes(bytes[8..16].try_into().map_err(|_| ())?);
        Ok(Self { id: SessionId(id), issued_at })
    }
}

impl fmt::Display for SessionCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&self.id.value().to_be_bytes());
        bytes[8..16].copy_from_slice(&self.issued_at.to_be_bytes());
        f.write_str(&ENCODING.encode(bytes))
    }
}

fn read_cookie(
    name: &str,
    jar: &CookieJar<'_>,
    ttl: Duration,
    now: OffsetDateTime,
) -> Option<SessionId> {
    SessionCookie::fetch(name, jar, ttl, now).ok().map(|cookie| cookie.id)
}
