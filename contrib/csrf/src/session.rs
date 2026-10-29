use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;

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

struct SessionResolution {
    session: Session,
    renewal: Option<(SessionCookie, SessionCookie)>,
}

#[derive(Debug)]
enum SessionError {
    Missing,
    Invalid,
    Expired,
}

struct CachedSession(Mutex<Option<Option<Session>>>);

impl Session {
    const PRIMARY_COOKIE: &'static str = "__rocket_csrf_session_a";
    const SECONDARY_COOKIE: &'static str = "__rocket_csrf_session_b";

    pub(crate) fn find(req: &Request<'_>, ttl: Duration) -> Option<Self> {
        let cache = req.local_cache(|| CachedSession(Mutex::new(None)));
        let mut cached = cache.0.lock().expect("csrf session cache");
        if let Some(session) = cached.as_ref() {
            return session.clone();
        }

        let renewal_key = req.rocket().config().secret_key
            .derive_key("rocket_csrf session renewal v1");
        let session = Self::find_from_jar(req.cookies(), ttl, &renewal_key);
        *cached = Some(session.clone());
        session
    }

    pub(crate) fn fetch(req: &Request<'_>, ttl: Duration) -> Self {
        let cache = req.local_cache(|| CachedSession(Mutex::new(None)));
        let mut cached = cache.0.lock().expect("csrf session cache");
        if let Some(Some(session)) = cached.as_ref() {
            return session.clone();
        }

        let renewal_key = req.rocket().config().secret_key
            .derive_key("rocket_csrf session renewal v1");
        let session = Self::from_jar(req.cookies(), ttl, &renewal_key);
        *cached = Some(Some(session.clone()));
        session
    }

    #[cfg(test)]
    pub(crate) fn for_test(id: SessionId) -> Self {
        Self { primary: id, secondary: None }
    }

    pub(crate) fn id(&self) -> SessionId {
        self.primary
    }

    pub(crate) fn contains(&self, id: u64) -> bool {
        self.primary.value() == id || self.secondary.map_or(false, |other| other.value() == id)
    }

    fn from_jar(jar: &CookieJar<'_>, ttl: Duration, renewal_key: &[u8; 32]) -> Self {
        Self::from_jar_at(jar, ttl, OffsetDateTime::now_utc(), renewal_key)
    }

    fn from_jar_at(
        jar: &CookieJar<'_>,
        ttl: Duration,
        now: OffsetDateTime,
        renewal_key: &[u8; 32],
    ) -> Self {
        let Some(resolution) = Self::resolve_cookies(jar, ttl, now, renewal_key) else {
            let primary = SessionCookie::new(now);
            primary.insert(Self::PRIMARY_COOKIE, jar, ttl);
            return Session { primary: primary.id, secondary: None };
        };

        resolution.session
    }

    fn find_from_jar(
        jar: &CookieJar<'_>,
        ttl: Duration,
        renewal_key: &[u8; 32],
    ) -> Option<Self> {
        Self::resolve_cookies(jar, ttl, OffsetDateTime::now_utc(), renewal_key)
            .map(|r| r.session)
    }

    fn resolve_cookies(
        jar: &CookieJar<'_>,
        ttl: Duration,
        now: OffsetDateTime,
        renewal_key: &[u8; 32],
    ) -> Option<SessionResolution> {
        let primary = read_cookie(Self::PRIMARY_COOKIE, jar, ttl, now);
        let secondary = read_cookie(Self::SECONDARY_COOKIE, jar, ttl, now);
        let resolution = resolve(primary, secondary, ttl, now, renewal_key)?;

        if let Some((primary, secondary)) = resolution.renewal {
            primary.insert(Self::PRIMARY_COOKIE, jar, ttl);
            secondary.insert(Self::SECONDARY_COOKIE, jar, ttl);
        }

        Some(resolution)
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

    fn renew(self, ttl: Duration, key: &[u8; 32]) -> Self {
        let renew_after = (ttl.whole_seconds() / 2).max(1);
        let issued_at = self.issued_at.checked_add(renew_after)
            .expect("renewal timestamp fits in i64");
        let mut input = [0; 8 + 8 + 8 + 8 + 4];
        input[..8].copy_from_slice(&self.id.value().to_be_bytes());
        input[8..16].copy_from_slice(&self.issued_at.to_be_bytes());
        input[16..24].copy_from_slice(&issued_at.to_be_bytes());
        input[24..32].copy_from_slice(&ttl.whole_seconds().to_be_bytes());

        let mut counter = 0u32;
        let id = loop {
            input[32..].copy_from_slice(&counter.to_be_bytes());
            let digest = blake3::keyed_hash(key, &input);
            let id = u64::from_be_bytes(digest.as_bytes()[..8].try_into().unwrap());
            if id != self.id.value() {
                break id;
            }

            counter = counter.checked_add(1).expect("renewal ID collision counter");
        };

        Self { id: SessionId(id), issued_at }
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

        if now - issued > ttl {
            return Err(SessionError::Expired);
        }

        Ok(session)
    }

    fn is_valid_at(self, ttl: Duration, now: OffsetDateTime) -> bool {
        OffsetDateTime::from_unix_timestamp(self.issued_at)
            .map(|issued| now - issued <= ttl)
            .unwrap_or(false)
    }

    fn should_renew(self, ttl: Duration, now: OffsetDateTime) -> bool {
        let age = now.unix_timestamp() - self.issued_at;
        let renew_after = (ttl.whole_seconds() / 2).max(1);
        age >= renew_after && self.is_valid_at(ttl, now)
    }

    fn expires_at(self, ttl: Duration) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.issued_at)
            .expect("session cookie timestamp") + ttl
    }

    fn insert(self, name: &'static str, jar: &CookieJar<'_>, ttl: Duration) {
        let cookie = Cookie::build((name, self.to_string())).expires(self.expires_at(ttl));
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
) -> Option<SessionCookie> {
    SessionCookie::fetch(name, jar, ttl, now).ok()
}

fn resolve(
    primary: Option<SessionCookie>,
    secondary: Option<SessionCookie>,
    ttl: Duration,
    now: OffsetDateTime,
    renewal_key: &[u8; 32],
) -> Option<SessionResolution> {
    match primary {
        Some(primary) if primary.should_renew(ttl, now) => {
            let renewed = primary.renew(ttl, renewal_key);
            Some(SessionResolution {
                session: Session { primary: renewed.id, secondary: Some(primary.id) },
                renewal: Some((renewed, primary)),
            })
        }
        Some(primary) => Some(SessionResolution {
            session: Session {
                primary: primary.id,
                secondary: secondary.map(|cookie| cookie.id),
            },
            renewal: None,
        }),
        None => secondary.map(|secondary| {
            let renewed = secondary.renew(ttl, renewal_key);
            SessionResolution {
                session: Session { primary: renewed.id, secondary: Some(secondary.id) },
                renewal: Some((renewed, secondary)),
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::{Cookie, Header, Status};
    use rocket::local::asynchronous::{Client, LocalResponse};

    const TEST_KEY: [u8; 32] = [7; 32];
    const TTL: Duration = Duration::hours(24);

    fn at(hours: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::hours(hours)
    }

    #[test]
    fn renewal_precedes_browser_expiry_and_preserves_open_forms_for_one_ttl() {
        let original = SessionCookie { id: SessionId::new(7), issued_at: at(0).unix_timestamp() };
        let old_expiry = original.expires_at(TTL);

        assert!(!original.should_renew(TTL, at(11)));
        let renewed = resolve(Some(original), None, TTL, at(12), &TEST_KEY).expect("valid session");
        let (current, previous) = renewed.renewal.expect("renew before browser expiry");

        assert_ne!(current.id, original.id);
        assert!(renewed.session.contains(original.id.value()));
        assert_eq!(current.issued_at, at(12).unix_timestamp());
        assert_eq!(current.expires_at(TTL), at(36));
        assert_eq!(previous.expires_at(TTL), old_expiry);

        // Browsers omit the old cookie at its original expiry. The renewed
        // cookie remains live, while the old session ID is no longer accepted.
        assert_eq!(old_expiry, at(24));
        assert!(original.is_valid_at(TTL, old_expiry));
        assert!(!original.is_valid_at(TTL, old_expiry + Duration::seconds(1)));
        let current_session = resolve(Some(current), None, TTL, old_expiry, &TEST_KEY)
            .expect("renewed cookie is still valid");
        assert!(!current_session.session.contains(original.id.value()));
        assert!(resolve(None, None, TTL, at(36), &TEST_KEY).is_none());
    }

    #[test]
    fn repeated_renewals_do_not_extend_expired_secondary_ids() {
        let original = SessionCookie { id: SessionId::new(7), issued_at: at(0).unix_timestamp() };
        let first = resolve(Some(original), None, TTL, at(12), &TEST_KEY).unwrap();
        let (first_current, first_previous) = first.renewal.unwrap();
        assert!(first.session.contains(original.id.value()));

        let second = resolve(Some(first_current), None, TTL, at(24), &TEST_KEY).unwrap();
        let (second_current, second_previous) = second.renewal.unwrap();
        assert!(!second.session.contains(original.id.value()));
        assert!(second.session.contains(first_current.id.value()));
        assert_eq!(first_previous.expires_at(TTL), at(24));
        assert_eq!(second_previous.id, first_current.id);
        assert_eq!(second_current.expires_at(TTL), at(48));

        let third = resolve(Some(second_current), Some(second_previous), TTL, at(36), &TEST_KEY)
            .unwrap();
        assert!(!third.session.contains(original.id.value()));
    }

    #[test]
    fn renewal_id_and_timestamp_are_deterministic_even_near_expiry() {
        let original = SessionCookie { id: SessionId::new(7), issued_at: at(0).unix_timestamp() };
        let just_renewed = resolve(Some(original), None, TTL, at(12), &TEST_KEY)
            .unwrap().renewal.unwrap().0;
        let delayed = resolve(
            Some(original),
            None,
            TTL,
            at(24) - Duration::seconds(60),
            &TEST_KEY,
        )
        .unwrap()
        .renewal
        .unwrap()
        .0;

        assert_eq!(just_renewed, delayed);
        assert_eq!(delayed.issued_at, at(12).unix_timestamp());
        assert!(delayed.is_valid_at(TTL, at(24) - Duration::seconds(60)));
        assert_eq!(delayed.expires_at(TTL), at(36));
    }

    #[test]
    fn expired_secondary_is_not_carried_into_the_resolved_session() {
        let current = SessionCookie { id: SessionId::new(9), issued_at: at(18).unix_timestamp() };
        let expired = SessionCookie { id: SessionId::new(7), issued_at: at(0).unix_timestamp() };
        let now = at(24) + Duration::seconds(1);
        assert!(!expired.is_valid_at(TTL, now));

        // read_cookie() filters the expired secondary before resolve().
        let resolved = resolve(Some(current), None, TTL, now, &TEST_KEY).unwrap();
        assert!(!resolved.session.contains(expired.id.value()));
        assert!(resolved.session.contains(current.id.value()));
    }

    #[get("/test/seed/<age_seconds>")]
    fn seed_aged_session(age_seconds: i64, jar: &CookieJar<'_>) {
        let issued_at = OffsetDateTime::now_utc().unix_timestamp() - age_seconds;
        SessionCookie { id: SessionId::new(7), issued_at }
            .insert(Session::PRIMARY_COOKIE, jar, TTL);
    }

    #[get("/test/bootstrap")]
    fn bootstrap(xsrf: crate::XsrfToken) -> String {
        xsrf.to_string()
    }

    #[post("/test/verify")]
    fn verify(_xsrf: crate::VerifiedXsrf) -> Status {
        Status::NoContent
    }

    fn test_rocket() -> rocket::Rocket<rocket::Build> {
        let figment = rocket::Config::figment().merge(("secret_key", vec![42; 64]));
        rocket::custom(figment)
            .attach(crate::Csrf::fairing())
            .mount("/", routes![seed_aged_session, bootstrap, verify])
    }

    fn private_session_cookies(response: &LocalResponse<'_>) -> Vec<Cookie<'static>> {
        response.cookies().iter()
            .filter(|cookie| cookie.name() == Session::PRIMARY_COOKIE
                || cookie.name() == Session::SECONDARY_COOKIE)
            .cloned()
            .collect()
    }

    #[rocket::async_test]
    async fn concurrent_bootstraps_from_an_aged_cookie_accept_every_response_pairing() {
        let first_client = Client::untracked(test_rocket()).await.unwrap();
        let second_client = Client::untracked(test_rocket()).await.unwrap();
        let seed = first_client.get("/test/seed/86340").dispatch().await;
        let aged_cookies: Vec<_> = seed.cookies().iter().cloned().collect();
        let (first, second) = rocket::tokio::join!(
            first_client.get("/test/bootstrap").cookies(aged_cookies.clone()).dispatch(),
            second_client.get("/test/bootstrap").cookies(aged_cookies).dispatch(),
        );

        let first_token = first.cookies().get(crate::XSRF_COOKIE).unwrap().value().to_string();
        let first_cookies = private_session_cookies(&first);
        let second_token = second.cookies().get(crate::XSRF_COOKIE).unwrap().value().to_string();
        let second_cookies = private_session_cookies(&second);
        assert_eq!(first_cookies.len(), 2);
        assert_eq!(second_cookies.len(), 2);

        let pairings = [
            (&first_token, &first_cookies),
            (&first_token, &second_cookies),
            (&second_token, &first_cookies),
            (&second_token, &second_cookies),
        ];
        for client in [&first_client, &second_client] {
            for (token, cookies) in pairings {
                let response = client.post("/test/verify")
                    .cookies(cookies.to_vec())
                    .header(Header::new(crate::XSRF_HEADER, token.clone()))
                    .dispatch()
                    .await;
                assert_eq!(response.status(), Status::NoContent);
            }
        }
    }
}
