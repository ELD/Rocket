use std::fmt;
use std::str::FromStr;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD as ENCODING};
use rocket::time::OffsetDateTime;
use subtle::ConstantTimeEq;

use crate::config::Rotate;
use crate::error::CsrfError;
use crate::session::{Session, SessionId};

const NONCE_LEN: usize = 12;
const DATA_LEN: usize = 4 + 8 + 1 + NONCE_LEN;
const MAC_LEN: usize = 32;
const TOKEN_LEN: usize = DATA_LEN + MAC_LEN;

struct KeyRing {
    generation: u32,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
}

pub(crate) struct Tokenizer {
    rotate: Rotate,
    root: [u8; 32],
}

impl fmt::Debug for Tokenizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokenizer").field("rotate", &self.rotate).finish_non_exhaustive()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Context {
    Form = 0,
    Header = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    data: TokenData,
    mac: [u8; MAC_LEN],
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct TokenData {
    generation: u32,
    session: u64,
    context: Context,
    nonce: [u8; NONCE_LEN],
}

impl Tokenizer {
    pub(crate) fn new(rotate: Rotate, root: [u8; 32]) -> Self {
        Self { rotate, root }
    }

    pub(crate) fn form_token(&self, session: SessionId) -> Token {
        Token::new(&self.keys_at(OffsetDateTime::now_utc()), session.value(), Context::Form)
    }

    pub(crate) fn header_token(&self, session: SessionId) -> Token {
        Token::new(&self.keys_at(OffsetDateTime::now_utc()), session.value(), Context::Header)
    }

    pub(crate) fn verify_form(&self, token: &Token, session: &Session) -> Result<(), CsrfError> {
        token.verify(&self.keys_at(OffsetDateTime::now_utc()), session, Context::Form)
    }

    pub(crate) fn verify_header(&self, token: &Token, session: &Session) -> Result<(), CsrfError> {
        token.verify(&self.keys_at(OffsetDateTime::now_utc()), session, Context::Header)
    }

    fn keys_at(&self, now: OffsetDateTime) -> KeyRing {
        let period = i64::from(self.rotate.period) * 3600;
        let window = i64::from(self.rotate.window) * 3600;
        let timestamp = now.unix_timestamp().max(0);
        let generation = (timestamp / period) as u32;
        let previous = if timestamp % period < window {
            generation.checked_sub(1).map(|previous| self.key(previous))
        } else {
            None
        };

        KeyRing { generation, current: self.key(generation), previous }
    }

    fn key(&self, generation: u32) -> [u8; 32] {
        // Bind keys to the protocol's rotation settings as well as its epoch.
        let mut info = [0; 8];
        info[..2].copy_from_slice(&self.rotate.period.to_be_bytes());
        info[2..4].copy_from_slice(&self.rotate.window.to_be_bytes());
        info[4..].copy_from_slice(&generation.to_be_bytes());
        *blake3::keyed_hash(&self.root, &info).as_bytes()
    }
}

impl Token {
    fn new(keys: &KeyRing, session: u64, context: Context) -> Self {
        let data = TokenData {
            generation: keys.generation,
            session,
            context,
            nonce: rand::random(),
        };

        Self {
            mac: data.sign(&keys.current),
            data,
        }
    }

    fn verify(&self, keys: &KeyRing, session: &Session, context: Context) -> Result<(), CsrfError> {
        if self.data.context != context {
            return Err(CsrfError::ContextMismatch);
        }

        let key = if self.data.generation == keys.generation {
            &keys.current
        } else if keys.generation.checked_sub(1) == Some(self.data.generation) {
            keys.previous.as_ref().ok_or(CsrfError::ExpiredToken)?
        } else {
            return Err(CsrfError::ExpiredToken);
        };

        if !session.contains(self.data.session) {
            return Err(CsrfError::InvalidSession);
        }

        let authentic = self.mac.ct_eq(&self.data.sign(key)).into();
        if authentic {
            Ok(())
        } else {
            Err(CsrfError::InvalidToken)
        }
    }
}

impl TokenData {
    fn sign(&self, key: &[u8; 32]) -> [u8; MAC_LEN] {
        *blake3::keyed_hash(key, &self.to_bytes()).as_bytes()
    }

    fn to_bytes(self) -> [u8; DATA_LEN] {
        let mut bytes = [0; DATA_LEN];
        bytes[0..4].copy_from_slice(&self.generation.to_be_bytes());
        bytes[4..12].copy_from_slice(&self.session.to_be_bytes());
        bytes[12] = self.context as u8;
        bytes[13..].copy_from_slice(&self.nonce);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DATA_LEN {
            return None;
        }

        let generation = u32::from_be_bytes(bytes[0..4].try_into().ok()?);
        let session = u64::from_be_bytes(bytes[4..12].try_into().ok()?);
        let context = Context::from_byte(bytes[12])?;
        let nonce = bytes[13..].try_into().ok()?;
        Some(Self { generation, session, context, nonce })
    }
}

impl Context {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Context::Form),
            1 => Some(Context::Header),
            _ => None,
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0; TOKEN_LEN];
        bytes[..DATA_LEN].copy_from_slice(&self.data.to_bytes());
        bytes[DATA_LEN..].copy_from_slice(&self.mac);
        f.write_str(&ENCODING.encode(bytes))
    }
}

impl FromStr for Token {
    type Err = ();

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if string.len() != TOKEN_LEN * 4 / 3 {
            return Err(());
        }

        let bytes = ENCODING.decode(string).map_err(|_| ())?;
        if bytes.len() != TOKEN_LEN {
            return Err(());
        }

        let data = TokenData::from_bytes(&bytes[..DATA_LEN]).ok_or(())?;
        let mac = bytes[DATA_LEN..].try_into().map_err(|_| ())?;
        Ok(Self { data, mac })
    }
}

#[cfg(test)]
mod tests {
    use rocket::time::Duration;

    use super::*;

    fn at(hours: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::hours(hours)
    }

    #[test]
    fn token_round_trips() {
        let token = Tokenizer::new(Rotate::default(), [7; 32]).form_token(SessionId::new(7));
        let parsed: Token = token.to_string().parse().expect("valid token");
        assert_eq!(token, parsed);
    }

    #[test]
    fn replicas_derive_identical_keys_independent_of_startup() {
        let rotate = Rotate { period: 4, window: 1 };
        let first = Tokenizer::new(rotate, [7; 32]);
        let second = Tokenizer::new(rotate, [7; 32]);
        // No intermediate refresh is necessary, including after long downtime.
        for hours in [0, 3, 4, 5, 8, 100_000] {
            let a = first.keys_at(at(hours));
            let b = second.keys_at(at(hours));
            assert_eq!(a.generation, b.generation);
            assert_eq!(a.current, b.current);
            assert_eq!(a.previous, b.previous);
        }
    }

    #[test]
    fn overlap_expires_at_the_exact_boundary_without_rotating_current() {
        let tokenizer = Tokenizer::new(Rotate { period: 4, window: 1 }, [7; 32]);
        let first = tokenizer.keys_at(at(3));
        let overlap = tokenizer.keys_at(at(4));
        assert_eq!(overlap.previous, Some(first.current));
        let just_before = tokenizer.keys_at(at(5) - Duration::nanoseconds(1));
        assert_eq!(just_before.previous, Some(first.current));
        let after = tokenizer.keys_at(at(5));
        assert_eq!(after.previous, None);
        assert_eq!(after.current, overlap.current);
        let next = tokenizer.keys_at(at(8));
        assert_eq!(next.previous, Some(after.current));
        assert_ne!(next.current, after.current);
    }

    #[test]
    fn verification_checks_expiration_and_authenticity_across_periods() {
        let rotate = Rotate { period: 4, window: 1 };
        let issuer = Tokenizer::new(rotate, [7; 32]);
        let replica = Tokenizer::new(rotate, [7; 32]);
        let session = Session::for_test(SessionId::new(7));
        let token = Token::new(&issuer.keys_at(at(3)), 7, Context::Form);
        assert_eq!(token.verify(&replica.keys_at(at(3)), &session, Context::Form), Ok(()));
        assert_eq!(token.verify(&replica.keys_at(at(4)), &session, Context::Form), Ok(()));
        assert_eq!(token.verify(&replica.keys_at(at(5)), &session, Context::Form),
            Err(CsrfError::ExpiredToken));
        assert_eq!(token.verify(&replica.keys_at(at(8)), &session, Context::Form),
            Err(CsrfError::ExpiredToken));

        let future = Token::new(&issuer.keys_at(at(4)), 7, Context::Form);
        assert_eq!(future.verify(&replica.keys_at(at(3)), &session, Context::Form),
            Err(CsrfError::ExpiredToken));
        let foreign = Tokenizer::new(rotate, [8; 32]);
        assert_eq!(token.verify(&foreign.keys_at(at(3)), &session, Context::Form),
            Err(CsrfError::InvalidToken));
        let mut altered = token;
        altered.mac[0] ^= 1;
        assert_eq!(altered.verify(&replica.keys_at(at(4)), &session, Context::Form),
            Err(CsrfError::InvalidToken));
    }

    #[test]
    fn root_and_configuration_are_domain_separated() {
        let rotate = Rotate { period: 4, window: 1 };
        let first = Tokenizer::new(rotate, [7; 32]).keys_at(at(4));
        let other = Tokenizer::new(rotate, [8; 32]).keys_at(at(4));
        let config = Tokenizer::new(Rotate { period: 4, window: 2 }, [7; 32]).keys_at(at(4));
        assert_ne!(first.current, other.current);
        assert_ne!(first.current, config.current);
    }

    #[test]
    fn debug_output_does_not_expose_root() {
        let tokenizer = Tokenizer::new(Rotate::default(), [123; 32]);
        assert!(!format!("{tokenizer:?}").contains("123"));
    }
}
