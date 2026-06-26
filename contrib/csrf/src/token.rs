use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD as ENCODING};
use rocket::time::OffsetDateTime;
use subtle::ConstantTimeEq;

use crate::config::{Phase, Rotate};
use crate::error::CsrfError;
use crate::session::{Session, SessionId};

const NONCE_LEN: usize = 12;
const DATA_LEN: usize = 4 + 8 + 1 + NONCE_LEN;
const MAC_LEN: usize = 32;
const TOKEN_LEN: usize = DATA_LEN + MAC_LEN;

#[derive(Debug)]
struct KeyState {
    keys: KeyRing,
    rotated_at: OffsetDateTime,
    phase: Phase,
}

#[derive(Debug)]
struct KeyRing {
    generation: u32,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
}

#[derive(Debug)]
struct Inner {
    rotate: Rotate,
    state: Mutex<KeyState>,
}

#[derive(Clone, Debug)]
pub(crate) struct Tokenizer {
    inner: Arc<Inner>,
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
    pub(crate) fn new(rotate: Rotate) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            inner: Arc::new(Inner {
                rotate,
                state: Mutex::new(KeyState {
                    keys: KeyRing::new(),
                    rotated_at: now,
                    phase: Phase::Epoch,
                }),
            }),
        }
    }

    pub(crate) fn form_token(&self, session: SessionId) -> Token {
        let mut state = self.inner.state.lock().expect("csrf key state");
        refresh(&mut state, self.inner.rotate, OffsetDateTime::now_utc());
        Token::new(&state.keys, session.value(), Context::Form)
    }

    pub(crate) fn header_token(&self, session: SessionId) -> Token {
        let mut state = self.inner.state.lock().expect("csrf key state");
        refresh(&mut state, self.inner.rotate, OffsetDateTime::now_utc());
        Token::new(&state.keys, session.value(), Context::Header)
    }

    pub(crate) fn verify_form(&self, token: &Token, session: &Session) -> Result<(), CsrfError> {
        let mut state = self.inner.state.lock().expect("csrf key state");
        refresh(&mut state, self.inner.rotate, OffsetDateTime::now_utc());
        token.verify(&state.keys, session, Context::Form)
    }

    pub(crate) fn verify_header(
        &self,
        token: &Token,
        session: &Session,
    ) -> Result<(), CsrfError> {
        let mut state = self.inner.state.lock().expect("csrf key state");
        refresh(&mut state, self.inner.rotate, OffsetDateTime::now_utc());
        token.verify(&state.keys, session, Context::Header)
    }
}

impl KeyRing {
    fn new() -> Self {
        Self {
            generation: 0,
            current: rand::random(),
            previous: None,
        }
    }

    fn rotate(&mut self) {
        let old = std::mem::replace(&mut self.current, rand::random());
        self.previous = Some(old);
        self.generation = self.generation.wrapping_add(1);
    }

    fn keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        std::iter::once(&self.current).chain(self.previous.iter())
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

        if keys.generation.wrapping_sub(self.data.generation) > 1 {
            return Err(CsrfError::ExpiredToken);
        }

        if !session.contains(self.data.session) {
            return Err(CsrfError::InvalidSession);
        }

        let authentic = keys.keys().any(|key| self.mac.ct_eq(&self.data.sign(key)).into());
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
        let bytes = ENCODING.decode(string).map_err(|_| ())?;
        if bytes.len() != TOKEN_LEN {
            return Err(());
        }

        let data = TokenData::from_bytes(&bytes[..DATA_LEN]).ok_or(())?;
        let mac = bytes[DATA_LEN..].try_into().map_err(|_| ())?;
        Ok(Self { data, mac })
    }
}

fn refresh(state: &mut KeyState, rotate: Rotate, now: OffsetDateTime) {
    while now - state.rotated_at >= state.phase.duration(rotate) {
        let duration = state.phase.duration(rotate);
        state.keys.rotate();
        state.rotated_at += duration;
        state.phase = state.phase.next();
    }
}

#[cfg(test)]
mod tests {
    use rocket::time::Duration;

    use super::*;

    #[test]
    fn token_round_trips() {
        let token = Tokenizer::new(Rotate::default()).form_token(SessionId::new(7));
        let parsed: Token = token.to_string().parse().expect("valid token");
        assert_eq!(token, parsed);
    }

    #[test]
    fn refresh_rotates_keys() {
        let rotate = Rotate { period: 4, window: 1 };
        let mut state = KeyState {
            keys: KeyRing::new(),
            rotated_at: OffsetDateTime::now_utc() - Duration::hours(5),
            phase: Phase::Epoch,
        };

        let generation = state.keys.generation;
        refresh(&mut state, rotate, OffsetDateTime::now_utc());
        assert!(state.keys.generation > generation);
    }
}
