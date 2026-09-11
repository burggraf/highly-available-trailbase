use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use getrandom::fill;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_ACCOUNT: usize = 64;
const MAX_PASSWORD: usize = 64;
const IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);
const ABSOLUTE_LIMIT: Duration = Duration::from_secs(8 * 60 * 60);
const MAX_SESSIONS: usize = 1024;
const MAX_FAILURES: u8 = 5;
const MAX_FAILURE_KEYS: usize = 4096;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    InvalidInput,
    Refused,
    Revoked,
}

struct Account {
    hash: String,
    enabled: bool,
}

struct Session {
    account: String,
    issued: Instant,
    last_seen: Instant,
    revoked: bool,
}

pub struct AuthStore {
    accounts: HashMap<String, Account>,
    sessions: HashMap<[u8; 32], Session>,
    failures: HashMap<String, (u8, Instant)>,
}

impl AuthStore {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            sessions: HashMap::new(),
            failures: HashMap::new(),
        }
    }

    pub fn create_account(&mut self, account: &str, password: &str) -> Result<(), AuthError> {
        if !valid_account(account)
            || !valid_password(password)
            || self.accounts.contains_key(account)
        {
            return Err(AuthError::InvalidInput);
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AuthError::InvalidInput)?
            .to_string();
        self.accounts.insert(
            account.to_owned(),
            Account {
                hash,
                enabled: true,
            },
        );
        Ok(())
    }

    pub fn load_account(
        &mut self,
        account: &str,
        hash: &str,
        enabled: bool,
    ) -> Result<(), AuthError> {
        if !valid_account(account)
            || hash.is_empty()
            || hash.len() > 4096
            || self.accounts.contains_key(account)
        {
            return Err(AuthError::InvalidInput);
        }
        PasswordHash::new(hash).map_err(|_| AuthError::InvalidInput)?;
        self.accounts.insert(
            account.to_owned(),
            Account {
                hash: hash.to_owned(),
                enabled,
            },
        );
        Ok(())
    }

    pub fn password_hash(&self, account: &str) -> Option<&str> {
        self.accounts
            .get(account)
            .map(|record| record.hash.as_str())
    }

    pub fn login(&mut self, account: &str, password: &str) -> Result<String, AuthError> {
        if !valid_account(account) || !valid_password(password) {
            return Err(AuthError::Refused);
        }
        let now = Instant::now();
        self.failures
            .retain(|_, (_, started)| now.duration_since(*started) <= FAILURE_WINDOW);
        if self.failures.get(account).is_some_and(|(count, started)| {
            *count >= MAX_FAILURES && now.duration_since(*started) <= FAILURE_WINDOW
        }) {
            return Err(AuthError::Refused);
        }
        let valid = self.accounts.get(account).is_some_and(|record| {
            let Ok(parsed) = PasswordHash::new(&record.hash) else {
                return false;
            };
            record.enabled
                && Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
        });
        if !valid {
            if !self.failures.contains_key(account) && self.failures.len() >= MAX_FAILURE_KEYS {
                return Err(AuthError::Refused);
            }
            let entry = self.failures.entry(account.to_owned()).or_insert((0, now));
            if now.duration_since(entry.1) > FAILURE_WINDOW {
                *entry = (0, now);
            }
            entry.0 = entry.0.saturating_add(1);
            return Err(AuthError::Refused);
        }
        self.failures.remove(account);
        self.sessions.retain(|_, session| {
            !session.revoked
                && now.duration_since(session.issued) <= ABSOLUTE_LIMIT
                && now.duration_since(session.last_seen) <= IDLE_LIMIT
        });
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(AuthError::Refused);
        }
        let mut token = [0u8; 32];
        fill(&mut token).map_err(|_| AuthError::Refused)?;
        let token_string: String = token.iter().map(|byte| format!("{byte:02x}")).collect();
        self.sessions.insert(
            hash_token_string(&token_string),
            Session {
                account: account.to_owned(),
                issued: now,
                last_seen: now,
                revoked: false,
            },
        );
        Ok(token_string)
    }

    pub fn authenticate(&mut self, token: &str) -> Result<String, AuthError> {
        let key = hash_token_string(token);
        let Some(session) = self.sessions.get_mut(&key) else {
            return Err(AuthError::Refused);
        };
        let now = Instant::now();
        if session.revoked
            || now.duration_since(session.issued) > ABSOLUTE_LIMIT
            || now.duration_since(session.last_seen) > IDLE_LIMIT
        {
            session.revoked = true;
            return Err(AuthError::Revoked);
        }
        if self
            .accounts
            .get(&session.account)
            .is_some_and(|account| !account.enabled)
        {
            return Err(AuthError::Revoked);
        }
        session.last_seen = now;
        Ok(session.account.clone())
    }

    pub fn revoke(&mut self, token: &str) {
        let key = hash_token_string(token);
        if let Some(session) = self.sessions.get_mut(&key) {
            session.revoked = true;
        }
    }

    pub fn logout(&mut self, token: &str) {
        self.sessions.remove(&hash_token_string(token));
    }

    pub fn disable_account(&mut self, account: &str) -> Result<(), AuthError> {
        let Some(record) = self.accounts.get_mut(account) else {
            return Err(AuthError::InvalidInput);
        };
        record.enabled = false;
        for session in self
            .sessions
            .values_mut()
            .filter(|session| session.account == account)
        {
            session.revoked = true;
        }
        Ok(())
    }
}

impl Default for AuthStore {
    fn default() -> Self {
        Self::new()
    }
}

fn valid_account(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ACCOUNT
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_password(value: &str) -> bool {
    let length = value.chars().count();
    (15..=MAX_PASSWORD).contains(&length)
}

fn hash_token_string(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_uses_generic_refusal_and_revocable_opaque_session() {
        let mut auth = AuthStore::new();
        auth.create_account("operator", "a sufficiently long password")
            .unwrap();
        assert_eq!(
            auth.login("missing", "a sufficiently long password"),
            Err(AuthError::Refused)
        );
        let token = auth
            .login("operator", "a sufficiently long password")
            .unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(auth.authenticate(&token), Ok("operator".into()));
        auth.revoke(&token);
        assert_eq!(auth.authenticate(&token), Err(AuthError::Revoked));
    }

    #[test]
    fn short_or_oversized_passwords_are_refused() {
        let mut auth = AuthStore::new();
        assert_eq!(
            auth.create_account("operator", "short"),
            Err(AuthError::InvalidInput)
        );
        assert_eq!(
            auth.create_account("operator", &"x".repeat(65)),
            Err(AuthError::InvalidInput)
        );
    }

    #[test]
    fn failed_logins_are_bounded_and_account_disable_revokes_sessions() {
        let mut auth = AuthStore::new();
        auth.create_account("operator", "a sufficiently long password")
            .unwrap();
        for _ in 0..5 {
            assert_eq!(
                auth.login("operator", "wrong password that is long"),
                Err(AuthError::Refused)
            );
        }
        assert_eq!(
            auth.login("operator", "a sufficiently long password"),
            Err(AuthError::Refused)
        );

        let mut fresh = AuthStore::new();
        fresh
            .create_account("operator", "a sufficiently long password")
            .unwrap();
        let token = fresh
            .login("operator", "a sufficiently long password")
            .unwrap();
        fresh.disable_account("operator").unwrap();
        assert_eq!(fresh.authenticate(&token), Err(AuthError::Revoked));
        fresh.logout(&token);
        assert_eq!(fresh.authenticate(&token), Err(AuthError::Refused));
    }
}
