use rusqlite::{params, Connection, Error as SqlError, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use std::path::Path;
use std::time::Duration;

const MAX_ID: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationReceipt {
    pub request_id: String,
    pub operation_id: String,
    pub state: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum JournalError {
    InvalidInput,
    AlreadyOwned,
    Conflict,
    Uncertain,
    Sql(String),
}

impl From<SqlError> for JournalError {
    fn from(error: SqlError) -> Self {
        Self::Sql(error.to_string())
    }
}

pub struct Journal {
    connection: Connection,
    owner: String,
}

impl Journal {
    pub fn open(path: impl AsRef<Path>, owner: &str) -> Result<Self, JournalError> {
        if owner.is_empty() || owner.len() > MAX_ID {
            return Err(JournalError::InvalidInput);
        }
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_millis(250))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS controller_lock (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 owner TEXT NOT NULL,
                 pid INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS operations (
                 request_id TEXT PRIMARY KEY,
                 operation_id TEXT NOT NULL UNIQUE,
                 digest TEXT NOT NULL,
                 state TEXT NOT NULL,
                 created_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             CREATE TABLE IF NOT EXISTS accounts (
                 account TEXT PRIMARY KEY,
                 password_hash TEXT NOT NULL,
                 enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
             );",
        )?;
        let pid = std::process::id();
        connection.execute_batch("BEGIN IMMEDIATE")?;
        let existing_pid = connection
            .query_row(
                "SELECT pid FROM controller_lock WHERE singleton = 1",
                [],
                |row| row.get::<_, u32>(0),
            )
            .optional()?;
        let result = match existing_pid {
            None => connection
                .execute(
                    "INSERT INTO controller_lock(singleton, owner, pid) VALUES (1, ?1, ?2)",
                    params![owner, pid],
                )
                .map(|_| ()),
            Some(existing_pid) if pid_alive(existing_pid) => Err(SqlError::QueryReturnedNoRows),
            Some(_) => connection
                .execute(
                    "UPDATE controller_lock SET owner = ?1, pid = ?2 WHERE singleton = 1",
                    params![owner, pid],
                )
                .map(|_| ()),
        };
        if let Err(error) = result {
            let _ = connection.execute_batch("ROLLBACK");
            if matches!(error, SqlError::QueryReturnedNoRows) {
                return Err(JournalError::AlreadyOwned);
            }
            return Err(error.into());
        }
        connection.execute_batch("COMMIT")?;
        Ok(Self {
            connection,
            owner: owner.to_owned(),
        })
    }

    pub fn receipt(&self, request_id: &str) -> Result<Option<OperationReceipt>, JournalError> {
        self.connection
            .query_row(
                "SELECT request_id, operation_id, state FROM operations WHERE request_id = ?1",
                params![request_id],
                |row| {
                    Ok(OperationReceipt {
                        request_id: row.get(0)?,
                        operation_id: row.get(1)?,
                        state: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn submit(
        &mut self,
        request_id: &str,
        operation_id: &str,
        digest: &str,
    ) -> Result<OperationReceipt, JournalError> {
        if invalid_id(request_id)
            || invalid_id(operation_id)
            || digest.is_empty()
            || digest.len() > MAX_ID
        {
            return Err(JournalError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = tx
            .query_row(
                "SELECT request_id, operation_id, digest, state FROM operations WHERE request_id = ?1",
                params![request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
        {
            if existing.1 == operation_id && existing.2 == digest {
                tx.commit()?;
                return Ok(OperationReceipt { request_id: existing.0, operation_id: existing.1, state: existing.3 });
            }
            return Err(JournalError::Conflict);
        }
        if tx
            .query_row(
                "SELECT 1 FROM operations WHERE state = 'blocked_uncertain' LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        {
            return Err(JournalError::Uncertain);
        }
        tx.execute(
            "INSERT INTO operations(request_id, operation_id, digest, state) VALUES (?1, ?2, ?3, 'active')",
            params![request_id, operation_id, digest],
        )?;
        tx.commit()?;
        Ok(OperationReceipt {
            request_id: request_id.to_owned(),
            operation_id: operation_id.to_owned(),
            state: "active".into(),
        })
    }

    pub fn block_uncertain(&mut self, operation_id: &str) -> Result<(), JournalError> {
        self.finish(operation_id, "blocked_uncertain")
    }

    pub fn finish(&mut self, operation_id: &str, state: &str) -> Result<(), JournalError> {
        if invalid_id(operation_id)
            || !matches!(state, "succeeded" | "failed_safe" | "blocked_uncertain")
        {
            return Err(JournalError::InvalidInput);
        }
        let changed = self.connection.execute(
            "UPDATE operations SET state = ?1 WHERE operation_id = ?2 AND state = 'active'",
            params![state, operation_id],
        )?;
        if changed == 0 {
            return Err(JournalError::InvalidInput);
        }
        Ok(())
    }

    pub fn set_account_enabled(
        &mut self,
        account: &str,
        enabled: bool,
    ) -> Result<(), JournalError> {
        let changed = self.connection.execute(
            "UPDATE accounts SET enabled = ?1 WHERE account = ?2",
            params![enabled as i64, account],
        )?;
        if changed == 0 {
            Err(JournalError::InvalidInput)
        } else {
            Ok(())
        }
    }

    pub fn store_account(
        &mut self,
        account: &str,
        password_hash: &str,
        enabled: bool,
    ) -> Result<(), JournalError> {
        if invalid_id(account) || password_hash.is_empty() || password_hash.len() > 4096 {
            return Err(JournalError::InvalidInput);
        }
        self.connection.execute(
            "INSERT INTO accounts(account, password_hash, enabled) VALUES (?1, ?2, ?3)",
            params![account, password_hash, enabled as i64],
        )?;
        Ok(())
    }

    pub fn accounts(&self) -> Result<Vec<(String, String, bool)>, JournalError> {
        let mut statement = self
            .connection
            .prepare("SELECT account, password_hash, enabled FROM accounts ORDER BY account")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn unfinished(&self) -> Result<Vec<OperationReceipt>, JournalError> {
        let mut statement = self.connection.prepare(
            "SELECT request_id, operation_id, state FROM operations WHERE state = 'active' ORDER BY created_at, request_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(OperationReceipt {
                request_id: row.get(0)?,
                operation_id: row.get(1)?,
                state: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = self.connection.execute(
            "DELETE FROM controller_lock WHERE singleton = 1 AND owner = ?1 AND pid = ?2",
            params![self.owner, std::process::id()],
        );
    }
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) performs no signal delivery and only probes process existence.
    unsafe {
        libc::kill(pid as libc::pid_t, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(not(unix))]
fn pid_alive(_pid: u32) -> bool {
    true
}

fn invalid_id(value: &str) -> bool {
    value.is_empty() || value.len() > MAX_ID || !value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path() -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hat-task5-{suffix}.db"))
    }

    #[test]
    fn durable_submit_is_idempotent_and_conflicts_refuse() {
        let path = path();
        let mut journal = Journal::open(&path, "controller-a").unwrap();
        let first = journal
            .submit("request-1", "operation-1", "digest-a")
            .unwrap();
        assert_eq!(
            journal
                .submit("request-1", "operation-1", "digest-a")
                .unwrap(),
            first
        );
        assert_eq!(
            journal.submit("request-1", "operation-2", "digest-b"),
            Err(JournalError::Conflict)
        );
        drop(journal);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn terminal_operations_cannot_be_rewritten() {
        let path = path();
        let mut journal = Journal::open(&path, "controller-a").unwrap();
        journal
            .submit("request-1", "operation-1", "digest-a")
            .unwrap();
        journal.finish("operation-1", "succeeded").unwrap();
        assert_eq!(
            journal.finish("operation-1", "failed_safe"),
            Err(JournalError::InvalidInput)
        );
        drop(journal);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unfinished_operations_survive_reopen_and_lock_is_exclusive() {
        let path = path();
        let journal = Journal::open(&path, "controller-a").unwrap();
        assert!(matches!(
            Journal::open(&path, "controller-b"),
            Err(JournalError::AlreadyOwned)
        ));
        drop(journal);
        let mut reopened = Journal::open(&path, "controller-b").unwrap();
        assert_eq!(reopened.unfinished().unwrap().len(), 0);
        reopened
            .submit("request-2", "operation-2", "digest-c")
            .unwrap();
        drop(reopened);
        let mut check = Journal::open(&path, "controller-c").unwrap();
        assert_eq!(check.unfinished().unwrap().len(), 1);
        check.finish("operation-2", "succeeded").unwrap();
        drop(check);
        let _ = std::fs::remove_file(path);
    }
}
