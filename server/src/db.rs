//! SQLite (WAL) mit Verbindungs-Pool. Alle Abfragen laufen ueber [`Db::run`] im Blocking-Pool,
//! ausschliesslich mit gebundenen Parametern (keine SQL-Verkettung mit Eingaben).

use crate::error::{AppError, AppResult};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use std::{path::Path, time::Duration};

#[derive(Clone)]
pub struct Db {
  pool: Pool<SqliteConnectionManager>,
}

/// Aktuelle Zeit in Unix-Sekunden.
pub fn now() -> i64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs() as i64)
    .unwrap_or_default()
}

fn setup(c: &mut Connection) -> rusqlite::Result<()> {
  c.busy_timeout(Duration::from_secs(5))?;
  c.execute_batch(
    "PRAGMA foreign_keys = ON;
     PRAGMA synchronous = NORMAL;
     PRAGMA temp_store = MEMORY;
     PRAGMA secure_delete = ON;",
  )?;
  Ok(())
}

impl Db {
  pub fn open(path: &Path) -> anyhow_like::Result<Self> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
      std::fs::create_dir_all(dir)?;
    }
    // WAL einmalig vor dem Pool setzen (gilt dauerhaft fuer die Datei); parallel beim Aufbau
    // des Pools gesetzt, sperren sich die Verbindungen gegenseitig.
    {
      let c = Connection::open(path)?;
      c.busy_timeout(Duration::from_secs(5))?;
      c.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
    }
    let manager = SqliteConnectionManager::file(path).with_init(setup);
    let pool = Pool::builder().max_size(8).build(manager)?;
    let db = Self { pool };
    db.migrate()?;
    Ok(db)
  }

  /// Nur fuer Tests: Datenbank im Speicher (eine geteilte Verbindung).
  #[cfg(test)]
  pub fn memory() -> Self {
    let manager = SqliteConnectionManager::memory().with_init(setup);
    let pool = Pool::builder().max_size(1).build(manager).unwrap();
    let db = Self { pool };
    db.migrate().unwrap();
    db
  }

  /// Fuehrt `f` mit einer Verbindung im Blocking-Pool aus.
  pub async fn run<T, F>(&self, f: F) -> AppResult<T>
  where
    T: Send + 'static,
    F: FnOnce(&mut Connection) -> AppResult<T> + Send + 'static,
  {
    let pool = self.pool.clone();
    tokio::task::spawn_blocking(move || {
      let mut conn = pool.get()?;
      f(&mut conn)
    })
    .await?
  }

  pub fn conn(&self) -> AppResult<r2d2::PooledConnection<SqliteConnectionManager>> {
    self.pool.get().map_err(AppError::from)
  }

  fn migrate(&self) -> anyhow_like::Result<()> {
    let conn = self.pool.get()?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 1 {
      conn.execute_batch(SCHEMA_V1)?;
      conn.execute_batch("PRAGMA user_version = 1")?;
    }
    Ok(())
  }
}

/// Minimaler Fehler-Sammeltyp fuer den Start (ohne zusaetzliche Abhaengigkeit).
pub mod anyhow_like {
  pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}

const SCHEMA_V1: &str = r#"
CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE TABLE sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

-- Eigene Schluesselpaare. Privater Schluessel, Widerrufszertifikat und persoenliches Raetsel liegen
-- nur versiegelt vor (XChaCha20-Poly1305, Schluessel aus NRZPGP_MASTER_KEY + uid, siehe seal.rs);
-- der private Schluessel ist darunter zusaetzlich mit der Passphrase geschuetzt (OpenPGP-S2K).
CREATE TABLE profiles (
  id                INTEGER PRIMARY KEY,
  uid               TEXT NOT NULL UNIQUE,
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label             TEXT NOT NULL,
  purpose           TEXT NOT NULL DEFAULT '',
  key_uid           TEXT NOT NULL,
  email             TEXT NOT NULL DEFAULT '',
  fingerprint       TEXT NOT NULL,
  key_id            TEXT NOT NULL,
  algorithm         TEXT NOT NULL,
  key_created_at    INTEGER NOT NULL,
  public_key        TEXT NOT NULL,
  sealed_secret     BLOB NOT NULL,
  sealed_revocation BLOB NOT NULL,
  sealed_riddle     BLOB NOT NULL,
  exports           INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL,
  last_used_at      INTEGER,
  UNIQUE (user_id, fingerprint)
);

-- Oeffentliche Schluessel anderer (Schluesselbund).
CREATE TABLE contacts (
  id             INTEGER PRIMARY KEY,
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label          TEXT NOT NULL,
  fingerprint    TEXT NOT NULL,
  key_id         TEXT NOT NULL,
  user_ids       TEXT NOT NULL DEFAULT '[]',
  algorithm      TEXT NOT NULL,
  key_created_at INTEGER NOT NULL,
  public_key     TEXT NOT NULL,
  note           TEXT NOT NULL DEFAULT '',
  verified       INTEGER NOT NULL DEFAULT 0,
  added_at       INTEGER NOT NULL,
  UNIQUE (user_id, fingerprint)
);

-- Protokoll: nur Aktion und Beschreibung, nie Nachrichteninhalte, Passphrasen oder Schluessel.
CREATE TABLE audit (
  id      INTEGER PRIMARY KEY,
  user_id INTEGER,
  at      INTEGER NOT NULL,
  action  TEXT NOT NULL,
  detail  TEXT NOT NULL DEFAULT '',
  ip      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_user ON audit(user_id, id);
"#;
