//! Local SQLite database for the UI cache.

use crate::types::{Contact, Message, MessageContent, MessageStatus};
use rusqlite::{Connection, Result as SqlResult, params};
use serde_json;
use std::path::Path;

pub struct LocalDb {
    conn: Connection,
}

impl LocalDb {
    pub fn open(path: impl AsRef<Path>) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> SqlResult<()> {
        self.conn.execute_batch("
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS contacts (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                last_seen_ts INTEGER,
                online       INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS messages (
                id           TEXT PRIMARY KEY,
                contact_id   TEXT NOT NULL,
                outbound     INTEGER NOT NULL,
                content_json TEXT NOT NULL,
                timestamp_ts INTEGER NOT NULL,
                status       TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_contact
                ON messages (contact_id, timestamp_ts);
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        ")
    }

    pub fn upsert_contact(&self, c: &Contact) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO contacts (id, name, last_seen_ts, online)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                last_seen_ts=excluded.last_seen_ts,
                online=excluded.online",
            params![c.id, c.name, c.last_seen_ts.map(|t| t as i64), c.online as i32],
        )?;
        Ok(())
    }

    pub fn load_contacts(&self) -> SqlResult<Vec<Contact>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, last_seen_ts, online FROM contacts ORDER BY name"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Contact {
                id: row.get(0)?,
                name: row.get(1)?,
                last_seen_ts: row.get::<_, Option<i64>>(2)?.map(|t| t as u64),
                online: row.get::<_, i32>(3)? != 0,
            })
        })?;
        rows.collect()
    }

    pub fn insert_message(&self, m: &Message) -> SqlResult<()> {
        let content_json = serde_json::to_string(&m.content).unwrap_or_else(|_| "{}".into());
        let status_str = format!("{:?}", m.status);
        self.conn.execute(
            "INSERT OR IGNORE INTO messages
             (id, contact_id, outbound, content_json, timestamp_ts, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![m.id, m.contact_id, m.outbound as i32, content_json, m.timestamp_ts as i64, status_str],
        )?;
        Ok(())
    }

    pub fn update_message_status(&self, id: &str, status: MessageStatus) -> SqlResult<()> {
        let status_str = format!("{:?}", status);
        self.conn.execute("UPDATE messages SET status=?1 WHERE id=?2", params![status_str, id])?;
        Ok(())
    }

    pub fn load_messages(&self, contact_id: &str) -> SqlResult<Vec<Message>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, contact_id, outbound, content_json, timestamp_ts, status
             FROM messages WHERE contact_id=?1 ORDER BY timestamp_ts"
        )?;
        let rows = stmt.query_map([contact_id], |row| {
            let content_json: String = row.get(3)?;
            let status_str: String = row.get(5)?;
            let content: MessageContent = serde_json::from_str(&content_json)
                .unwrap_or(MessageContent::Text("[unreadable]".into()));
            let status = match status_str.as_str() {
                "Pending"   => MessageStatus::Pending,
                "Sent"      => MessageStatus::Sent,
                "Delivered" => MessageStatus::Delivered,
                "Read"      => MessageStatus::Read,
                _           => MessageStatus::Failed,
            };
            Ok(Message {
                id: row.get(0)?,
                contact_id: row.get(1)?,
                outbound: row.get::<_, i32>(2)? != 0,
                content,
                timestamp_ts: row.get::<_, i64>(4)? as u64,
                status,
            })
        })?;
        rows.collect()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> SqlResult<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT value FROM settings WHERE key=?1")?;
        let mut rows = stmt.query([key])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }
}
