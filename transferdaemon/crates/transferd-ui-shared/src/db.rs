//! Local SQLite database for the UI cache.

use crate::types::{Contact, Message, MessageContent, MessageStatus};
use egui::Color32;
use rusqlite::{Connection, Result as SqlResult, params};
use serde_json;
use std::collections::HashMap;
use std::path::Path;

pub struct LocalDb {
    conn: Connection,
}

fn color_to_hex(c: Color32) -> String {
    format!("#{:02X}{:02X}{:02X}", c.r(), c.g(), c.b())
}

fn color_from_hex(s: &str) -> Color32 {
    let h = s.trim_start_matches('#');
    if h.len() == 6 {
        if let (Ok(r), Ok(g), Ok(b)) = (
            u8::from_str_radix(&h[0..2], 16),
            u8::from_str_radix(&h[2..4], 16),
            u8::from_str_radix(&h[4..6], 16),
        ) {
            return Color32::from_rgb(r, g, b);
        }
    }
    Color32::from_rgb(0, 122, 255)
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
                online       INTEGER NOT NULL DEFAULT 0,
                nickname     TEXT,
                blocked      INTEGER NOT NULL DEFAULT 0,
                color        TEXT
            );
            CREATE TABLE IF NOT EXISTS messages (
                id             TEXT PRIMARY KEY,
                contact_id     TEXT NOT NULL,
                outbound       INTEGER NOT NULL,
                content_json   TEXT NOT NULL,
                timestamp_ts   INTEGER NOT NULL,
                status         TEXT NOT NULL,
                group_id       TEXT,
                sender_pk      TEXT,
                reply_to       TEXT,
                reactions_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_messages_contact
                ON messages (contact_id, timestamp_ts);
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        ")
    }

    // ── Identity cache ───────────────────────────────────────────────────────

    pub fn cache_identity(&self, public_key: &str, display_name: &str) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES ('identity_pk', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![public_key],
        )?;
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES ('identity_name', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![display_name],
        )?;
        Ok(())
    }

    pub fn load_cached_identity(&self) -> SqlResult<Option<(String, String)>> {
        let pk = self.get_setting("identity_pk")?;
        let name = self.get_setting("identity_name")?;
        Ok(match (pk, name) {
            (Some(p), Some(n)) => Some((p, n)),
            _ => None,
        })
    }

    pub fn cache_recovery_phrase(&self, phrase: &str) -> SqlResult<()> {
        self.set_setting("recovery_phrase", phrase)
    }

    pub fn load_cached_recovery_phrase(&self) -> SqlResult<Option<String>> {
        self.get_setting("recovery_phrase")
    }

    // ── Contacts ─────────────────────────────────────────────────────────────

    pub fn upsert_contact(&self, c: &Contact) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO contacts (id, name, last_seen_ts, online, nickname, blocked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                last_seen_ts=excluded.last_seen_ts,
                online=excluded.online,
                nickname=excluded.nickname,
                blocked=excluded.blocked",
            params![
                c.id,
                c.name,
                c.last_seen_ts.map(|t| t as i64),
                c.online as i32,
                c.nickname,
                c.blocked as i32,
            ],
        )?;
        Ok(())
    }

    pub fn set_contact_nickname(&self, contact_id: &str, nickname: Option<&str>) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE contacts SET nickname=?1 WHERE id=?2",
            params![nickname, contact_id],
        )?;
        Ok(())
    }

    pub fn set_contact_color(&self, contact_id: &str, color: Color32) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO contacts (id, name, color) VALUES (?1, '', ?2)
             ON CONFLICT(id) DO UPDATE SET color=excluded.color",
            params![contact_id, color_to_hex(color)],
        )?;
        Ok(())
    }

    pub fn load_all_contact_colors(&self) -> SqlResult<HashMap<String, Color32>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, color FROM contacts WHERE color IS NOT NULL"
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let color: String = row.get(1)?;
            Ok((id, color_from_hex(&color)))
        })?;
        let mut map = HashMap::new();
        for r in rows.flatten() {
            map.insert(r.0, r.1);
        }
        Ok(map)
    }

    pub fn load_contacts(&self) -> SqlResult<Vec<Contact>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, last_seen_ts, online, nickname, blocked FROM contacts ORDER BY name"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Contact {
                id: row.get(0)?,
                name: row.get(1)?,
                last_seen_ts: row.get::<_, Option<i64>>(2)?.map(|t| t as u64),
                online: row.get::<_, i32>(3)? != 0,
                nickname: row.get(4)?,
                blocked: row.get::<_, i32>(5)? != 0,
                typing: false,
            })
        })?;
        rows.collect()
    }

    // ── Messages ─────────────────────────────────────────────────────────────

    pub fn insert_message(&self, m: &Message) -> SqlResult<()> {
        let content_json = serde_json::to_string(&m.content).unwrap_or_else(|_| "{}".into());
        let status_str = format!("{:?}", m.status);
        let reactions_json = serde_json::to_string(&m.reactions).unwrap_or_else(|_| "[]".into());
        self.conn.execute(
            "INSERT OR IGNORE INTO messages
             (id, contact_id, outbound, content_json, timestamp_ts, status, group_id, sender_pk, reply_to, reactions_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                m.id,
                m.contact_id,
                m.outbound as i32,
                content_json,
                m.timestamp_ts as i64,
                status_str,
                m.group_id,
                m.sender_pk,
                m.reply_to,
                reactions_json,
            ],
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
            "SELECT id, contact_id, outbound, content_json, timestamp_ts, status,
                    group_id, sender_pk, reply_to, reactions_json
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
            let reactions_json: String = row.get(9)?;
            let reactions: Vec<(String, String)> = serde_json::from_str(&reactions_json)
                .unwrap_or_default();
            Ok(Message {
                id: row.get(0)?,
                contact_id: row.get(1)?,
                outbound: row.get::<_, i32>(2)? != 0,
                content,
                timestamp_ts: row.get::<_, i64>(4)? as u64,
                status,
                group_id: row.get(6)?,
                sender_pk: row.get(7)?,
                reply_to: row.get(8)?,
                reactions,
            })
        })?;
        rows.collect()
    }

    // ── Settings ─────────────────────────────────────────────────────────────

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
        rows.next()?.map(|r| r.get(0)).transpose()
    }
}