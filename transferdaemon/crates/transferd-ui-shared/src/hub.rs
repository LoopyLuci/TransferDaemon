//! The window's link to the daemon's control hub, for the pages that use it: the activity log, the terminal, the
//! daemon's own controls and the update state.
//!
//! Each call runs on its own thread, so a slow or stopped daemon never holds up a frame. A page starts calls on a
//! [`Calls`] and takes the answers out of it each frame.

use serde_json::Value;
use std::collections::HashSet;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;
use transferd_activity::Level;

/// Run one operation on the daemon's control hub, with its JSON arguments. Errors are text for the user.
pub fn call(op: &str, args: Value) -> Result<Value, String> {
    transferd_control::Client::connect()
        .and_then(|client| client.with_timeout(Duration::from_secs(30)).call(op, args))
        .map_err(|e| e.to_string())
}

/// Record an event in the daemon's activity log, from a window (its own errors, and what the user did). Fire and
/// forget: a daemon that is not running simply does not record it.
pub fn report(level: Level, category: &'static str, message: impl Into<String>) {
    let message = message.into();
    std::thread::spawn(move || {
        let _ = call(
            "activity.record",
            serde_json::json!({"level": level.as_str(), "category": category, "source": "gui", "message": message}),
        );
    });
}

/// Background work, collected by label. Starting a label that is still running does nothing (so a poll never
/// piles up); a label is free again once its result has been taken with [`Calls::drain`].
pub struct Calls<T: Send + 'static> {
    tx: Sender<(String, T)>,
    rx: Receiver<(String, T)>,
    running: HashSet<String>,
}

impl<T: Send + 'static> Default for Calls<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send + 'static> Calls<T> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self { tx, rx, running: HashSet::new() }
    }

    /// Run `work` on a thread under `label`. Returns false, and does nothing, when `label` is still running.
    pub fn start(&mut self, label: &str, work: impl FnOnce() -> T + Send + 'static) -> bool {
        if self.running.contains(label) {
            return false;
        }
        self.running.insert(label.to_string());
        let tx = self.tx.clone();
        let owned = label.to_string();
        std::thread::spawn(move || {
            let result = work();
            let _ = tx.send((owned, result));
        });
        true
    }

    /// Whether `label` has work in progress.
    pub fn busy(&self, label: &str) -> bool {
        self.running.contains(label)
    }

    /// Whether any work is still in progress.
    pub fn pending(&self) -> bool {
        !self.running.is_empty()
    }

    /// The results that have arrived since the last call.
    pub fn drain(&mut self) -> Vec<(String, T)> {
        let mut done = Vec::new();
        while let Ok((label, result)) = self.rx.try_recv() {
            self.running.remove(&label);
            done.push((label, result));
        }
        done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_runs_once_at_a_time_and_its_result_comes_back() {
        let mut calls: Calls<u32> = Calls::new();
        assert!(calls.start("poll", || 7));
        // Still running (or just finished on its thread): a second start under the same label is refused until drained.
        let mut answers = Vec::new();
        for _ in 0..200 {
            answers.extend(calls.drain());
            if !answers.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(answers, vec![("poll".to_string(), 7)]);
        assert!(!calls.busy("poll"));
        assert!(calls.start("poll", || 8), "free again after its result was taken");
    }

    #[test]
    fn distinct_labels_run_side_by_side() {
        let mut calls: Calls<&'static str> = Calls::new();
        assert!(calls.start("cmd1", || "a"));
        assert!(calls.start("cmd2", || "b"));
        assert!(calls.busy("cmd1") && calls.busy("cmd2"));
    }
}
