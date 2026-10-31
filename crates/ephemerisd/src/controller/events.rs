//! Events for the controller (docs/controller-api.md, Telemetry): what
//! happened, queued until the link sends it.
//!
//! - **Coalescing:** an event of the same kind for the same subject (a
//!   tether, an interface) within [`COALESCE`] of the last one sent is held
//!   back; when the window ends, the latest of them goes out with
//!   `"repeats": n` in its detail. A flapping tether makes one event per
//!   window, and the last one still says how it ended.
//! - **A cap:** at most [`PER_MINUTE`] events leave a minute; the rest are
//!   counted (`dropped`).
//! - **Bounded:** at most [`QUEUE`] events wait while the link is down; the
//!   oldest go first.

use serde_json::{json, Map, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

pub const COALESCE: Duration = Duration::from_secs(10);
pub const PER_MINUTE: usize = 60;
pub const QUEUE: usize = 256;
/// A detail is at most this big (in JSON).
const DETAIL_MAX: usize = 4096;

#[derive(Default)]
pub struct Events {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    ready: VecDeque<Value>,
    /// Per (kind, subject): when one was last let through, and the latest
    /// held back since (with how many).
    recent: HashMap<(String, String), Recent>,
    /// When each event in the last minute was sent.
    sent: VecDeque<Instant>,
    pub dropped: u64,
}

struct Recent {
    at: Instant,
    held: Option<(Value, u64)>,
}

/// RFC 3339, UTC, to the second.
fn rfc3339(t: SystemTime) -> String {
    let t = time::OffsetDateTime::from(t);
    let t = t.replace_nanosecond(0).unwrap_or(t);
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl Events {
    /// Something happened: `kind` (dotted, lowercase), about `subject`
    /// (what coalescing keys on: a tether's or interface's name, or ""),
    /// with a flat `detail`.
    pub fn emit(&self, kind: &str, subject: &str, detail: Value) {
        self.emit_at(kind, subject, detail, Instant::now(), SystemTime::now());
    }

    fn emit_at(&self, kind: &str, subject: &str, detail: Value, now: Instant, wall: SystemTime) {
        let mut detail = match detail {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        if Value::Object(detail.clone()).to_string().len() > DETAIL_MAX {
            detail = Map::new();
            detail.insert("truncated".into(), true.into());
        }
        let event = json!({"type": "event", "at": rfc3339(wall), "kind": kind, "detail": detail});
        let mut g = self.inner.lock().unwrap();
        let key = (kind.to_string(), subject.to_string());
        match g.recent.get_mut(&key) {
            Some(r) if now.duration_since(r.at) < COALESCE => {
                let n = r.held.as_ref().map_or(0, |(_, n)| *n);
                r.held = Some((event, n + 1));
            }
            _ => {
                g.recent.insert(
                    key,
                    Recent {
                        at: now,
                        held: None,
                    },
                );
                g.push(event);
            }
        }
    }

    /// The events to send now (held ones whose window ended, the cap
    /// allowing).
    pub fn take(&self) -> Vec<Value> {
        self.take_at(Instant::now())
    }

    fn take_at(&self, now: Instant) -> Vec<Value> {
        let mut g = self.inner.lock().unwrap();
        let mut due = Vec::new();
        g.recent.retain(|_, r| {
            if now.duration_since(r.at) < COALESCE {
                return true;
            }
            if let Some((mut e, n)) = r.held.take() {
                e["detail"]["repeats"] = n.into();
                due.push(e);
                // It went out now: the next one waits a window again.
                r.at = now;
                return true;
            }
            false
        });
        for e in due {
            g.push(e);
        }
        while g
            .sent
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            g.sent.pop_front();
        }
        let room = PER_MINUTE.saturating_sub(g.sent.len()).min(g.ready.len());
        let out: Vec<Value> = g.ready.drain(..room).collect();
        g.sent.extend(std::iter::repeat_n(now, out.len()));
        out
    }

    /// Events dropped: over the cap, or pushed out of a full queue.
    pub fn dropped(&self) -> u64 {
        self.inner.lock().unwrap().dropped
    }
}

impl Inner {
    fn push(&mut self, e: Value) {
        if self.ready.len() >= QUEUE {
            self.ready.pop_front();
            self.dropped += 1;
        }
        self.ready.push_back(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_rfc3339_utc() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_400_000);
        assert_eq!(rfc3339(t), "2026-10-30T22:40:00Z");
        assert_eq!(rfc3339(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let leap = SystemTime::UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(rfc3339(leap), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn a_flapping_tether_is_one_event_a_window_ending_as_it_ended() {
        let ev = Events::default();
        let (t0, wall) = (Instant::now(), SystemTime::now());
        let down = |at: u64, state: &str| {
            ev.emit_at(
                "tether.down",
                "lte",
                json!({"tether": "lte", "state": state}),
                t0 + Duration::from_secs(at),
                wall,
            )
        };
        down(0, "first");
        down(2, "second");
        down(4, "third");
        let first = ev.take_at(t0 + Duration::from_secs(5));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0]["detail"]["state"], "first");
        assert!(
            ev.take_at(t0 + Duration::from_secs(9)).is_empty(),
            "still in the window"
        );
        let later = ev.take_at(t0 + Duration::from_secs(11));
        assert_eq!(later.len(), 1);
        assert_eq!(
            (
                later[0]["detail"]["state"].as_str(),
                later[0]["detail"]["repeats"].as_u64()
            ),
            (Some("third"), Some(2))
        );
        // Another subject isn't held back by this one.
        ev.emit_at(
            "tether.down",
            "fibre",
            json!({}),
            t0 + Duration::from_secs(12),
            wall,
        );
        assert_eq!(ev.take_at(t0 + Duration::from_secs(12)).len(), 1);
    }

    #[test]
    fn at_most_sixty_a_minute_and_a_bounded_queue() {
        let ev = Events::default();
        let (t0, wall) = (Instant::now(), SystemTime::now());
        for i in 0..300 {
            ev.emit_at("config.committed", &i.to_string(), json!({}), t0, wall);
        }
        assert_eq!(ev.dropped(), (300 - QUEUE) as u64);
        assert_eq!(ev.take_at(t0).len(), PER_MINUTE);
        assert!(ev.take_at(t0 + Duration::from_secs(30)).is_empty());
        assert_eq!(ev.take_at(t0 + Duration::from_secs(61)).len(), PER_MINUTE);
        // Not a flat object, or too big: still an event, without the detail.
        ev.emit_at("x.y", "a", json!("text"), t0, wall);
        ev.emit_at("x.y", "b", json!({"big": "z".repeat(5000)}), t0, wall);
    }
}
