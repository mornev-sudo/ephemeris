//! The API's logging endpoints (under `/api/v1`, behind login and audit
//! like the rest):
//!
//! | Method | Path                          | What                                         |
//! |--------|-------------------------------|----------------------------------------------|
//! | GET    | /logs?after=&level=&category=&limit= | recent lines from memory, oldest first |
//! | GET    | /logs/audit?limit=N           | the end of audit.log                         |
//! | GET    | /logging                      | categories and their levels, files, filter   |
//! | PUT    | /logging {category, level, for?} | set a level (debug: for a while)          |
//! | PUT    | /logging/host {host}          | trace only packets to/from host (null: all)  |
//! | DELETE | /logging                      | back to the configured levels                |

use super::api::ApiError;
use super::Shared;
use crate::logging::{self, control, sink, Lvl};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

type St = State<Arc<Shared>>;
type ApiResult = Result<Json<Value>, ApiError>;

pub fn routes() -> Router<Arc<Shared>> {
    Router::new()
        .route("/logs", get(recent))
        .route("/logs/audit", get(audit_tail))
        .route("/logging", get(levels).put(set_level).delete(reset))
        .route("/logging/host", put(set_host))
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

#[derive(Deserialize)]
struct RecentQuery {
    #[serde(default)]
    after: u64,
    level: Option<String>,
    category: Option<String>,
    limit: Option<usize>,
}

async fn recent(Query(q): Query<RecentQuery>) -> ApiResult {
    let min = match q.level.as_deref() {
        None => Lvl::Trace,
        Some(l) => Lvl::parse(l).ok_or_else(|| bad(format!("no log level {l:?}")))?,
    };
    if let Some(c) = &q.category {
        if logging::category(c).is_none() {
            return Err(bad(format!("no log category {c:?}")));
        }
    }
    let limit = q.limit.unwrap_or(200).min(sink::RING_LINES);
    let lines: Vec<Value> = sink::logs()
        .map(|l| l.recent(q.after, min, q.category.as_deref(), limit))
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            let mut v = serde_json::to_value(&r).unwrap();
            v["time"] = sink::rfc3339(r.unix_ms).into();
            v
        })
        .collect();
    Ok(Json(json!(lines)))
}

#[derive(Deserialize)]
struct TailQuery {
    limit: Option<usize>,
}

async fn audit_tail(Query(q): Query<TailQuery>) -> ApiResult {
    let n = q.limit.unwrap_or(100).min(10_000);
    let dir = control().config().dir;
    let path = std::path::Path::new(&dir).join("audit.log");
    let lines = tokio::task::spawn_blocking(move || sink::tail(&path, n))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(|e| bad(format!("reading audit.log: {e}")))?;
    Ok(Json(json!(lines)))
}

fn file_size(p: &std::path::Path) -> u64 {
    let mut old = p.as_os_str().to_owned();
    old.push(".1");
    [p.to_path_buf(), old.into()]
        .iter()
        .filter_map(|f| std::fs::metadata(f).ok())
        .map(|m| m.len())
        .sum()
}

async fn levels() -> Json<Value> {
    let c = control();
    let cfg = c.config();
    let dir = std::path::Path::new(&cfg.dir);
    let logs = sink::logs();
    Json(json!({
        "categories": c.states(),
        "levels": Lvl::ALL.map(|l| l.name()),
        "host": c.host().map(|h| h.to_string()),
        "debug_minutes": cfg.debug_minutes,
        "trace_per_sec": cfg.trace_per_sec,
        "files": {
            "dir": cfg.dir,
            "debug": { "bytes": file_size(&dir.join("debug.log")), "limit": cfg.debug_file_mb << 20 },
            "audit": { "bytes": file_size(&dir.join("audit.log")), "limit": cfg.audit_file_mb << 20 },
            "error": logs.and_then(|l| l.file_error.lock().unwrap().clone()),
        },
        "dropped": logs.map_or(0, |l| l.dropped.load(std::sync::atomic::Ordering::Relaxed)),
    }))
}

#[derive(Deserialize)]
struct SetLevel {
    category: String,
    level: String,
    /// "10m", "2h", "forever"; absent: debug for `debug_minutes`, other
    /// levels until reset.
    #[serde(rename = "for")]
    for_: Option<String>,
}

async fn set_level(Json(b): Json<SetLevel>) -> ApiResult {
    let level = Lvl::parse(&b.level).ok_or_else(|| bad(format!("no log level {:?}", b.level)))?;
    let dur = match b.for_.as_deref() {
        None => None,
        Some(s) => Some(
            logging::parse_duration(s)
                .ok_or_else(|| bad(format!("{s:?}: say how long, e.g. 10m, 2h or forever")))?,
        ),
    };
    let until = control()
        .set(&b.category, level, dur)
        .map_err(|e| bad(e.to_string()))?;
    let how_long = match until {
        Some(d) => format!("for {}", logging::fmt_duration(d)),
        None => "until reset".into(),
    };
    tracing::info!(
        target: logging::cat::AUDIT,
        "log category {} set to {} {how_long}",
        b.category,
        level.name()
    );
    Ok(Json(json!({
        "category": b.category,
        "level": level.name(),
        "expires_in_secs": until.map(|d| d.as_secs()),
    })))
}

#[derive(Deserialize)]
struct SetHost {
    host: Option<String>,
}

async fn set_host(Json(b): Json<SetHost>) -> ApiResult {
    let host = match b.host.as_deref().map(str::trim) {
        None | Some("") | Some("off") | Some("all") => None,
        Some(h) => {
            let p = if h.contains('/') {
                h.to_string()
            } else {
                format!("{h}/32")
            };
            Some(
                p.parse::<eph_fib::Prefix>()
                    .map_err(|_| bad(format!("{h:?} isn't an address or prefix")))?,
            )
        }
    };
    control().set_host(host);
    tracing::info!(
        target: logging::cat::AUDIT,
        "packet tracing limited to {}",
        host.map_or("all hosts".into(), |h| h.to_string())
    );
    Ok(Json(json!({ "host": host.map(|h| h.to_string()) })))
}

async fn reset(State(_): St) -> Json<Value> {
    control().reset();
    tracing::info!(target: logging::cat::AUDIT, "log levels reset to the configuration");
    Json(json!({ "ok": true }))
}
