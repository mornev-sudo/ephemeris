//! REST API (`/api/v1/...`, JSON, bearer token) and the web portal (`/`).
//!
//! | Method | Path                      | What                                        |
//! |--------|---------------------------|---------------------------------------------|
//! | POST   | /login {username,password}| web login: sets the session cookie (public) |
//! | POST   | /logout                   | end the web session                         |
//! | GET    | /whoami                   | who is logged in, and how                   |
//! | POST   | /system/password          | change the admin password {current?, new}   |
//! | GET    | /status                   | ports, counters, drops, session totals      |
//! | GET    | /sessions?limit=N         | the newest sessions (at most 1000)          |
//! | GET    | /neighbors                | ARP table                                   |
//! | GET    | /stats/history?secs=N     | sessions, pps, bps, drops every 5 s (≤1 h)  |
//! | GET    | /stats/resources          | CPU, memory, disk, threads, table capacity  |
//! | GET    | /dhcp                     | DHCP: the router's own leases, leases given |
//! | GET    | /wan                      | outside interfaces: static / DHCP / PPPoE   |
//! | GET    | /routes                   | forwarding table                            |
//! | POST   | /routes  {prefix, via}    | add/replace a static route (commits)        |
//! | DELETE | /routes?prefix=P          | remove a static route (commits)             |
//! | GET    | /config                   | running + candidate text, pending confirm   |
//! | PUT    | /config/candidate (TOML)  | validate + stage, returns diff              |
//! | GET    | /config/model             | working config as structured JSON (GUI)     |
//! | PUT    | /config/model             | stage an edited structured config (GUI)     |
//! | DELETE | /config/candidate         | discard staged changes                      |
//! | POST   | /config/commit?confirm=S  | apply candidate (auto-rollback after S s)   |
//! | POST   | /config/confirm           | keep a confirmed commit                     |
//! | POST   | /config/rollback?to=N     | restore history entry N (default 1)         |
//! | GET    | /config/history           | saved versions                              |
//! | POST   | /restart                  | restart ephemerisd (systemd brings it back)   |
//! | GET    | /overlay                  | SD-WAN tethers, health, path decisions      |
//! | GET    | /overlay/sites            | this router and its configured peer sites   |
//! | GET    | /overlay/key?site=S       | the key shared with site S                  |
//! | POST   | /overlay/key {site, key?} | set (or, without key, generate) it; commits |
//! | GET    | /overlay/entry?site=S     | [[site]] entry describing this router, for S|
//! | GET    | /system                   | build, update job state                     |
//! | POST   | /system/update/check      | list installed + available versions         |
//! | POST   | /system/update            | install newest version into inactive slot   |
//! | POST   | /system/reboot            | reboot (into the newest installed version)  |
//!
//! ephemerisd serves plain HTTP on loopback only; nginx in front terminates
//! HTTPS for the network (see image/) and passes the client's address in
//! `X-Real-IP`, trusted only from loopback. Every request goes through
//! [`front`]: a concurrency limit, a Host / Origin check (against DNS
//! rebinding and cross-site requests) and security headers on the response.

use super::configmgr::{Apply, Committed};
use super::Shared;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use eph_dataplane::{Dir, NextHop};
use eph_packet::eth;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

type St = State<Arc<Shared>>;

/// Largest request body (a config is at most 256 KiB, see configmgr).
const MAX_BODY: usize = 512 * 1024;
/// Requests handled at once; more get 503 instead of piling up.
static REQUESTS: Semaphore = Semaphore::const_new(64);
/// Password checks at once (each one is deliberately slow).
static PASSWORD_CHECKS: Semaphore = Semaphore::const_new(2);
/// A handler that takes longer than this is cut off (updates included).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// Longest `?confirm=` for a provisional commit.
const MAX_CONFIRM_SECS: u64 = 3600;

/// Errors become `{"error": "..."}` with a status code.
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        // `{:#}` includes the cause chain: "parsing ...: route X: gateway ..."
        ApiError(StatusCode::BAD_REQUEST, format!("{e:#}"))
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

/// Who sent a request: their address and whether it came over HTTPS, as the
/// nginx in front reports them (believed only from loopback).
#[derive(Clone, Copy, Debug)]
pub struct Client {
    pub ip: IpAddr,
    pub https: bool,
}

pub fn router(shared: Arc<Shared>) -> Router {
    let api = Router::new()
        .route("/status", get(status))
        .route("/sessions", get(sessions))
        .route("/neighbors", get(neighbors))
        .route("/stats/history", get(stats_history))
        .route("/stats/resources", get(stats_resources))
        .route("/dhcp", get(dhcp_status))
        .route("/wan", get(wan_status))
        .route("/routes", get(routes).post(add_route).delete(del_route))
        .route("/config", get(config))
        .route(
            "/config/candidate",
            put(put_candidate).delete(clear_candidate),
        )
        .route("/config/model", get(get_model).put(put_model))
        .route("/config/commit", post(commit))
        .route("/config/confirm", post(confirm))
        .route("/config/rollback", post(rollback))
        .route("/config/history", get(history))
        .route("/restart", post(restart))
        .route("/overlay", get(overlay))
        .route("/overlay/sites", get(overlay_sites))
        .route("/overlay/key", get(site_key).post(set_site_key))
        .route("/overlay/entry", get(site_entry))
        .route("/system", get(system))
        .route("/system/update/check", post(update_check))
        .route("/system/update", post(update_start))
        .route("/system/reboot", post(reboot))
        .route("/system/password", post(change_password))
        .route("/whoami", get(whoami))
        .route("/logout", post(logout))
        // Everything above needs a login (checked first), and every change
        // is written to the audit log; the routes below don't.
        .route_layer(middleware::from_fn(audit))
        .route_layer(middleware::from_fn_with_state(shared.clone(), auth))
        .route("/login", post(login));
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .nest("/api/v1", api)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(shared.clone(), front))
        .with_state(shared)
}

pub async fn serve(shared: Arc<Shared>, listen: SocketAddr) -> anyhow::Result<()> {
    let stop = shared.stop;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("management API on http://{listen}/");
    axum::serve(
        listener,
        router(shared).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?;
    Ok(())
}

/// The portal never needs to be framed, or to load anything from elsewhere;
/// its script is a file of its own so no inline script is allowed at all.
const PORTAL_CSP: &str =
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
     connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; \
     base-uri 'none'";

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_SECURITY_POLICY, PORTAL_CSP)],
        Html(include_str!("web/index.html")),
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("web/app.js"),
    )
}

/// Runs for every request: limits, where it came from, Host and Origin
/// checks, and security headers on the way out.
async fn front(State(s): St, mut req: Request, next: Next) -> Response {
    let Ok(_permit) = REQUESTS.try_acquire() else {
        return ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy, try again".into()).into_response();
    };
    let client = client_of(&req);
    let hostnames = s
        .config
        .lock()
        .unwrap()
        .running()
        .management
        .hostnames
        .clone();
    if !host_allowed(req.headers(), &hostnames) {
        tracing::warn!("refused a request for an unknown Host from {}", client.ip);
        return ApiError(
            StatusCode::MISDIRECTED_REQUEST,
            "unknown host name: use the router's address, or add the name to \
             management.hostnames"
                .into(),
        )
        .into_response();
    }
    if !origin_allowed(req.method(), req.headers()) {
        return ApiError(StatusCode::FORBIDDEN, "cross-origin request refused".into())
            .into_response();
    }
    req.extensions_mut().insert(client);
    let mut resp = match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(r) => r,
        Err(_) => {
            ApiError(StatusCode::GATEWAY_TIMEOUT, "request took too long".into()).into_response()
        }
    };
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if client.https {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    resp
}

fn client_of(req: &Request) -> Client {
    // No connection info: a request from inside this process (tests).
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |c| c.0.ip());
    if !peer.is_loopback() {
        return Client {
            ip: peer,
            https: false,
        };
    }
    let h = req.headers();
    let real = h
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok());
    Client {
        ip: real.unwrap_or(peer),
        https: h
            .get("x-forwarded-proto")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"https")),
    }
}

/// The host part of a Host header or an origin's authority: no port, IPv6
/// brackets removed.
fn host_part(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    match authority.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    }
}

/// DNS rebinding defence: a browser sends the name it thinks it's talking
/// to. Addresses, localhost, this router's own host name and the configured
/// names are fine; any other name is someone else's domain pointing here.
fn host_allowed(headers: &HeaderMap, extra: &[String]) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return true; // not a browser (HTTP/1.0 tools, tests)
    };
    let host = host_part(host.trim());
    if host.parse::<IpAddr>().is_ok() || host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let own = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let own = own.trim();
    let local = format!("{own}.local");
    (!own.is_empty() && (host.eq_ignore_ascii_case(own) || host.eq_ignore_ascii_case(&local)))
        || extra.iter().any(|n| host.eq_ignore_ascii_case(n))
}

/// A browser marks where a state-changing request comes from: it has to be
/// the portal itself (same host as the request is addressed to).
fn origin_allowed(method: &Method, headers: &HeaderMap) -> bool {
    if matches!(*method, Method::GET | Method::HEAD) {
        return true;
    }
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // not a browser (ephctl, curl)
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let authority = origin.split_once("://").map_or("", |(_, a)| a);
    !authority.is_empty() && authority.eq_ignore_ascii_case(host.trim())
}

/// Two ways in: `Authorization: Bearer <API token>` (ephctl, scripts) or the
/// web session cookie (the portal). Cookie-authenticated requests that
/// change something must also carry an `X-Ephemeris` header: a page on another
/// site can make the browser send our cookie, but can't add custom headers
/// without our permission (CORS), so this stops cross-site request forgery.
/// How a request was authenticated. Only the API token (readable by root
/// alone, on the router) may reset the password without knowing the old one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AuthVia {
    Token,
    Session,
}

impl AuthVia {
    fn name(self) -> &'static str {
        match self {
            AuthVia::Token => "api-token",
            AuthVia::Session => "session",
        }
    }
}

async fn auth(State(s): St, mut req: Request, next: Next) -> Response {
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if let Some(t) = bearer {
        // An empty configured token must never match an empty header.
        if !s.token.is_empty() && crate::mgmt::constant_time_eq(t.as_bytes(), s.token.as_bytes()) {
            req.extensions_mut().insert(AuthVia::Token);
            return next.run(req).await;
        }
    } else if let Some(sess) = session_cookie(&req) {
        if s.auth.session_valid(&sess) {
            let safe = matches!(*req.method(), Method::GET | Method::HEAD);
            if safe || req.headers().contains_key("x-ephemeris") {
                req.extensions_mut().insert(AuthVia::Session);
                return next.run(req).await;
            }
            return ApiError(StatusCode::FORBIDDEN, "missing X-Ephemeris header".into())
                .into_response();
        }
    }
    ApiError(StatusCode::UNAUTHORIZED, "not logged in".into()).into_response()
}

/// Every change made through the API, with who made it and from where.
async fn audit(req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD) {
        return next.run(req).await;
    }
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    let via = req.extensions().get::<AuthVia>().map_or("?", |v| v.name());
    let ip = req
        .extensions()
        .get::<Client>()
        .map_or("?".to_string(), |c| c.ip.to_string());
    let resp = next.run(req).await;
    tracing::info!(
        target: "audit",
        "admin {method} {path} via {via} from {ip}: {}",
        resp.status().as_u16()
    );
    resp
}

fn session_cookie(req: &Request) -> Option<String> {
    req.headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == super::auth::SESSION_COOKIE)
        .map(|(_, v)| v.to_string())
}

/// The session cookie: HttpOnly, same-site only, and Secure over HTTPS.
fn set_session_cookie(token: &str, max_age: u64, https: bool) -> String {
    format!(
        "{}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{}",
        super::auth::SESSION_COOKIE,
        if https { "; Secure" } else { "" }
    )
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn login(
    State(s): St,
    Extension(client): Extension<Client>,
    Json(r): Json<LoginReq>,
) -> Response {
    if let Err(wait) = s.auth.throttle.check(client.ip) {
        tracing::warn!(
            "web login from {} refused: too many wrong passwords",
            client.ip
        );
        let secs = wait.as_secs().max(1);
        return (
            [(header::RETRY_AFTER, secs.to_string())],
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                format!("too many wrong passwords: try again in {secs} s"),
            ),
        )
            .into_response();
    }
    let ok = r.username == "admin" && {
        let _permit = PASSWORD_CHECKS.acquire().await;
        let s = s.clone();
        let pw = r.password.clone();
        tokio::task::spawn_blocking(move || s.auth.check_password(&pw))
            .await
            .unwrap_or(false)
    };
    if !ok {
        let locked = s.auth.throttle.failed(client.ip);
        // Slow down password guessing.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let user: String = r.username.chars().take(64).collect();
        tracing::warn!(
            "failed web login for {user:?} from {}{}",
            client.ip,
            if locked {
                ": address locked out for 15 minutes"
            } else {
                ""
            }
        );
        return ApiError(
            StatusCode::UNAUTHORIZED,
            "wrong username or password".into(),
        )
        .into_response();
    }
    s.auth.throttle.succeeded(client.ip);
    let Ok(token) = s.auth.new_session() else {
        return ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not create a session".into(),
        )
        .into_response();
    };
    tracing::info!(target: "audit", "web login: admin from {}", client.ip);
    let cookie = set_session_cookie(
        &token,
        super::auth::SESSION_LIFETIME.as_secs(),
        client.https,
    );
    (
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "ok": true, "user": "admin" })),
    )
        .into_response()
}

async fn logout(State(s): St, Extension(client): Extension<Client>, req: Request) -> Response {
    if let Some(t) = session_cookie(&req) {
        s.auth.end_session(&t);
    }
    let clear = set_session_cookie("", 0, client.https);
    ([(header::SET_COOKIE, clear)], Json(json!({ "ok": true }))).into_response()
}

async fn whoami(Extension(via): Extension<AuthVia>) -> Json<Value> {
    Json(json!({ "user": "admin", "via": via.name() }))
}

#[derive(Deserialize)]
struct PasswordReq {
    /// Leave out to reset: only allowed with the API token (`ephctl` as root).
    #[serde(default)]
    current: Option<String>,
    new: String,
}

async fn change_password(
    State(s): St,
    Extension(via): Extension<AuthVia>,
    Extension(client): Extension<Client>,
    Json(r): Json<PasswordReq>,
) -> Result<Response, ApiError> {
    let st = s.clone();
    let reset = r.current.is_none();
    let result = tokio::task::spawn_blocking(move || {
        match &r.current {
            Some(cur) if !st.auth.check_password(cur) => {
                anyhow::bail!("the current password is wrong")
            }
            None if via != AuthVia::Token => {
                anyhow::bail!("give the current password (only root on the router can reset it)")
            }
            _ => {}
        }
        st.auth.set_password(&r.new)
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    result?;
    // Logged either way, so an unexpected password change can be traced.
    if reset {
        tracing::warn!(target: "audit", "admin password reset with the API token (root on the router)");
    } else {
        tracing::info!(target: "audit", "admin password changed from {}", client.ip);
    }
    // Every session ended with the old password; whoever changed it from
    // the portal gets a fresh one, so they stay logged in.
    let body = Json(json!({ "ok": true }));
    if via == AuthVia::Session {
        if let Ok(token) = s.auth.new_session() {
            let cookie = set_session_cookie(
                &token,
                super::auth::SESSION_LIFETIME.as_secs(),
                client.https,
            );
            return Ok(([(header::SET_COOKIE, cookie)], body).into_response());
        }
    }
    Ok(body.into_response())
}

// ------------------------------------------------------------------ reads

async fn status(State(s): St) -> Json<Value> {
    let sum = s.summary();
    let ports = s.ports.read().unwrap().clone();
    let ports: Vec<Value> = ports
        .iter()
        .zip(&s.runtime)
        .map(|(p, rt)| {
            json!({
                "id": p.id, "name": p.name, "device": rt.device, "vlan": p.vlan,
                "mac": eth::fmt_mac(&p.mac),
                "address": format!("{}/{}", p.addr, p.subnet.len()),
                "allow_new_sessions": p.allow_new_sessions,
                "mss_adjust": p.mss_adjust,
                "role": if p.role == eph_dataplane::Role::Outside { "outside" } else { "inside" },
                "xdp_mode": rt.xdp_mode, "zero_copy": rt.zero_copy,
            })
        })
        .collect();
    let cfg = s.config.lock().unwrap();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build": s.build,
        "uptime_secs": s.started.elapsed().as_secs(),
        "workers": s.workers,
        "ports": ports,
        "counters": {
            "rx": sum.rx, "forwarded": sum.forwarded, "originated": sum.originated,
            "kernel_drops": sum.kernel_drops, "fill_empty": sum.fill_empty,
            "tcp_blind": sum.tcp_blind, "arp_conflicts": sum.arp_conflicts,
        },
        "drops": sum.drops,
        "sessions": {
            "active": sum.sessions_active, "created": sum.sessions_created,
            "expired": sum.sessions_expired,
        },
        "routes": s.fib.read().unwrap().routes().len(),
        // The four headline numbers, over the last sampling interval.
        "rates": s.history.lock().unwrap().latest().map(|r| json!({
            "sessions": r.sessions, "rx_pps": r.rx_pps, "tx_pps": r.tx_pps,
            "rx_bps": r.rx_bps, "tx_bps": r.tx_bps, "drops_per_sec": r.drops_per_sec,
        })),
        "drops_total": super::history::drops_total(&sum),
        "neighbors": sum.neighbor_count,
        "pending_confirm_secs": cfg.pending_confirm_secs(),
        "candidate_staged": cfg.candidate_text().is_some(),
        "dataplane_error": s.startup.dataplane_error,
        "fallback": s.startup.fallback,
    }))
}

#[derive(Deserialize)]
struct Limit {
    limit: Option<usize>,
}

async fn sessions(State(s): St, Query(q): Query<Limit>) -> Json<Value> {
    // The newest sessions (each worker gathers its newest 1000 while
    // someone looks; together, the newest 1000 of those).
    let mut list = s.detail().await.sessions;
    list.sort_by_key(|v| std::cmp::Reverse(v.session.created_ns));
    let limit = q
        .limit
        .unwrap_or(crate::report::SESSION_DETAIL)
        .min(crate::report::SESSION_DETAIL);
    let (f, r) = (Dir::Forward as usize, Dir::Reverse as usize);
    let out: Vec<Value> = list
        .iter()
        .take(limit)
        .map(|v| {
            let ((ia, ip), (ra, rp)) = v.session.endpoints();
            json!({
                "proto": v.proto_name(),
                "initiator": format!("{ia}:{ip}"),
                "responder": format!("{ra}:{rp}"),
                "state": v.session.state.name(),
                "nat": v.session.nat.map(|n| format!("{}:{}", n.addr, n.port)),
                "packets": [v.session.packets[f], v.session.packets[r]],
                "bytes": [v.session.bytes[f], v.session.bytes[r]],
                "age_secs": v.age_secs(),
                "idle_secs": v.idle_secs(),
            })
        })
        .collect();
    Json(Value::Array(out))
}

#[derive(Deserialize)]
struct HistoryQuery {
    /// How far back, in seconds (default 15 minutes, at most an hour).
    secs: Option<u64>,
}

/// The Reporting graphs' data: one sample every 5 seconds.
async fn stats_history(State(s): St, Query(q): Query<HistoryQuery>) -> Json<Value> {
    let secs = q.secs.unwrap_or(900).min(3600);
    let names: Vec<String> = s
        .ports
        .read()
        .unwrap()
        .iter()
        .map(|p| p.name.clone())
        .collect();
    Json(json!({
        "interval_secs": super::history::INTERVAL_SECS,
        "interfaces": names,
        "samples": s.history.lock().unwrap().since(secs),
    }))
}

/// The router's resources and how full its tables are.
async fn stats_resources(State(s): St) -> Json<Value> {
    let sum = s.summary();
    let sys = s.system.lock().unwrap().clone().unwrap_or_default();
    let busy = s
        .history
        .lock()
        .unwrap()
        .latest()
        .map(|x| x.workers_busy_pct.clone())
        .unwrap_or_default();
    let fib = s.fib.read().unwrap().clone();
    let drop = |name: &str| sum.drops.get(name).copied().unwrap_or(0);

    let workers: Vec<Value> = sum
        .workers
        .iter()
        .enumerate()
        .map(|(i, w)| {
            json!({
                "id": i, "busy_pct": busy.get(i).copied().unwrap_or(0.0),
                "sessions": w.sessions, "sessions_max": w.sessions_max,
                "neighbors": w.neighbors, "neighbors_max": eph_dataplane::NEIGHBOR_MAX,
                "nat": w.nat,
            })
        })
        .collect();

    // Capacity: each limit the router has, and how close it is.
    let mut capacity = vec![];
    let mut cap = |name: &str, used: u64, max: Option<u64>, note: String| {
        capacity.push(json!({ "name": name, "used": used, "max": max, "note": note }));
    };
    let sessions: u64 = sum.workers.iter().map(|w| w.sessions).sum();
    let sessions_max: u64 = sum.workers.iter().map(|w| w.sessions_max).sum();
    cap(
        "Sessions",
        sessions,
        (sessions_max > 0).then_some(sessions_max),
        format!(
            "{} refused because a table was full (raise sessions.max_per_worker)",
            drop("session-table-full")
        ),
    );
    let busiest_neigh = sum.workers.iter().map(|w| w.neighbors).max().unwrap_or(0);
    cap(
        "Neighbours (ARP), busiest worker",
        busiest_neigh,
        Some(eph_dataplane::NEIGHBOR_MAX as u64),
        "hosts the router knows the MAC address of".into(),
    );
    cap(
        "NAT translations",
        sum.workers.iter().map(|w| w.nat).sum(),
        None,
        format!(
            "~64,000 ports per outside address and destination; {} sessions found no free port",
            drop("nat-exhausted")
        ),
    );
    cap(
        "Routes",
        fib.routes().len() as u64,
        None,
        "routes up to /24 have no practical limit".into(),
    );
    cap(
        "Next hops (forwarding table)",
        fib.next_hops() as u64,
        Some(eph_fib::MAX_NEXT_HOPS as u64),
        "distinct gateways, interfaces and SD-WAN sites routes point to".into(),
    );
    cap(
        "/24s holding longer routes",
        fib.tbl8_groups() as u64,
        Some(eph_fib::MAX_TBL8_GROUPS as u64),
        "each /24 with a /25-/32 route inside it takes one".into(),
    );
    // DHCP pools: leased (or offered) out of the range's size.
    let cfg = s.config.lock().unwrap().running().clone();
    let st = s.dhcp.lock().unwrap().clone();
    for i in &cfg.interfaces {
        let Some(d) = &i.dhcp else { continue };
        let size = d
            .range
            .split_once('-')
            .and_then(|(a, b)| {
                let a: std::net::Ipv4Addr = a.trim().parse().ok()?;
                let b: std::net::Ipv4Addr = b.trim().parse().ok()?;
                Some((u32::from(b) - u32::from(a)) as u64 + 1)
            })
            .unwrap_or(0);
        let leased = st.leases.get(&i.name).map_or(0, |l| {
            l.iter()
                .filter(|x| x.state != crate::dhcp::server::LeaseState::Declined)
                .count() as u64
        });
        cap(
            &format!("DHCP pool on {}", i.name),
            leased,
            Some(size),
            d.range.clone(),
        );
    }
    let health = s.health.read().unwrap().clone();
    if !s.overlay.tethers.is_empty() {
        cap(
            "SD-WAN tethers up",
            health.iter().filter(|h| h.up).count() as u64,
            Some(s.overlay.tethers.len() as u64),
            "of the configured tethers".into(),
        );
    }

    let session_bytes = sessions_max * std::mem::size_of::<eph_dataplane::Session>() as u64;
    Json(json!({
        "system": {
            "cpu_pct": sys.cpu_pct, "cpu_each_pct": sys.cpu_each_pct,
            "memory": sys.memory, "load": sys.load, "uptime_secs": sys.uptime_secs,
            "disks": sys.disks,
        },
        "process": {
            "rss": sys.process_rss, "cpu_pct": sys.process_cpu_pct, "threads": sys.threads,
            // The big, fixed parts of ephemerisd's memory.
            "memory": {
                "packet_buffers": s.umem_bytes,
                "session_tables": session_bytes,
                "forwarding_table": fib.memory_bytes(),
            },
        },
        "workers": workers,
        "capacity": capacity,
    }))
}

async fn neighbors(State(s): St) -> Json<Value> {
    let ports = s.ports.read().unwrap().clone();
    let out: Vec<Value> = s
        .detail()
        .await
        .neighbors
        .iter()
        .filter(|n| (n.port as usize) < ports.len())
        .map(|n| {
            json!({
                "ip": n.ip.to_string(), "mac": eth::fmt_mac(&n.mac),
                "port": ports[n.port as usize].name,
            })
        })
        .collect();
    Json(Value::Array(out))
}

/// Every outside interface: how it gets its address and how that's going.
async fn wan_status(State(s): St) -> Json<Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cfg = s.config.lock().unwrap().running().clone();
    let st = s.dhcp.lock().unwrap().clone();
    let ports = s.ports.read().unwrap().clone();
    let out: Vec<Value> = cfg
        .interfaces
        .iter()
        .zip(ports.iter())
        .filter(|(i, _)| i.role == crate::config::RoleCfg::Outside)
        .map(|(i, p)| {
            let addr = (!p.addr.is_unspecified()).then(|| format!("{}/{}", p.addr, p.subnet.len()));
            let gw = p.gateway.map(|g| g.to_string());
            if i.is_pppoe() {
                let ps = st.pppoe.get(&i.name);
                let l = ps.and_then(|x| x.link.as_ref());
                json!({
                    "interface": i.name, "mode": "pppoe", "apply_error": st.apply_error,
                    "state": ps.map(|x| x.phase), "address": addr, "gateway": gw,
                    "dns": l.map(|l| l.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>()),
                    "pppoe": {
                        "username": i.pppoe.as_ref().map(|c| c.username.clone()),
                        "concentrator": l.map(|l| l.ac_name.clone()),
                        "session": l.map(|l| l.session),
                        "mtu": l.map(|l| l.mtu),
                        "up_for_secs": l.map(|l| now.saturating_sub(l.up_since_unix)),
                        "last_error": ps.and_then(|x| x.last_error.clone()),
                    },
                })
            } else if i.is_dhcp_client() {
                let c = st.clients.get(&i.name);
                let l = c.and_then(|c| c.lease.as_ref());
                json!({
                    "interface": i.name, "mode": "dhcp", "apply_error": st.apply_error,
                    "state": c.map(|c| c.phase), "address": addr, "gateway": gw,
                    "dns": l.map(|l| l.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>()),
                    "dhcp": {
                        "server": l.map(|l| l.server.to_string()),
                        "expires_in_secs": l.map(|l| l.expires_unix().saturating_sub(now)),
                    },
                })
            } else {
                json!({
                    "interface": i.name, "mode": "static", "state": "up",
                    "address": addr, "gateway": gw, "dns": null,
                })
            }
        })
        .collect();
    Json(Value::Array(out))
}

/// DHCP: what each DHCP-client interface holds, and what each served LAN
/// has handed out. Times are seconds from now.
async fn dhcp_status(State(s): St) -> Json<Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut st = s.dhcp.lock().unwrap().clone();
    // Interfaces the configuration puts on DHCP, even before the service
    // has anything to report (or when the data plane isn't running).
    let cfg = s.config.lock().unwrap().running().clone();
    for i in &cfg.interfaces {
        if i.is_dhcp_client() {
            st.clients
                .entry(i.name.clone())
                .or_insert(crate::dhcp::ClientStatus {
                    phase: crate::dhcp::client::Phase::Init,
                    lease: None,
                });
        } else if i.dhcp.is_some() {
            st.leases.entry(i.name.clone()).or_default();
        }
    }
    let mut clients: Vec<Value> = st
        .clients
        .iter()
        .map(|(name, c)| {
            let l = c.lease.as_ref();
            json!({
                "interface": name,
                "state": c.phase,
                "address": l.map(|l| format!("{}/{}", l.addr, l.prefix_len)),
                "gateway": l.and_then(|l| l.router).map(|r| r.to_string()),
                "dns": l.map(|l| l.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>()),
                "server": l.map(|l| l.server.to_string()),
                "expires_in_secs": l.map(|l| l.expires_unix().saturating_sub(now)),
            })
        })
        .collect();
    clients.sort_by(|a, b| a["interface"].as_str().cmp(&b["interface"].as_str()));
    let mut servers: Vec<Value> = st
        .leases
        .iter()
        .map(|(name, leases)| {
            let mut ls: Vec<Value> = leases
                .iter()
                .map(|l| {
                    json!({
                        "mac": eth::fmt_mac(&l.mac), "ip": l.ip.to_string(),
                        "hostname": l.hostname, "state": l.state,
                        "expires_in_secs": l.expires_unix.saturating_sub(now),
                    })
                })
                .collect();
            ls.sort_by_key(|l| {
                l["ip"]
                    .as_str()
                    .unwrap_or("")
                    .parse::<std::net::Ipv4Addr>()
                    .map(u32::from)
                    .unwrap_or(0)
            });
            json!({ "interface": name, "leases": ls })
        })
        .collect();
    servers.sort_by(|a, b| a["interface"].as_str().cmp(&b["interface"].as_str()));
    Json(json!({ "clients": clients, "servers": servers }))
}

async fn routes(State(s): St) -> Json<Value> {
    let ports = s.ports.read().unwrap().clone();
    let fib = s.fib.read().unwrap().clone();
    let out: Vec<Value> = fib
        .routes()
        .iter()
        .map(|(prefix, nh)| match *nh {
            NextHop::Ip { port, gateway } => json!({
                "prefix": prefix.to_string(),
                "via": gateway.map(|g| g.to_string()),
                "port": ports[port as usize].name,
                "kind": if gateway.is_some() { "static" } else { "connected" },
            }),
            NextHop::Site(i) => json!({
                "prefix": prefix.to_string(),
                "via": format!("site {}", s.overlay.sites[i]),
                "port": "overlay",
                "kind": "overlay",
            }),
        })
        .collect();
    Json(Value::Array(out))
}

async fn overlay(State(s): St) -> Json<Value> {
    let o = &s.overlay;
    let sum = s.summary();
    let health = s.health.read().unwrap().clone();
    let paths = s.paths.read().unwrap().clone();
    let ports = s.ports.read().unwrap().clone();
    let tethers: Vec<Value> = o
        .tethers
        .iter()
        .map(|t| {
            let h = health.get(t.id as usize).copied().unwrap_or_default();
            let st = sum.tethers.get(t.id as usize).copied().unwrap_or_default();
            json!({
                "name": t.name, "interface": ports[t.port as usize].name,
                // A peer without a fixed address: where it was last heard
                // from, if it has been.
                "remote": if t.remote.is_unspecified() {
                    s.endpoints.get(t.id).map(|(ip, port)| format!("{ip}:{port} (learned)"))
                        .unwrap_or_else(|| "waiting to hear from it".into())
                } else {
                    t.remote.to_string()
                },
                "site": t.peer_site,
                "encrypted": t.key.is_some(),
                "up": h.up,
                "rtt_ms": h.rtt_ns as f64 / 1e6, "jitter_ms": h.jitter_ns as f64 / 1e6,
                "loss_pct": h.loss_pct,
                "tx_packets": st.tx_packets, "rx_packets": st.rx_packets,
                "tx_bytes": st.tx_bytes, "rx_bytes": st.rx_bytes,
                "probes_sent": st.probes_sent, "probe_replies": st.replies,
            })
        })
        .collect();
    let mut choices = Vec::new();
    for (site_idx, site) in o.sites.iter().enumerate() {
        for (class_idx, class) in o.classes.iter().enumerate() {
            let t = paths.get(site_idx, class_idx as u8);
            choices.push(json!({
                "site": site, "class": class.name,
                "tether": t.map(|t| o.tethers[t as usize].name.clone()),
            }));
        }
    }
    Json(json!({
        "enabled": o.enabled(),
        "site_id": o.site_id,
        "mtu": o.mtu,
        "path_generation": paths.gen,
        "tethers": tethers,
        "paths": choices,
    }))
}

/// This router as other sites should know it: its name, id and role, its
/// fixed WAN addresses (DHCP ones are left out: peers learn those) and the
/// networks behind it.
fn this_site(s: &Shared, cfg: &crate::config::Config) -> Option<crate::config::SiteCfg> {
    let o = cfg.overlay.as_ref()?;
    let ports = s.ports.read().unwrap().clone();
    let mut addresses = vec![];
    let mut prefixes = vec![];
    for (i, p) in cfg.interfaces.iter().zip(ports.iter()) {
        match i.role {
            crate::config::RoleCfg::Outside if !i.is_dhcp_client() => {
                addresses.push(p.addr.to_string())
            }
            crate::config::RoleCfg::Inside => prefixes.push(p.subnet.to_string()),
            _ => {}
        }
    }
    let name = o.name.clone().unwrap_or_else(|| {
        std::fs::read_to_string("/etc/hostname")
            .map(|h| h.trim().to_string())
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| format!("site{}", o.site_id))
    });
    Some(crate::config::SiteCfg {
        name,
        id: o.site_id,
        role: o.role,
        addresses,
        prefixes,
        key: None,
    })
}

/// The configured sites, with whether this router connects to each.
async fn overlay_sites(State(s): St) -> ApiResult {
    let cfg = s.config.lock().unwrap().running().clone();
    let tethers = cfg.site_tethers()?;
    let me = this_site(&s, &cfg);
    let role = cfg.overlay.as_ref().map(|o| o.role).unwrap_or_default();
    let sites: Vec<Value> = cfg
        .sites
        .iter()
        .map(|x| {
            json!({
                "name": x.name, "id": x.id, "role": x.role,
                "addresses": x.addresses, "prefixes": x.prefixes,
                "has_key": x.key.is_some(),
                "connected": role.peers_with(x.role),
                "tethers": tethers.iter().filter(|t| t.site == x.id).map(|t| t.name.clone()).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Json(json!({ "this": me, "sites": sites })))
}

#[derive(Deserialize)]
struct SiteQuery {
    site: String,
}

async fn site_key(State(s): St, Query(q): Query<SiteQuery>) -> ApiResult {
    let cfg = s.config.lock().unwrap();
    let site = cfg
        .running()
        .sites
        .iter()
        .find(|x| x.name == q.site)
        .ok_or_else(|| anyhow::anyhow!("no site named {:?}", q.site))?;
    Ok(Json(json!({ "site": site.name, "key": site.key })))
}

#[derive(Deserialize)]
struct SetKeyReq {
    site: String,
    /// 64 hex characters; omitted: generate a new random key.
    #[serde(default)]
    key: Option<String>,
}

/// Set or generate the key shared with a site, and commit. The other
/// router needs the same key (see /overlay/entry).
async fn set_site_key(State(s): St, Json(r): Json<SetKeyReq>) -> ApiResult {
    let key = match r.key {
        Some(k) => k.trim().to_ascii_lowercase(),
        None => super::auth::random_hex(32)?,
    };
    let c = {
        let mut cfg = s.config.lock().unwrap();
        if cfg.candidate_text().is_some() {
            return Err(
                anyhow::anyhow!("there are staged changes: commit or discard them first").into(),
            );
        }
        let mut model = cfg.running().clone();
        let site = model
            .sites
            .iter_mut()
            .find(|x| x.name == r.site)
            .ok_or_else(|| anyhow::anyhow!("no site named {:?}", r.site))?;
        site.key = Some(key.clone());
        let text = cfg.text_from_model(&model)?;
        cfg.set_candidate(text)?;
        cfg.commit(None)?
    };
    let mut out = finish_commit(&s, c, None)?;
    out.0["key"] = json!(key);
    Ok(out)
}

/// A `[[site]]` entry describing this router, with the key shared with
/// `site`: paste it into that router's configuration.
async fn site_entry(State(s): St, Query(q): Query<SiteQuery>) -> ApiResult {
    let cfg = s.config.lock().unwrap().running().clone();
    let peer = cfg
        .sites
        .iter()
        .find(|x| x.name == q.site)
        .ok_or_else(|| anyhow::anyhow!("no site named {:?}", q.site))?;
    let mut me = this_site(&s, &cfg)
        .ok_or_else(|| anyhow::anyhow!("SD-WAN isn't configured ([overlay])"))?;
    me.key = peer.key.clone();
    #[derive(serde::Serialize)]
    struct Entry {
        site: Vec<crate::config::SiteCfg>,
    }
    let text = toml::to_string(&Entry {
        site: vec![me.clone()],
    })
    .map_err(anyhow::Error::from)?;
    Ok(Json(
        json!({ "toml": text, "entry": me, "dynamic": me.addresses.is_empty() }),
    ))
}

async fn config(State(s): St) -> Json<Value> {
    let cfg = s.config.lock().unwrap();
    Json(json!({
        "running": cfg.running_text(),
        "candidate": cfg.candidate_text(),
        "pending_confirm_secs": cfg.pending_confirm_secs(),
    }))
}

async fn history(State(s): St) -> ApiResult {
    let h = s.config.lock().unwrap().history()?;
    Ok(Json(serde_json::to_value(h).unwrap()))
}

// ----------------------------------------------------------------- writes

/// The configuration the GUI edits: the candidate (if staged) or running
/// one, as structured data, plus what the forms need to offer choices.
async fn get_model(State(s): St) -> ApiResult {
    let cfg = s.config.lock().unwrap();
    let (_, working) = cfg.working();
    let devices = super::nics::list();
    Ok(Json(json!({
        "config": serde_json::to_value(working).map_err(anyhow::Error::from)?,
        "candidate_staged": cfg.candidate_text().is_some(),
        "pending_confirm_secs": cfg.pending_confirm_secs(),
        "devices": devices,
    })))
}

/// Stage an edited structured configuration: it's turned into config-file
/// text and goes through exactly the same validation and diff as a text edit.
async fn put_model(State(s): St, Json(model): Json<crate::config::Config>) -> ApiResult {
    let mut cfg = s.config.lock().unwrap();
    let text = cfg.text_from_model(&model)?;
    let preview = cfg.set_candidate(text)?;
    Ok(Json(serde_json::to_value(preview).unwrap()))
}

async fn put_candidate(State(s): St, body: String) -> ApiResult {
    let preview = s.config.lock().unwrap().set_candidate(body)?;
    Ok(Json(serde_json::to_value(preview).unwrap()))
}

async fn clear_candidate(State(s): St) -> Json<Value> {
    s.config.lock().unwrap().clear_candidate();
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct CommitQuery {
    /// Roll back automatically after this many seconds unless confirmed.
    confirm: Option<u64>,
}

async fn commit(State(s): St, Query(q): Query<CommitQuery>) -> ApiResult {
    if q.confirm
        .is_some_and(|c| !(1..=MAX_CONFIRM_SECS).contains(&c))
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("confirm must be between 1 and {MAX_CONFIRM_SECS} seconds"),
        ));
    }
    let c = s.config.lock().unwrap().commit(q.confirm)?;
    finish_commit(&s, c, q.confirm)
}

/// Push a committed change into the data plane and describe the outcome.
fn finish_commit(s: &Arc<Shared>, mut c: Committed, confirm: Option<u64>) -> ApiResult {
    if c.apply == Apply::Live {
        if s.startup.dataplane_error.is_some() {
            // No data plane to update: it takes effect when it starts.
            c.apply = Apply::RestartRequired;
        } else {
            s.apply_live(&c.config)?;
            remember_good(s);
        }
    }
    if let (Some(id), Some(secs)) = (c.confirm_id, confirm) {
        let s = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(secs)).await;
            let expired = s.config.lock().unwrap().expire_pending(id);
            match expired {
                Some(Ok(back)) => {
                    tracing::warn!("commit {id} not confirmed within {secs}s: rolled back");
                    if back.apply == Apply::Live {
                        match s.apply_live(&back.config) {
                            Ok(()) => remember_good(&s),
                            Err(e) => tracing::error!("applying rollback: {e:#}"),
                        }
                    }
                }
                Some(Err(e)) => tracing::error!("automatic rollback failed: {e:#}"),
                None => {}
            }
        });
    }
    tracing::info!("config committed ({:?})", c.apply);
    Ok(Json(json!({
        "applied": c.apply,
        "diff": c.diff,
        "confirm_within_secs": c.confirm_id.and(confirm),
    })))
}

/// The running data plane now uses the committed config: if it ever has to
/// fall back at startup, this is the version to go back to.
fn remember_good(s: &Shared) {
    let cfg = s.config.lock().unwrap();
    if let Err(e) = crate::startup::mark_good(cfg.path(), cfg.running_text()) {
        tracing::warn!("could not save the last good config: {e:#}");
    }
}

async fn confirm(State(s): St) -> ApiResult {
    s.config.lock().unwrap().confirm()?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct RollbackQuery {
    to: Option<usize>,
}

async fn rollback(State(s): St, Query(q): Query<RollbackQuery>) -> ApiResult {
    let c = s.config.lock().unwrap().rollback(q.to.unwrap_or(1))?;
    finish_commit(&s, c, None)
}

#[derive(Deserialize)]
struct RouteReq {
    prefix: String,
    via: String,
}

/// Convenience: edit the running config, then validate + commit it, all in
/// one step. Discards any other staged candidate.
async fn add_route(State(s): St, Json(r): Json<RouteReq>) -> ApiResult {
    let c = {
        let mut cfg = s.config.lock().unwrap();
        let prefix = r
            .prefix
            .parse::<eph_fib::Prefix>()
            .map_err(anyhow::Error::msg)?;
        let text = cfg.with_route(&prefix.to_string(), &r.via)?;
        cfg.set_candidate(text)?;
        cfg.commit(None)?
    };
    finish_commit(&s, c, None)
}

#[derive(Deserialize)]
struct PrefixQuery {
    prefix: String,
}

async fn del_route(State(s): St, Query(q): Query<PrefixQuery>) -> ApiResult {
    let c = {
        let mut cfg = s.config.lock().unwrap();
        let prefix = q
            .prefix
            .parse::<eph_fib::Prefix>()
            .map_err(anyhow::Error::msg)?;
        let text = cfg.without_route(&prefix.to_string())?;
        cfg.set_candidate(text)?;
        cfg.commit(None)?
    };
    finish_commit(&s, c, None)
}

async fn restart(State(s): St) -> Json<Value> {
    tracing::warn!("restart requested via API");
    s.stop.store(true, Ordering::Relaxed);
    Json(json!({ "ok": true, "note": "ephemerisd is exiting; systemd restarts it in ~2 s" }))
}

// ------------------------------------------------------------ OS updates
//
// Updates are done by systemd-sysupdate (see image/). ephemerisd runs in a
// sandbox with a read-only file system, so it never writes to disk itself: it
// asks systemd to run things in their own, unsandboxed units.

/// Run a command in a transient systemd unit and capture its output.
async fn systemd_run(args: &'static [&'static str]) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new("systemd-run")
            .args([
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--service-type=exec",
            ])
            .args(args)
            .output()
            .map_err(|e| {
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("systemd-run: {e}"),
                )
            })?;
        command_output(out.status.success(), &out.stdout, &out.stderr)
            .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e))
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

/// A command's answer is its stdout; its stderr is a log of what it did
/// (systemd-sysupdate's progress, gpg's notes). Only a failure shows the
/// log, where it's the useful part.
fn command_output(ok: bool, stdout: &[u8], stderr: &[u8]) -> Result<String, String> {
    let out = String::from_utf8_lossy(stdout).into_owned();
    if ok {
        return Ok(out);
    }
    let log = String::from_utf8_lossy(stderr);
    let text = format!("{}\n{}", out.trim(), log.trim());
    Err(text.trim().to_string())
}

/// The version in a boot entry's name: "ephemeris_0.7.1-d0d9b19_x86-64+3-0.efi"
/// -> "0.7.1-d0d9b19".
fn entry_version(id: &str) -> Option<String> {
    let rest = id.strip_prefix("ephemeris_")?;
    let (v, _) = rest.split_once("_x86-64")?;
    (!v.is_empty()).then(|| v.to_string())
}

/// The version the boot loader will start next (its default entry).
async fn boot_default_version() -> Option<String> {
    let out = systemd_run(&["/usr/bin/bootctl", "list", "--json=short", "--no-pager"])
        .await
        .ok()?;
    let entries: Value = serde_json::from_str(&out).ok()?;
    entries
        .as_array()?
        .iter()
        .find(|e| e["isDefault"] == true)
        .and_then(|e| e["id"].as_str())
        .and_then(entry_version)
}

/// Where a software update stands: "idle", "installing" (into the idle
/// slot), "installed" (reboot to switch) or "failed".
async fn update_status(s: &Shared, job_state: &str, job_result: &str) -> Value {
    let running = std::fs::read_to_string("/usr/lib/ephemeris/version")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    if matches!(job_state, "activating" | "active" | "reloading") {
        let target = s.update.lock().unwrap().target.clone();
        return json!({ "phase": "installing", "version": target });
    }
    // Ask the boot loader at most every 15 s, or when the job changed.
    let key = format!("{job_state}/{job_result}");
    let cached = s.update.lock().unwrap().default_entry.clone();
    let default = match cached {
        Some((at, k, v)) if k == key && at.elapsed() < Duration::from_secs(15) => v,
        _ => {
            let v = boot_default_version().await;
            s.update.lock().unwrap().default_entry =
                Some((std::time::Instant::now(), key, v.clone()));
            v
        }
    };
    match default {
        Some(v) if !running.is_empty() && v != running => {
            json!({ "phase": "installed", "version": v })
        }
        _ if job_state == "failed" || (job_result != "success" && !job_result.is_empty()) => {
            json!({ "phase": "failed", "detail": format!("the last install ended with: {job_result} (see journalctl -u ephemeris-update)") })
        }
        _ => json!({ "phase": "idle" }),
    }
}

fn systemctl(args: &[&str]) -> Result<String, ApiError> {
    let out = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("systemctl: {e}")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(ApiError(
            StatusCode::BAD_GATEWAY,
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

async fn system(State(s): St) -> Json<Value> {
    // "ActiveState=activating\nResult=success\n" -> {"active_state": .., "result": ..}
    let job = systemctl(&[
        "show",
        "-p",
        "ActiveState,Result",
        "ephemeris-update.service",
    ])
    .map(|out| {
        let get = |k: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(k))
                .unwrap_or("")
                .to_string()
        };
        json!({ "state": get("ActiveState="), "result": get("Result=") })
    })
    .unwrap_or(Value::Null);
    let update = update_status(
        &s,
        job["state"].as_str().unwrap_or(""),
        job["result"].as_str().unwrap_or(""),
    )
    .await;
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build": s.build,
        "update_job": job,
        "update": update,
    }))
}

async fn update_check() -> ApiResult {
    let list = systemd_run(&["/usr/lib/systemd/systemd-sysupdate", "list"]).await?;
    let newest = systemd_run(&["/usr/lib/systemd/systemd-sysupdate", "check-new"])
        .await
        .map(|o| o.trim().to_string())
        .unwrap_or_default();
    Ok(Json(json!({
        "versions": list,
        "available": (!newest.is_empty()).then_some(newest),
    })))
}

async fn update_start(State(s): St) -> ApiResult {
    // Which version it will install, for the messages while it runs.
    let target = systemd_run(&["/usr/lib/systemd/systemd-sysupdate", "check-new"])
        .await
        .map(|o| o.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty());
    s.update.lock().unwrap().target = target.clone();
    systemctl(&["start", "--no-block", "ephemeris-update.service"])?;
    let note = match &target {
        Some(v) => format!(
            "Installing {v} into the idle slot. The router keeps forwarding; reboot when it's installed."
        ),
        None => "Installing the newest version into the idle slot. The router keeps forwarding; reboot when it's installed.".into(),
    };
    Ok(Json(json!({ "ok": true, "version": target, "note": note })))
}

async fn reboot() -> ApiResult {
    tracing::warn!("reboot requested via API");
    systemctl(&["reboot", "--no-block"])?;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::configmgr::ConfigManager;
    use crate::mgmt::PortRuntime;
    use crate::report::{Control, Report};
    use axum::body::Body;
    use std::sync::atomic::AtomicBool;
    use std::sync::{mpsc, Mutex, RwLock};
    use tower::ServiceExt;

    const CONFIG: &str = r#"
[management]
listen = "127.0.0.1:0"

[[interface]]
name = "lan-a"
device = "eth1"
address = "10.10.1.1/24"

[[interface]]
name = "lan-b"
device = "eth2"
address = "10.10.2.1/24"
"#;

    static STOP: AtomicBool = AtomicBool::new(false);

    fn shared(tag: &str) -> (Arc<Shared>, mpsc::Receiver<Control>) {
        let dir = std::env::temp_dir().join(format!("eph-api-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ephemeris.toml");
        std::fs::write(&path, CONFIG).unwrap();
        let mgr = ConfigManager::open(&path).unwrap();
        let ports: Arc<[_]> = mgr
            .running()
            .ports(|_| Ok([2, 0, 0, 0, 0, 1]))
            .unwrap()
            .into();
        let fib = Arc::new(mgr.running().fib(&ports).unwrap());
        let (tx, rx) = mpsc::channel();
        let s = Shared {
            build: "test".into(),
            started: std::time::Instant::now(),
            runtime: ["eth1", "eth2"]
                .map(|d| PortRuntime {
                    device: d.into(),
                    xdp_mode: "Native".into(),
                    zero_copy: false,
                })
                .to_vec(),
            workers: 1,
            ports: RwLock::new(ports),
            fib: RwLock::new(fib),
            overlay: Arc::new(eph_dataplane::overlay::Overlay::disabled()),
            paths: RwLock::new(Arc::new(eph_dataplane::overlay::PathTable {
                gen: 0,
                choice: vec![],
            })),
            health: RwLock::new(vec![]),
            reports: vec![Arc::new(Mutex::new(Report::default()))],
            control: Mutex::new(vec![tx]),
            config: Mutex::new(mgr),
            token: "secret".into(),
            auth: crate::mgmt::auth::Auth::new(&dir),
            startup: Default::default(),
            dhcp: Default::default(),
            endpoints: Arc::new(eph_dataplane::overlay::Endpoints::new(0)),
            history: Default::default(),
            update: Default::default(),
            system: Default::default(),
            umem_bytes: 0,
            detail: Default::default(),
            stop: &STOP,
        };
        (Arc::new(s), rx)
    }

    async fn call(
        s: &Arc<Shared>,
        method: &str,
        uri: &str,
        token: &str,
        body: Body,
        json: bool,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if !token.is_empty() {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if json {
            req = req.header(header::CONTENT_TYPE, "application/json");
        }
        let resp = router(s.clone())
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[test]
    fn command_output_keeps_the_log_out_of_answers() {
        let log = b"Automatically discovered root block device '/dev/sda'.\ngpg: Good signature\n";
        assert_eq!(
            command_output(true, b"0.7.1-d0d9b19\n", log)
                .unwrap()
                .trim(),
            "0.7.1-d0d9b19"
        );
        let e = command_output(false, b"", b"Failed to acquire manifest: 404\n").unwrap_err();
        assert_eq!(e, "Failed to acquire manifest: 404");
    }

    #[test]
    fn boot_entry_versions() {
        assert_eq!(
            entry_version("ephemeris_0.7.1-d0d9b19_x86-64+3-0.efi").as_deref(),
            Some("0.7.1-d0d9b19")
        );
        assert_eq!(
            entry_version("ephemeris_0.7.0.9_x86-64.efi").as_deref(),
            Some("0.7.0.9")
        );
        assert_eq!(entry_version("auto-windows"), None);
    }

    #[tokio::test]
    async fn api_requires_the_token() {
        let (s, _) = shared("auth");
        let (code, _) = call(&s, "GET", "/api/v1/status", "", Body::empty(), false).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        let (code, _) = call(&s, "GET", "/api/v1/status", "wrong", Body::empty(), false).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        let (code, v) = call(&s, "GET", "/api/v1/status", "secret", Body::empty(), false).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["ports"][1]["address"], "10.10.2.1/24");
        // The portal page itself is public (it asks for the token).
        let resp = router(s.clone())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn only_the_api_token_can_reset_the_password() {
        let (s, _) = shared("pwreset");
        let body = || Body::from(r#"{"new":"a-brand-new-password"}"#);
        // A portal session must know the current password.
        let cookie = s.auth.new_session().unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/system/password")
            .header(header::COOKIE, format!("eph_session={cookie}"))
            .header("x-ephemeris", "1")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body())
            .unwrap();
        let resp = router(s.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("only root"));
        // The token may (hashing needs Linux's crypt, so only check it there).
        #[cfg(target_os = "linux")]
        {
            let (code, _) = call(
                &s,
                "POST",
                "/api/v1/system/password",
                "secret",
                body(),
                true,
            )
            .await;
            assert_eq!(code, StatusCode::OK);
            assert!(s.auth.check_password("a-brand-new-password"));
        }
    }

    async fn call_cookie(
        s: &Arc<Shared>,
        method: &str,
        uri: &str,
        cookie: &str,
        csrf: bool,
    ) -> StatusCode {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::COOKIE, format!("eph_session={cookie}"));
        if csrf {
            req = req.header("x-ephemeris", "1");
        }
        router(s.clone())
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn web_sessions_and_csrf_protection() {
        let (s, _) = shared("session");
        let sess = s.auth.new_session().unwrap();
        assert_eq!(
            call_cookie(&s, "GET", "/api/v1/status", &sess, false).await,
            StatusCode::OK
        );
        assert_eq!(
            call_cookie(&s, "GET", "/api/v1/status", "forged", false).await,
            StatusCode::UNAUTHORIZED
        );
        // Changing something with only a cookie: refused without the header.
        assert_eq!(
            call_cookie(&s, "POST", "/api/v1/config/confirm", &sess, false).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call_cookie(&s, "POST", "/api/v1/logout", &sess, true).await,
            StatusCode::OK
        );
        assert_eq!(
            call_cookie(&s, "GET", "/api/v1/status", &sess, false).await,
            StatusCode::UNAUTHORIZED,
            "logged out"
        );
        // Wrong password: refused.
        let body = Body::from(r#"{"username":"admin","password":"nope"}"#);
        let (code, _) = call(&s, "POST", "/api/v1/login", "", body, true).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn empty_token_never_authenticates() {
        let (s, _) = shared("emptytoken");
        let mut sh = Arc::try_unwrap(s).ok().unwrap();
        sh.token = String::new();
        let s = Arc::new(sh);
        let req = Request::builder()
            .uri("/api/v1/status")
            .header(header::AUTHORIZATION, "Bearer ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router(s).oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn adding_a_route_reaches_the_workers() {
        let (s, rx) = shared("route");
        let body = Body::from(r#"{"prefix":"192.168.50.0/24","via":"10.10.2.254"}"#);
        let (code, v) = call(&s, "POST", "/api/v1/routes", "secret", body, true).await;
        assert_eq!(code, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], "live");
        // The worker channel received the new tables.
        let msgs: Vec<Control> = rx.try_iter().collect();
        assert!(msgs
            .iter()
            .any(|m| matches!(m, Control::SetFib(f) if f.routes().len() == 3)));
        let (_, v) = call(&s, "GET", "/api/v1/routes", "secret", Body::empty(), false).await;
        assert!(v
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["via"] == "10.10.2.254"));
        // And it can be removed again.
        let (code, _) = call(
            &s,
            "DELETE",
            "/api/v1/routes?prefix=192.168.50.0/24",
            "secret",
            Body::empty(),
            false,
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(s.fib.read().unwrap().routes().len(), 2);
    }

    #[tokio::test]
    async fn bad_config_is_rejected_with_a_reason() {
        let (s, _) = shared("bad");
        let body = Body::from(r#"{"prefix":"0.0.0.0/0","via":"172.16.0.1"}"#);
        let (code, v) = call(&s, "POST", "/api/v1/routes", "secret", body, true).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .contains("not on any connected subnet"),
            "{v}"
        );
        let (code, v) = call(
            &s,
            "PUT",
            "/api/v1/config/candidate",
            "secret",
            Body::from("not = [valid"),
            false,
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{v}");
    }

    fn get(uri: &str, headers: &[(&str, &str)]) -> Request {
        let mut r = Request::builder().uri(uri);
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        r.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn requests_for_other_host_names_are_refused() {
        let (s, _) = shared("host");
        for ok in ["10.0.2.15:8443", "[::1]:8443", "localhost", "127.0.0.1"] {
            let resp = router(s.clone()).oneshot(get("/", &[("host", ok)])).await;
            assert_eq!(resp.unwrap().status(), StatusCode::OK, "{ok}");
        }
        // DNS rebinding: someone else's name pointing at the router.
        let resp = router(s.clone())
            .oneshot(get("/", &[("host", "attacker.example:8443")]))
            .await;
        assert_eq!(resp.unwrap().status(), StatusCode::MISDIRECTED_REQUEST);
    }

    #[tokio::test]
    async fn cross_origin_changes_are_refused() {
        let (s, _) = shared("origin");
        let post = |origin: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/confirm")
                .header(header::AUTHORIZATION, "Bearer secret")
                .header(header::HOST, "10.0.2.15:8443")
                .header(header::ORIGIN, origin)
                .body(Body::empty())
                .unwrap()
        };
        let resp = router(s.clone())
            .oneshot(post("https://evil.example"))
            .await;
        assert_eq!(resp.unwrap().status(), StatusCode::FORBIDDEN);
        // Same origin: reaches the handler (which has nothing to confirm).
        let resp = router(s.clone())
            .oneshot(post("https://10.0.2.15:8443"))
            .await;
        assert_eq!(resp.unwrap().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn responses_carry_security_headers() {
        let (s, _) = shared("headers");
        let resp = router(s.clone()).oneshot(get("/", &[])).await.unwrap();
        let h = resp.headers();
        let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("script-src 'self';"), "{csp}");
        assert!(!csp.contains("script-src 'unsafe-inline'"));
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert!(
            h.get(header::STRICT_TRANSPORT_SECURITY).is_none(),
            "not over HTTPS"
        );
        // Through nginx over HTTPS: HSTS too.
        let resp = router(s.clone())
            .oneshot(get("/", &[("x-forwarded-proto", "https")]))
            .await
            .unwrap();
        assert!(resp
            .headers()
            .get(header::STRICT_TRANSPORT_SECURITY)
            .is_some());
        // The portal's script is a file of its own.
        let resp = router(s.clone())
            .oneshot(get("/app.js", &[]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/javascript"));
    }

    #[tokio::test]
    async fn the_confirm_window_is_bounded() {
        let (s, _) = shared("confirm");
        let uri = "/api/v1/config/commit?confirm=18446744073709551615";
        let (code, v) = call(&s, "POST", uri, "secret", Body::empty(), false).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(
            v["error"].as_str().unwrap().contains("between 1 and 3600"),
            "{v}"
        );
    }

    #[tokio::test]
    async fn an_address_guessing_passwords_is_locked_out() {
        let (s, _) = shared("lockout");
        let guesser: std::net::IpAddr = "192.0.2.50".parse().unwrap();
        for _ in 0..5 {
            s.auth.throttle.failed(guesser);
        }
        let login = |ip: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/login")
                .header("x-real-ip", ip)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"username":"admin","password":"guess"}"#))
                .unwrap()
        };
        let resp = router(s.clone())
            .oneshot(login("192.0.2.50"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get(header::RETRY_AFTER).is_some());
        // Someone else still gets to try (and fail).
        let resp = router(s.clone())
            .oneshot(login("192.0.2.51"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn oversized_bodies_are_refused() {
        let (s, _) = shared("bigbody");
        let body = Body::from(vec![b'#'; MAX_BODY + 1]);
        let (code, _) = call(&s, "PUT", "/api/v1/config/candidate", "secret", body, false).await;
        assert_eq!(code, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
