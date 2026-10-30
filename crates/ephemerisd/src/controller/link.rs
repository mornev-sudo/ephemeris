//! The connection to the controller (docs/controller-api.md): the router
//! connects out over TLS (see [`tls`]) to `wss://<url>/v1/router`, says
//! `hello`, and stays connected: WebSocket pings every 30 s, closed after
//! 90 s without a frame, reconnected with exponential backoff (1 s up to
//! 5 min, with jitter). Enrolment is one connection of its own, before
//! there's a `[controller]` section to follow.
//!
//! Nothing the controller sends is acted on yet: requests are answered
//! `unknown_type` until the router learns them (config, telemetry...).

use super::{tls, Identity};
use crate::mgmt::Shared;
use crate::sdwan::hex;
use anyhow::{bail, Context, Result};
use eph_config::Enrolment;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{info, warn};

/// The message set this router speaks (`hello`'s `protocol`).
pub const PROTOCOL: u64 = 1;
const PING_EVERY: Duration = Duration::from_secs(30);
const SILENT_AFTER: Duration = Duration::from_secs(90);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A message is at most this big.
const MAX_MESSAGE: usize = 1 << 20;
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// Connected this long: the next reconnect starts from 1 s again.
const STABLE_AFTER: Duration = Duration::from_secs(60);

/// Where the link stands, for the API (`GET /controller`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Status {
    pub state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The controller's id for this router, once it said hello back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub router_id: Option<u64>,
    /// When the current state began (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// No `[controller]` section: not managed.
    #[default]
    Off,
    Connecting,
    Connected,
    /// The controller doesn't know this router's key: it needs a new
    /// enrolment (an administrator's token). Retried with backoff anyway.
    NotEnrolled,
    /// The last attempt failed (see `error`); retrying with backoff.
    Failed,
}

/// An error the controller answered with (`"error": {"code", "message"}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the controller refused: {} ({})",
            self.code, self.message
        )
    }
}

impl std::error::Error for Refused {}

type Ws = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `https://host[:port][/path]` → host, port, and the WebSocket path.
fn split_url(url: &str) -> Result<(String, u16, String)> {
    eph_config::check_controller_url(url)?;
    let rest = url.strip_prefix("https://").expect("checked");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().expect("checked")),
        None => (authority, 443),
    };
    let base = path.trim_end_matches('/');
    let path = if base.is_empty() {
        "/v1/router".to_string()
    } else {
        format!("/{base}/v1/router")
    };
    Ok((host.to_string(), port, path))
}

/// TLS (the pinned key, the router's certificate), then the WebSocket.
pub async fn connect(url: &str, pin: [u8; 32], identity: &Identity) -> Result<Ws> {
    let (host, port, path) = split_url(url)?;
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .context("connecting: timed out")?
        .with_context(|| format!("connecting to {host}:{port}"))?;
    let name = ServerName::try_from(host.clone()).context("the controller's host name")?;
    let connector = tokio_rustls::TlsConnector::from(tls::client_config(identity, pin)?);
    let tls = timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
        .await
        .context("TLS: timed out")?
        .context("TLS (is the pin right?)")?;
    let config = WebSocketConfig {
        max_message_size: Some(MAX_MESSAGE),
        max_frame_size: Some(MAX_MESSAGE),
        ..Default::default()
    };
    let request = format!("wss://{host}:{port}{path}");
    let (ws, _) = timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::client_async_with_config(request, tls, Some(config)),
    )
    .await
    .context("WebSocket: timed out")?
    .context("WebSocket")?;
    Ok(ws)
}

async fn send<S>(ws: &mut WebSocketStream<S>, v: Value) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    ws.send(Message::Text(v.to_string())).await?;
    Ok(())
}

/// The answer to our request `id`: its `ok`, or what the controller refused
/// with. Pings on the way are fine; any other message first isn't.
async fn answer<S>(ws: &mut WebSocketStream<S>, id: u64) -> Result<Value>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let msg = timeout(SILENT_AFTER, ws.next())
            .await
            .context("no answer from the controller")?
            .context("the controller closed the connection")??;
        match msg {
            Message::Text(t) => {
                let v: Value = serde_json::from_str(&t).context("a malformed answer")?;
                if v["type"] != "result" || v["id"] != id {
                    bail!("the controller sent something else before answering");
                }
                if let Some(e) = v.get("error") {
                    return Err(Refused {
                        code: e["code"].as_str().unwrap_or("?").to_string(),
                        message: e["message"].as_str().unwrap_or("").to_string(),
                    }
                    .into());
                }
                return Ok(v["ok"].clone());
            }
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => bail!("the controller closed the connection"),
            _ => bail!("the controller sent something else before answering"),
        }
    }
}

fn refused_with(e: &anyhow::Error, code: &str) -> bool {
    e.downcast_ref::<Refused>().is_some_and(|r| r.code == code)
}

/// Say hello as request `id`; the controller's id for this router.
async fn say_hello<S>(ws: &mut WebSocketStream<S>, mut hello: Value, id: u64) -> Result<u64>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    hello["id"] = id.into();
    send(ws, hello).await?;
    let ok = answer(ws, id).await?;
    if ok["protocol"].as_u64() != Some(PROTOCOL) {
        bail!(
            "the controller speaks protocol {}, not {PROTOCOL}",
            ok["protocol"]
        );
    }
    ok["router_id"]
        .as_u64()
        .context("the controller's hello answer has no router_id")
}

/// Enrol with a one-time token: `enrol`, then `hello` on the same
/// connection. A router the controller already knows (`already_enrolled`)
/// just says hello. The controller's id for this router.
pub async fn enrol(e: &Enrolment, identity: &Identity, hello: Value) -> Result<u64> {
    let mut ws = connect(&e.url, e.fingerprint, identity).await?;
    send(
        &mut ws,
        json!({"type": "enrol", "id": 1, "token": e.token, "key": hex(&identity.public())}),
    )
    .await?;
    match answer(&mut ws, 1).await {
        Ok(_) => {}
        Err(err) if refused_with(&err, "already_enrolled") => {}
        Err(err) => return Err(err),
    }
    let id = say_hello(&mut ws, hello, 2).await?;
    let _ = ws.close(None).await;
    Ok(id)
}

/// One connected session: hello, then keep-alive and answering until the
/// controller goes away, falls silent, or `wanted` says to stop (the
/// `[controller]` section changed).
pub async fn session<S>(
    mut ws: WebSocketStream<S>,
    hello: Value,
    status: &Mutex<Status>,
    wanted: impl Fn() -> bool,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let router_id = say_hello(&mut ws, hello, 1).await?;
    {
        let mut s = status.lock().unwrap();
        s.state = State::Connected;
        s.router_id = Some(router_id);
        s.since_unix = Some(now_unix());
        s.error = None;
    }
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    let mut heard = Instant::now();
    loop {
        tokio::select! {
            msg = ws.next() => {
                let Some(msg) = msg else { return Ok(()) };
                heard = Instant::now();
                match msg? {
                    Message::Text(t) => answer_request(&mut ws, &t).await?,
                    Message::Close(_) => return Ok(()),
                    _ => {}
                }
            }
            _ = ping.tick() => {
                if heard.elapsed() > SILENT_AFTER {
                    bail!("the controller went silent");
                }
                if !wanted() {
                    let _ = ws.close(None).await;
                    return Ok(());
                }
                ws.send(Message::Ping(Vec::new())).await?;
            }
        }
    }
}

/// A request from the controller. None are known yet.
async fn answer_request<S>(ws: &mut WebSocketStream<S>, text: &str) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let error = |id: Value, code: &str, message: String| json!({"type": "result", "id": id, "error": {"code": code, "message": message}});
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return send(ws, error(Value::Null, "bad_request", "not JSON".into())).await;
    };
    let (typ, id) = (v["type"].as_str().unwrap_or(""), v["id"].clone());
    if typ == "result" {
        return Ok(()); // an answer to nothing we asked
    }
    if !id.is_u64() {
        return send(
            ws,
            error(Value::Null, "bad_request", "no request id".into()),
        )
        .await;
    }
    send(
        ws,
        error(
            id,
            "unknown_type",
            format!("this router doesn't know {typ:?}"),
        ),
    )
    .await
}

/// `hello`'s contents: the router and its running config.
pub fn hello(shared: &Shared) -> Value {
    let (sha, pending) = {
        let mgr = shared.config.lock().unwrap();
        let sha: [u8; 32] = Sha256::digest(mgr.running_text().as_bytes()).into();
        (hex(&sha), mgr.pending_confirm_secs())
    };
    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    json!({
        "type": "hello",
        "protocol": PROTOCOL,
        "router": {"version": shared.build, "hostname": hostname},
        // No version number yet: config history only counts back from the
        // running one. `sha256` identifies the config meanwhile.
        "config": {"version": Value::Null, "sha256": sha, "schema": schema()},
        "pending_confirm": pending,
        "capabilities": [],
    })
}

/// The config format's name: this release's major.minor (`"0.13"`).
fn schema() -> String {
    env!("CARGO_PKG_VERSION")
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".")
}

/// A delay of `d` plus up to a quarter more, so routers don't all come
/// back in the same second.
fn jittered(d: Duration) -> Duration {
    let mut b = [0u8; 2];
    let r = getrandom::fill(&mut b).map_or(0, |_| u16::from_le_bytes(b));
    d + d.mul_f64(f64::from(r) / f64::from(u16::MAX) / 4.0)
}

/// Follow the `[controller]` section for as long as the router runs, on a
/// thread of its own.
pub fn spawn(shared: Arc<Shared>, identity: Arc<Identity>) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("eph-controller".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a tokio runtime");
            rt.block_on(follow(shared, identity));
        })
        .map(|_| ())
}

async fn follow(shared: Arc<Shared>, identity: Arc<Identity>) {
    let mut backoff = Duration::from_secs(1);
    let section = || shared.config.lock().unwrap().running().controller.clone();
    loop {
        let Some(cfg) = section() else {
            *shared.controller.lock().unwrap() = Status::default();
            backoff = Duration::from_secs(1);
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        let set = |state: State, error: Option<String>| {
            let mut s = shared.controller.lock().unwrap();
            if s.state != state {
                s.since_unix = Some(now_unix());
            }
            s.state = state;
            s.url = Some(cfg.url.clone());
            s.error = error;
        };
        set(State::Connecting, None);
        let started = Instant::now();
        let result = match cfg.pin_bytes() {
            Ok(pin) => match connect(&cfg.url, pin, &identity).await {
                Ok(ws) => {
                    let wanted = || section().as_ref() == Some(&cfg);
                    session(ws, hello(&shared), &shared.controller, wanted).await
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        let was_up = shared.controller.lock().unwrap().state == State::Connected;
        if was_up {
            info!(target: crate::logging::cat::MGMT, "controller {}: disconnected", cfg.url);
        }
        match result {
            Ok(()) => set(State::Connecting, None),
            Err(e) if refused_with(&e, "not_enrolled") => {
                warn!(target: crate::logging::cat::MGMT, "controller {} doesn't know this router: it needs enrolling again", cfg.url);
                set(State::NotEnrolled, Some(format!("{e:#}")));
            }
            Err(e) => {
                if !was_up {
                    warn!(target: crate::logging::cat::MGMT, "controller {}: {e:#}", cfg.url);
                }
                set(State::Failed, Some(format!("{e:#}")));
            }
        }
        if started.elapsed() > STABLE_AFTER {
            backoff = Duration::from_secs(1);
        }
        tokio::time::sleep(jittered(backoff)).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
    use tokio::net::TcpListener;

    #[test]
    fn urls_become_websocket_paths() {
        let s = |u: &str| split_url(u).unwrap();
        assert_eq!(
            s("https://c.example.net"),
            ("c.example.net".into(), 443, "/v1/router".into())
        );
        assert_eq!(
            s("https://c.example.net/"),
            ("c.example.net".into(), 443, "/v1/router".into())
        );
        assert_eq!(
            s("https://10.0.0.5:8443/acme/"),
            ("10.0.0.5".into(), 8443, "/acme/v1/router".into())
        );
        assert!(split_url("http://c.example.net/").is_err());
    }

    #[test]
    fn backoff_jitter_stays_within_a_quarter() {
        for _ in 0..100 {
            let d = jittered(Duration::from_secs(8));
            assert!(
                (Duration::from_secs(8)..=Duration::from_secs(10)).contains(&d),
                "{d:?}"
            );
        }
    }

    /// Accepts any client certificate (the test checks its key itself).
    #[derive(Debug)]
    struct AnyClient(rustls::crypto::WebPkiSupportedAlgorithms);

    impl ClientCertVerifier for AnyClient {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }
        fn verify_client_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            Ok(ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("no TLS 1.2".into()))
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_schemes()
        }
    }

    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO_-";

    /// A controller for one connection, playing the contract's part: it
    /// checks the token and that `enrol`'s key is the client certificate's,
    /// answers hello, then sends an unknown request and a ping, and closes
    /// once it has the answer. Its address and pin.
    async fn controller(known: bool) -> (String, [u8; 32], tokio::task::JoinHandle<Vec<Value>>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let pin = tls::spki_sha256(&cert_der).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(AnyClient(
                provider.signature_verification_algorithms,
            )))
            .with_single_cert(
                vec![cert_der],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(tcp)
                .await
                .unwrap();
            let client_key = {
                let certs = tls.get_ref().1.peer_certificates().unwrap();
                let ee = webpki::EndEntityCert::try_from(&certs[0]).unwrap();
                hex(&ee.subject_public_key_info().as_ref()[12..])
            };
            let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
            let mut seen = Vec::new();
            let mut enrolled = known;
            while let Some(Ok(msg)) = ws.next().await {
                let Message::Text(t) = msg else { continue };
                let v: Value = serde_json::from_str(&t).unwrap();
                seen.push(v.clone());
                let id = v["id"].clone();
                let reply = match v["type"].as_str().unwrap() {
                    "enrol" if v["token"] != TOKEN => {
                        json!({"type": "result", "id": id, "error": {"code": "invalid_token", "message": ""}})
                    }
                    "enrol" if v["key"] != client_key.as_str() => {
                        json!({"type": "result", "id": id, "error": {"code": "bad_request", "message": "key"}})
                    }
                    "enrol" => {
                        enrolled = true;
                        json!({"type": "result", "id": id, "ok": {"router_id": 12}})
                    }
                    "hello" if !enrolled => {
                        json!({"type": "result", "id": id, "error": {"code": "not_enrolled", "message": ""}})
                    }
                    "hello" => json!({"type": "result", "id": id, "ok": {
                        "protocol": 1, "router_id": 12, "expected_config": null, "push_waiting": false}}),
                    "result" => break, // the router's answer to our request below
                    _ => continue,
                };
                let hello_ok = v["type"] == "hello" && enrolled;
                ws.send(Message::Text(reply.to_string())).await.unwrap();
                if hello_ok && known {
                    ws.send(Message::Ping(Vec::new())).await.unwrap();
                    let req = json!({"type": "config.push", "id": 1});
                    ws.send(Message::Text(req.to_string())).await.unwrap();
                }
            }
            let _ = ws.close(None).await;
            seen
        });
        (format!("https://localhost:{}/", addr.port()), pin, task)
    }

    fn hello_msg() -> Value {
        json!({"type": "hello", "protocol": PROTOCOL, "router": {}, "config": {}, "capabilities": []})
    }

    #[tokio::test]
    async fn enrolment_registers_the_key_of_the_client_certificate() {
        let (url, pin, server) = controller(false).await;
        let id = Identity::from_seed([5; 32]);
        let e = Enrolment::parse(&format!("eph-enrol:v1:{url}#{TOKEN}@{}", hex(&pin))).unwrap();
        assert_eq!(enrol(&e, &id, hello_msg()).await.unwrap(), 12);
        let seen = server.await.unwrap();
        assert_eq!(seen[0]["type"], "enrol");
        assert_eq!(seen[0]["key"], hex(&id.public()));
        assert_eq!(
            (seen[1]["type"].as_str(), seen[1]["id"].as_u64()),
            (Some("hello"), Some(2))
        );
    }

    #[tokio::test]
    async fn a_wrong_token_or_pin_is_refused() {
        let (url, pin, _server) = controller(false).await;
        let id = Identity::from_seed([5; 32]);
        let bad_token = "x".repeat(43);
        let e = Enrolment::parse(&format!("eph-enrol:v1:{url}#{bad_token}@{}", hex(&pin))).unwrap();
        let err = enrol(&e, &id, hello_msg()).await.unwrap_err();
        assert!(refused_with(&err, "invalid_token"), "{err:#}");

        let (url, _, _server) = controller(false).await;
        let e =
            Enrolment::parse(&format!("eph-enrol:v1:{url}#{TOKEN}@{}", "00".repeat(32))).unwrap();
        let err = enrol(&e, &id, hello_msg()).await.unwrap_err();
        assert!(format!("{err:#}").contains("TLS"), "{err:#}");
    }

    #[tokio::test]
    async fn a_session_says_hello_and_answers_what_it_doesnt_know() {
        let (url, pin, server) = controller(true).await;
        let id = Identity::from_seed([6; 32]);
        let ws = connect(&url, pin, &id).await.unwrap();
        let status = Mutex::new(Status::default());
        session(ws, hello_msg(), &status, || true).await.unwrap();
        assert_eq!(status.lock().unwrap().state, State::Connected);
        assert_eq!(status.lock().unwrap().router_id, Some(12));
        let seen = server.await.unwrap();
        assert_eq!(
            (seen[0]["type"].as_str(), seen[0]["id"].as_u64()),
            (Some("hello"), Some(1))
        );
        assert_eq!(seen[1]["error"]["code"], "unknown_type");
        assert_eq!(seen[1]["id"], 1);
    }

    #[tokio::test]
    async fn not_enrolled_is_told_apart() {
        let (url, pin, _server) = controller(false).await;
        let id = Identity::from_seed([7; 32]);
        let ws = connect(&url, pin, &id).await.unwrap();
        let status = Mutex::new(Status::default());
        let err = session(ws, hello_msg(), &status, || true)
            .await
            .unwrap_err();
        assert!(refused_with(&err, "not_enrolled"), "{err:#}");
    }
}
