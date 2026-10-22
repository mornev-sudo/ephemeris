//! PPPoE client: dial an ISP over an outside interface.
//!
//! ```text
//! Discovery (RFC 2516)   PADI ─▶ PADO ◀─ PADR ─▶ PADS ◀─        session id
//! LCP (RFC 1661)         Configure-Request/Ack both ways        MRU, magic, auth
//! Auth                   PAP (RFC 1334) or CHAP-MD5 (RFC 1994)  login
//! IPCP (RFC 1332, 1877)  Configure-Request/Nak/Ack both ways    address, DNS
//! Up                     LCP echo every 10 s; 30 s silence = down
//! ```
//!
//! Pure logic like the DHCP client: frames and the time go in, frames to
//! send and events come out. Time is in whole seconds; `tick` is called
//! once a second.

use crate::logging::cat::PPPOE;
use eph_packet::pppoe::{self, Control, Frame};
use eph_packet::{eth, Mac};
use serde::Serialize;
use std::net::Ipv4Addr;
use tracing::{debug, info, trace, warn};

/// Configure-Request restart timer and Max-Configure (RFC 1661 4.6).
const RESTART_SECS: u64 = 3;
const MAX_CONFIGURE: u32 = 10;
const ECHO_EVERY_SECS: u64 = 10;
/// No LCP traffic at all from the ISP for this long: the link is dead.
const DEAD_AFTER_SECS: u64 = 30;
/// Waiting for a CHAP challenge (the ISP sends it).
const AUTH_WAIT_SECS: u64 = 30;
const RETRY_MAX_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub interface: String,
    pub mac: Mac,
    pub username: String,
    pub password: String,
    /// Service-Name to ask for; empty = any.
    pub service: String,
    pub mtu: u16,
}

/// A connected session: what the router applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    pub session: u16,
    #[serde(with = "crate::dhcp::server::mac_text")]
    pub ac_mac: Mac,
    pub ac_name: String,
    pub addr: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub mtu: u16,
    pub up_since_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Looking for an access concentrator (PADI).
    Discovery,
    /// Asking it for a session (PADR).
    Requesting,
    Lcp,
    Auth,
    Ipcp,
    Up,
    /// Waiting before dialling again.
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Up(Link),
    /// Lost (or never got) the session: stop using its address.
    Down(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Auth {
    Pap,
    Chap,
}

type Out = (Vec<Vec<u8>>, Option<Event>);

pub struct Client {
    pub cfg: Settings,
    pub phase: Phase,
    pub link: Option<Link>,
    /// Why the last attempt failed (for the operator).
    pub last_error: Option<String>,
    rng: u32,
    host_uniq: [u8; 4],
    ac: Mac,
    ac_name: String,
    cookie: Option<Vec<u8>>,
    relay: Option<Vec<u8>>,
    session: u16,
    attempts: u32,
    next_tx: u64,
    phase_since: u64,
    downs: u32,
    // LCP
    magic: u32,
    lcp_id: u8,
    lcp_opts: Vec<(u8, Vec<u8>)>,
    lcp_ours: bool,
    lcp_theirs: bool,
    peer_mru: u16,
    auth: Option<Auth>,
    // Authentication
    auth_id: u8,
    // IPCP
    ipcp_id: u8,
    ipcp_opts: Vec<(u8, Vec<u8>)>,
    ipcp_ours: bool,
    ipcp_theirs: bool,
    peer_ip: Ipv4Addr,
    // Keepalive
    echo_id: u8,
    last_heard: u64,
    last_echo: u64,
}

impl Client {
    pub fn new(cfg: Settings, seed: u32) -> Self {
        let mut c = Client {
            cfg,
            phase: Phase::Down,
            link: None,
            last_error: None,
            rng: seed | 1,
            host_uniq: [0; 4],
            ac: [0; 6],
            ac_name: String::new(),
            cookie: None,
            relay: None,
            session: 0,
            attempts: 0,
            next_tx: 0,
            phase_since: 0,
            downs: 0,
            magic: 0,
            lcp_id: 0,
            lcp_opts: vec![],
            lcp_ours: false,
            lcp_theirs: false,
            peer_mru: pppoe::DEFAULT_MTU,
            auth: None,
            auth_id: 0,
            ipcp_id: 0,
            ipcp_opts: vec![],
            ipcp_ours: false,
            ipcp_theirs: false,
            peer_ip: Ipv4Addr::UNSPECIFIED,
            echo_id: 0,
            last_heard: 0,
            last_echo: 0,
        };
        c.host_uniq = c.random().to_be_bytes();
        c
    }

    fn random(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        x
    }

    fn enter(&mut self, phase: Phase, now: u64) {
        if self.phase != phase {
            debug!(target: PPPOE, iface = %self.cfg.interface, "{:?} -> {phase:?}", self.phase);
        }
        self.phase = phase;
        self.phase_since = now;
        self.attempts = 0;
        self.next_tx = now;
    }

    /// Timers: call about once a second.
    pub fn tick(&mut self, now: u64) -> Out {
        match self.phase {
            Phase::Down if now >= self.next_tx => {
                self.reset_session();
                self.enter(Phase::Discovery, now);
                self.tick(now)
            }
            Phase::Discovery if now >= self.next_tx => {
                // 3 s, doubling to 30 s, for as long as it takes.
                self.next_tx = now + (RESTART_SECS << self.attempts.min(3)).min(30);
                self.attempts += 1;
                debug!(target: PPPOE, iface = %self.cfg.interface, attempt = self.attempts, "PADI (looking for a concentrator)");
                // Nobody answering discovery is almost always the line, a
                // missing VLAN tag, or the wrong port: say so once.
                if self.attempts == 4 {
                    warn!(target: PPPOE, iface = %self.cfg.interface,
                        "no concentrator answered 4 PADIs: check the cable/modem, and whether the ISP needs a VLAN (vlan = ...)");
                }
                (vec![self.padi()], None)
            }
            Phase::Requesting if now >= self.next_tx => {
                if self.attempts >= 3 {
                    warn!(target: PPPOE, iface = %self.cfg.interface,
                        "{} didn't answer 3 PADRs: back to discovery", eth::fmt_mac(&self.ac));
                    self.enter(Phase::Discovery, now);
                    return self.tick(now);
                }
                self.next_tx = now + RESTART_SECS;
                self.attempts += 1;
                debug!(target: PPPOE, iface = %self.cfg.interface, attempt = self.attempts,
                    "PADR to {} ({})", eth::fmt_mac(&self.ac), self.ac_name);
                (vec![self.padr()], None)
            }
            Phase::Lcp | Phase::Auth | Phase::Ipcp | Phase::Up => self.session_timers(now),
            _ => (vec![], None),
        }
    }

    fn session_timers(&mut self, now: u64) -> Out {
        if now.saturating_sub(self.last_heard) >= DEAD_AFTER_SECS {
            return self.down("the ISP stopped answering (no LCP echo replies)", now);
        }
        let mut out = vec![];
        if (self.phase == Phase::Up || self.lcp_opened())
            && now.saturating_sub(self.last_echo) >= ECHO_EVERY_SECS
        {
            self.last_echo = now;
            self.echo_id = self.echo_id.wrapping_add(1);
            let data = self.magic.to_be_bytes().to_vec();
            out.push(
                self.ppp(
                    pppoe::PROTO_LCP,
                    &Control {
                        code: pppoe::ECHO_REQ,
                        id: self.echo_id,
                        data,
                    }
                    .encode(),
                ),
            );
        }
        if now < self.next_tx {
            return (out, None);
        }
        self.next_tx = now + RESTART_SECS;
        match self.phase {
            Phase::Lcp if !self.lcp_ours => {
                if self.attempts >= MAX_CONFIGURE {
                    return self.down("LCP negotiation didn't finish", now);
                }
                self.attempts += 1;
                out.push(self.lcp_request());
            }
            Phase::Auth => match self.auth {
                Some(Auth::Pap) => {
                    if self.attempts >= MAX_CONFIGURE {
                        return self.down("no answer to the PAP login", now);
                    }
                    self.attempts += 1;
                    out.push(self.pap_request());
                }
                _ if now.saturating_sub(self.phase_since) >= AUTH_WAIT_SECS => {
                    return self.down("the ISP never sent a CHAP challenge", now);
                }
                _ => {}
            },
            Phase::Ipcp if !self.ipcp_ours => {
                if self.attempts >= MAX_CONFIGURE {
                    return self.down("IPCP negotiation didn't finish (no address)", now);
                }
                self.attempts += 1;
                out.push(self.ipcp_request());
            }
            _ => {}
        }
        (out, None)
    }

    /// A PPPoE frame from the interface.
    pub fn handle(&mut self, f: &Frame, now: u64) -> Out {
        if f.ethertype == pppoe::TYPE_DISCOVERY {
            return self.discovery(f, now);
        }
        // Session traffic: only from our concentrator, in our session.
        if f.session != self.session || f.src != self.ac || self.session == 0 {
            trace!(target: PPPOE, iface = %self.cfg.interface,
                "ignored session frame: session {:#06x} from {}", f.session, eth::fmt_mac(&f.src));
            return (vec![], None);
        }
        let Some((proto, data)) = f.ppp() else {
            return (vec![], None);
        };
        let data = data.to_vec();
        self.last_heard = now;
        match proto {
            pppoe::PROTO_LCP => self.lcp(&data, now),
            pppoe::PROTO_PAP => self.pap(&data, now),
            pppoe::PROTO_CHAP => self.chap(&data, now),
            pppoe::PROTO_IPCP => self.ipcp(&data, now),
            pppoe::PROTO_IPV4 => (vec![], None), // data before we're up: ignore
            other => {
                // Anything else (IPv6CP, CCP...): Protocol-Reject (RFC 1661 5.7).
                debug!(target: PPPOE, iface = %self.cfg.interface,
                    "Protocol-Reject for PPP protocol {other:#06x} (not supported)");
                let mut rej = other.to_be_bytes().to_vec();
                rej.extend_from_slice(&data);
                rej.truncate(self.peer_mru as usize - 8);
                self.lcp_id = self.lcp_id.wrapping_add(1);
                let c = Control {
                    code: pppoe::PROTO_REJ,
                    id: self.lcp_id,
                    data: rej,
                };
                (vec![self.ppp(pppoe::PROTO_LCP, &c.encode())], None)
            }
        }
    }

    /// Hang up (shutdown, or PPPoE turned off): LCP Terminate and PADT.
    pub fn hang_up(&mut self) -> Vec<Vec<u8>> {
        if self.session == 0 {
            return vec![];
        }
        self.lcp_id = self.lcp_id.wrapping_add(1);
        let term = Control {
            code: pppoe::TERM_REQ,
            id: self.lcp_id,
            data: vec![],
        };
        let out = vec![self.ppp(pppoe::PROTO_LCP, &term.encode()), self.padt()];
        self.reset_session();
        self.link = None;
        self.phase = Phase::Down;
        out
    }

    // ------------------------------------------------------------ discovery

    fn discovery(&mut self, f: &Frame, now: u64) -> Out {
        if f.dst != self.cfg.mac && f.dst != eth::BROADCAST {
            return (vec![], None);
        }
        let ours = f.tag(pppoe::TAG_HOST_UNIQ).as_deref() == Some(&self.host_uniq[..]);
        match (self.phase, f.code) {
            (Phase::Discovery, pppoe::PADO) if ours => {
                if let Some(e) = error_tag(f) {
                    warn!(target: PPPOE, iface = %self.cfg.interface,
                        "PADO from {} with an error: {e}", eth::fmt_mac(&f.src));
                    self.last_error = Some(format!("PADO error: {e}"));
                    return (vec![], None);
                }
                let svc = f.tag(pppoe::TAG_SERVICE_NAME).unwrap_or_default();
                if !self.cfg.service.is_empty() && svc != self.cfg.service.as_bytes() {
                    info!(target: PPPOE, iface = %self.cfg.interface,
                        "PADO from {} offers service {:?}, not {:?}: ignored",
                        eth::fmt_mac(&f.src), String::from_utf8_lossy(&svc), self.cfg.service);
                    return (vec![], None); // offers another service
                }
                self.ac = f.src;
                self.ac_name =
                    String::from_utf8_lossy(&f.tag(pppoe::TAG_AC_NAME).unwrap_or_default()).into();
                self.cookie = f.tag(pppoe::TAG_AC_COOKIE);
                self.relay = f.tag(pppoe::TAG_RELAY_SESSION_ID);
                debug!(target: PPPOE, iface = %self.cfg.interface,
                    "PADO from {} ({}), service {:?}{}", eth::fmt_mac(&f.src), self.ac_name,
                    String::from_utf8_lossy(&svc), if self.cookie.is_some() { ", with a cookie" } else { "" });
                self.enter(Phase::Requesting, now);
                self.tick(now)
            }
            (Phase::Requesting, pppoe::PADS) if ours && f.src == self.ac => {
                if let Some(e) =
                    error_tag(f).or_else(|| (f.session == 0).then(|| "no session id".into()))
                {
                    return self.down(&format!("the ISP refused the session: {e}"), now);
                }
                self.session = f.session;
                info!(target: PPPOE, iface = %self.cfg.interface,
                    "session {:#06x} with {} ({}): negotiating the link", f.session, self.ac_name, eth::fmt_mac(&self.ac));
                self.magic = self.random();
                self.lcp_opts = vec![
                    (pppoe::LCP_MRU, self.cfg.mtu.to_be_bytes().to_vec()),
                    (pppoe::LCP_MAGIC, self.magic.to_be_bytes().to_vec()),
                ];
                self.last_heard = now;
                self.enter(Phase::Lcp, now);
                self.session_timers(now)
            }
            (_, pppoe::PADT)
                if f.session == self.session && f.src == self.ac && self.session != 0 =>
            {
                self.session = 0; // already gone: no PADT back
                self.down("the ISP ended the session (PADT)", now)
            }
            _ => (vec![], None),
        }
    }

    // ------------------------------------------------------------ LCP

    fn lcp_opened(&self) -> bool {
        self.lcp_ours && self.lcp_theirs
    }

    fn lcp(&mut self, data: &[u8], now: u64) -> Out {
        let Some(c) = Control::parse(data) else {
            return (vec![], None);
        };
        trace!(target: PPPOE, iface = %self.cfg.interface, "LCP {} id {} in {:?}", pppoe::code_name(c.code), c.id, self.phase);
        let mut out = vec![];
        let mut event = None;
        match c.code {
            pppoe::CONF_REQ => {
                if self.phase != Phase::Lcp {
                    // The ISP renegotiates: start the link over (RFC 1661).
                    // Until IPCP finishes again the address isn't usable.
                    if self.restart_lcp(now) {
                        event = Some(Event::Down("the ISP renegotiated the link".into()));
                    }
                    out.push(self.lcp_request());
                }
                let Some(opts) = pppoe::options(&c.data) else {
                    return (out, None);
                };
                let (mut naks, mut rejs) = (vec![], vec![]);
                let mut auth = None;
                let mut mru = pppoe::DEFAULT_MTU;
                for (t, v) in &opts {
                    match (*t, v.len()) {
                        (pppoe::LCP_MRU, 2) => mru = u16::from_be_bytes([v[0], v[1]]),
                        (pppoe::LCP_MAGIC, 4) => {}
                        (pppoe::LCP_AUTH, _) if v.len() >= 2 => {
                            match (u16::from_be_bytes([v[0], v[1]]), v.get(2)) {
                                (pppoe::PROTO_PAP, None) => auth = Some(Auth::Pap),
                                (pppoe::PROTO_CHAP, Some(&pppoe::CHAP_MD5)) => {
                                    auth = Some(Auth::Chap)
                                }
                                // MS-CHAP, EAP...: ask for CHAP-MD5 instead.
                                _ => {
                                    naks.push((pppoe::LCP_AUTH, vec![0xc2, 0x23, pppoe::CHAP_MD5]))
                                }
                            }
                        }
                        _ => rejs.push((*t, v.clone())),
                    }
                }
                let (code, reply) = if !rejs.is_empty() {
                    (pppoe::CONF_REJ, pppoe::encode_options(&rejs))
                } else if !naks.is_empty() {
                    (pppoe::CONF_NAK, pppoe::encode_options(&naks))
                } else {
                    self.lcp_theirs = true;
                    self.peer_mru = mru.max(576);
                    self.auth = auth;
                    (pppoe::CONF_ACK, c.data.clone())
                };
                out.push(
                    self.ppp(
                        pppoe::PROTO_LCP,
                        &Control {
                            code,
                            id: c.id,
                            data: reply,
                        }
                        .encode(),
                    ),
                );
            }
            pppoe::CONF_ACK if c.id == self.lcp_id => self.lcp_ours = true,
            pppoe::CONF_NAK if c.id == self.lcp_id => {
                for (t, v) in pppoe::options(&c.data).unwrap_or_default() {
                    match t {
                        pppoe::LCP_MRU if v.len() == 2 => {
                            let m = u16::from_be_bytes([v[0], v[1]]).clamp(576, self.cfg.mtu);
                            set_opt(&mut self.lcp_opts, t, m.to_be_bytes().to_vec());
                        }
                        pppoe::LCP_MAGIC => {
                            self.magic = self.random();
                            set_opt(&mut self.lcp_opts, t, self.magic.to_be_bytes().to_vec());
                        }
                        _ => {}
                    }
                }
                out.push(self.lcp_request());
            }
            pppoe::CONF_REJ if c.id == self.lcp_id => {
                let rejected: Vec<u8> = pppoe::options(&c.data)
                    .unwrap_or_default()
                    .iter()
                    .map(|(t, _)| *t)
                    .collect();
                self.lcp_opts.retain(|(t, _)| !rejected.contains(t));
                if rejected.contains(&pppoe::LCP_MAGIC) {
                    self.magic = 0;
                }
                out.push(self.lcp_request());
            }
            pppoe::TERM_REQ => {
                out.push(
                    self.ppp(
                        pppoe::PROTO_LCP,
                        &Control {
                            code: pppoe::TERM_ACK,
                            id: c.id,
                            data: vec![],
                        }
                        .encode(),
                    ),
                );
                let (more, ev) = self.down("the ISP ended the link (LCP Terminate)", now);
                out.extend(more);
                return (out, ev);
            }
            pppoe::ECHO_REQ => {
                let mut data = self.magic.to_be_bytes().to_vec();
                data.extend_from_slice(c.data.get(4..).unwrap_or_default());
                out.push(
                    self.ppp(
                        pppoe::PROTO_LCP,
                        &Control {
                            code: pppoe::ECHO_REPLY,
                            id: c.id,
                            data,
                        }
                        .encode(),
                    ),
                );
            }
            pppoe::PROTO_REJ if c.data.get(..2) == Some(&pppoe::PROTO_IPCP.to_be_bytes()[..]) => {
                return self.down("the ISP rejected IPCP (no IPv4 service)", now);
            }
            _ => {} // Echo-Reply, Discard, Code-Reject: nothing to do
        }
        if self.phase == Phase::Lcp && self.lcp_opened() {
            out.extend(self.after_lcp(now));
        }
        (out, event)
    }

    /// Back to LCP negotiation. Returns whether the link was up.
    fn restart_lcp(&mut self, now: u64) -> bool {
        let was_up = self.link.take().is_some();
        self.lcp_ours = false;
        self.lcp_theirs = false;
        self.ipcp_ours = false;
        self.ipcp_theirs = false;
        self.enter(Phase::Lcp, now);
        self.next_tx = now + RESTART_SECS;
        was_up
    }

    /// LCP is open: authenticate if the ISP asked, then IPCP.
    fn after_lcp(&mut self, now: u64) -> Vec<Vec<u8>> {
        match self.auth {
            Some(a) => {
                self.enter(Phase::Auth, now);
                if a == Auth::Pap {
                    self.attempts = 1;
                    self.next_tx = now + RESTART_SECS;
                    vec![self.pap_request()]
                } else {
                    vec![] // the ISP sends the challenge
                }
            }
            None => self.start_ipcp(now),
        }
    }

    fn lcp_request(&mut self) -> Vec<u8> {
        self.lcp_id = self.lcp_id.wrapping_add(1);
        let c = Control {
            code: pppoe::CONF_REQ,
            id: self.lcp_id,
            data: pppoe::encode_options(&self.lcp_opts),
        };
        self.ppp(pppoe::PROTO_LCP, &c.encode())
    }

    // ------------------------------------------------------------ PAP / CHAP

    fn pap_request(&mut self) -> Vec<u8> {
        self.auth_id = self.auth_id.wrapping_add(1);
        let (u, p) = (self.cfg.username.as_bytes(), self.cfg.password.as_bytes());
        let mut data = vec![u.len() as u8];
        data.extend_from_slice(u);
        data.push(p.len() as u8);
        data.extend_from_slice(p);
        self.ppp(
            pppoe::PROTO_PAP,
            &Control {
                code: 1,
                id: self.auth_id,
                data,
            }
            .encode(),
        )
    }

    fn pap(&mut self, data: &[u8], now: u64) -> Out {
        let Some(c) = Control::parse(data) else {
            return (vec![], None);
        };
        if self.phase != Phase::Auth || c.id != self.auth_id {
            return (vec![], None);
        }
        match c.code {
            2 => {
                info!(target: PPPOE, iface = %self.cfg.interface, "PAP login accepted for {}", self.cfg.username);
                (self.start_ipcp(now), None)
            }
            3 => self.down(&format!("PAP login refused: {}", message(&c.data)), now),
            _ => (vec![], None),
        }
    }

    fn chap(&mut self, data: &[u8], now: u64) -> Out {
        use md5::{Digest, Md5};
        let Some(c) = Control::parse(data) else {
            return (vec![], None);
        };
        match c.code {
            // Challenge (also later, to re-check us): answer it.
            1 => {
                let Some(&n) = c.data.first() else {
                    return (vec![], None);
                };
                let Some(challenge) = c.data.get(1..1 + n as usize) else {
                    return (vec![], None);
                };
                debug!(target: PPPOE, iface = %self.cfg.interface, id = c.id, "CHAP challenge: answering as {}", self.cfg.username);
                let mut h = Md5::new();
                h.update([c.id]);
                h.update(self.cfg.password.as_bytes());
                h.update(challenge);
                let mut resp = vec![16u8];
                resp.extend_from_slice(&h.finalize());
                resp.extend_from_slice(self.cfg.username.as_bytes());
                (
                    vec![self.ppp(
                        pppoe::PROTO_CHAP,
                        &Control {
                            code: 2,
                            id: c.id,
                            data: resp,
                        }
                        .encode(),
                    )],
                    None,
                )
            }
            3 if self.phase == Phase::Auth => {
                info!(target: PPPOE, iface = %self.cfg.interface, "CHAP login accepted for {}", self.cfg.username);
                (self.start_ipcp(now), None)
            }
            4 => self.down(
                &format!("CHAP login refused: {}", String::from_utf8_lossy(&c.data)),
                now,
            ),
            _ => (vec![], None),
        }
    }

    // ------------------------------------------------------------ IPCP

    fn start_ipcp(&mut self, now: u64) -> Vec<Vec<u8>> {
        self.enter(Phase::Ipcp, now);
        self.ipcp_ours = false;
        self.ipcp_theirs = false;
        self.ipcp_opts = vec![
            (pppoe::IPCP_ADDRESS, vec![0; 4]),
            (pppoe::IPCP_DNS1, vec![0; 4]),
            (pppoe::IPCP_DNS2, vec![0; 4]),
        ];
        self.attempts = 1;
        self.next_tx = now + RESTART_SECS;
        vec![self.ipcp_request()]
    }

    fn ipcp_request(&mut self) -> Vec<u8> {
        self.ipcp_id = self.ipcp_id.wrapping_add(1);
        let c = Control {
            code: pppoe::CONF_REQ,
            id: self.ipcp_id,
            data: pppoe::encode_options(&self.ipcp_opts),
        };
        self.ppp(pppoe::PROTO_IPCP, &c.encode())
    }

    fn ipcp(&mut self, data: &[u8], now: u64) -> Out {
        let Some(c) = Control::parse(data) else {
            return (vec![], None);
        };
        trace!(target: PPPOE, iface = %self.cfg.interface, "IPCP {} id {} in {:?}", pppoe::code_name(c.code), c.id, self.phase);
        let mut out = vec![];
        if !matches!(self.phase, Phase::Ipcp | Phase::Up) {
            return (out, None);
        }
        match c.code {
            pppoe::CONF_REQ => {
                let opts = pppoe::options(&c.data).unwrap_or_default();
                let rejs: Vec<(u8, Vec<u8>)> = opts
                    .iter()
                    .filter(|(t, v)| !(*t == pppoe::IPCP_ADDRESS && v.len() == 4))
                    .cloned()
                    .collect();
                let (code, reply) = if rejs.is_empty() {
                    if let Some((_, v)) = opts.iter().find(|(t, _)| *t == pppoe::IPCP_ADDRESS) {
                        self.peer_ip = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
                    }
                    self.ipcp_theirs = true;
                    (pppoe::CONF_ACK, c.data.clone())
                } else {
                    (pppoe::CONF_REJ, pppoe::encode_options(&rejs))
                };
                out.push(
                    self.ppp(
                        pppoe::PROTO_IPCP,
                        &Control {
                            code,
                            id: c.id,
                            data: reply,
                        }
                        .encode(),
                    ),
                );
            }
            pppoe::CONF_NAK if c.id == self.ipcp_id => {
                for (t, v) in pppoe::options(&c.data).unwrap_or_default() {
                    if v.len() == 4 && self.ipcp_opts.iter().any(|(x, _)| *x == t) {
                        set_opt(&mut self.ipcp_opts, t, v);
                    }
                }
                out.push(self.ipcp_request());
            }
            pppoe::CONF_REJ if c.id == self.ipcp_id => {
                let rejected: Vec<u8> = pppoe::options(&c.data)
                    .unwrap_or_default()
                    .iter()
                    .map(|(t, _)| *t)
                    .collect();
                if rejected.contains(&pppoe::IPCP_ADDRESS) {
                    return self.down("the ISP won't assign an IPv4 address", now);
                }
                self.ipcp_opts.retain(|(t, _)| !rejected.contains(t));
                out.push(self.ipcp_request());
            }
            pppoe::CONF_ACK if c.id == self.ipcp_id => {
                if ip_opt(&self.ipcp_opts, pppoe::IPCP_ADDRESS).is_unspecified() {
                    out.push(self.ipcp_request()); // an ACK for 0.0.0.0 isn't an address
                } else {
                    self.ipcp_ours = true;
                }
            }
            pppoe::TERM_REQ => {
                out.push(
                    self.ppp(
                        pppoe::PROTO_IPCP,
                        &Control {
                            code: pppoe::TERM_ACK,
                            id: c.id,
                            data: vec![],
                        }
                        .encode(),
                    ),
                );
                let (more, ev) = self.down("the ISP closed IPv4 (IPCP Terminate)", now);
                out.extend(more);
                return (out, ev);
            }
            _ => {}
        }
        if self.phase == Phase::Ipcp && self.ipcp_ours && self.ipcp_theirs {
            let dns = [pppoe::IPCP_DNS1, pppoe::IPCP_DNS2]
                .iter()
                .map(|t| ip_opt(&self.ipcp_opts, *t))
                .filter(|d| !d.is_unspecified())
                .collect();
            let link = Link {
                session: self.session,
                ac_mac: self.ac,
                ac_name: self.ac_name.clone(),
                addr: ip_opt(&self.ipcp_opts, pppoe::IPCP_ADDRESS),
                peer: self.peer_ip,
                dns,
                mtu: self.cfg.mtu.min(self.peer_mru),
                up_since_unix: now,
            };
            self.phase = Phase::Up;
            self.downs = 0;
            self.last_error = None;
            self.link = Some(link.clone());
            return (out, Some(Event::Up(link)));
        }
        (out, None)
    }

    // ------------------------------------------------------------ plumbing

    fn down(&mut self, why: &str, now: u64) -> Out {
        // Once up, the service reports the session going down; failures on
        // the way up are said here.
        if self.link.is_none() {
            warn!(target: PPPOE, iface = %self.cfg.interface, "{why}; dialling again in {}s",
                (5u64 << self.downs.min(4)).min(RETRY_MAX_SECS));
        }
        let mut out = vec![];
        if self.session != 0 {
            out.push(self.padt());
        }
        let was_up = self.link.take().is_some();
        self.reset_session();
        self.last_error = Some(why.to_string());
        self.phase = Phase::Down;
        // Wait before dialling again: 5 s, doubling to a minute.
        self.next_tx = now + (5u64 << self.downs.min(4)).min(RETRY_MAX_SECS);
        self.downs += 1;
        (out, was_up.then(|| Event::Down(why.to_string())))
    }

    fn reset_session(&mut self) {
        self.session = 0;
        self.lcp_ours = false;
        self.lcp_theirs = false;
        self.ipcp_ours = false;
        self.ipcp_theirs = false;
        self.auth = None;
        self.cookie = None;
        self.relay = None;
        self.peer_mru = pppoe::DEFAULT_MTU;
        self.host_uniq = self.random().to_be_bytes();
    }

    fn padi(&self) -> Vec<u8> {
        pppoe::discovery(
            self.cfg.mac,
            eth::BROADCAST,
            pppoe::PADI,
            0,
            &[
                (pppoe::TAG_SERVICE_NAME, self.cfg.service.as_bytes()),
                (pppoe::TAG_HOST_UNIQ, &self.host_uniq),
            ],
        )
    }

    fn padr(&self) -> Vec<u8> {
        let mut tags: Vec<(u16, &[u8])> = vec![
            (pppoe::TAG_SERVICE_NAME, self.cfg.service.as_bytes()),
            (pppoe::TAG_HOST_UNIQ, &self.host_uniq),
        ];
        if let Some(c) = &self.cookie {
            tags.push((pppoe::TAG_AC_COOKIE, c));
        }
        if let Some(r) = &self.relay {
            tags.push((pppoe::TAG_RELAY_SESSION_ID, r));
        }
        pppoe::discovery(self.cfg.mac, self.ac, pppoe::PADR, 0, &tags)
    }

    fn padt(&self) -> Vec<u8> {
        pppoe::discovery(self.cfg.mac, self.ac, pppoe::PADT, self.session, &[])
    }

    fn ppp(&self, proto: u16, data: &[u8]) -> Vec<u8> {
        pppoe::session(self.cfg.mac, self.ac, self.session, proto, data)
    }
}

fn set_opt(opts: &mut [(u8, Vec<u8>)], t: u8, v: Vec<u8>) {
    if let Some(o) = opts.iter_mut().find(|(x, _)| *x == t) {
        o.1 = v;
    }
}

fn ip_opt(opts: &[(u8, Vec<u8>)], t: u8) -> Ipv4Addr {
    opts.iter()
        .find(|(x, v)| *x == t && v.len() == 4)
        .map_or(Ipv4Addr::UNSPECIFIED, |(_, v)| {
            Ipv4Addr::new(v[0], v[1], v[2], v[3])
        })
}

fn error_tag(f: &Frame) -> Option<String> {
    [
        pppoe::TAG_SERVICE_NAME_ERROR,
        pppoe::TAG_AC_SYSTEM_ERROR,
        pppoe::TAG_GENERIC_ERROR,
    ]
    .iter()
    .find_map(|t| f.tag(*t))
    .map(|v| {
        if v.is_empty() {
            "unspecified".into()
        } else {
            String::from_utf8_lossy(&v).into()
        }
    })
}

/// PAP Ack/Nak message: a length byte, then text.
fn message(d: &[u8]) -> String {
    d.get(1..1 + *d.first().unwrap_or(&0) as usize)
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "no reason given".into())
}

#[cfg(test)]
mod tests;
