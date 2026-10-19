//! DHCP client for an outside interface (RFC 2131 section 4.4).
//!
//! Pure logic: the caller feeds it received messages and the time, sends
//! the frames it returns, and acts on its events (apply the new address and
//! default gateway, or take them away).

use eph_packet::dhcp::{self, Message, Received};
use eph_packet::{eth, Mac};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Give up on an offer (and start over) after this many unanswered REQUESTs.
const MAX_REQUESTS: u32 = 4;
/// Retransmission backoff: 4 s, 8 s, ... capped at 64 s (RFC 2131 4.1).
const BACKOFF_MAX_SECS: u64 = 64;
/// Leases shorter than this are treated as this long (a server sending a
/// tiny lease would otherwise make us renew constantly).
const MIN_LEASE_SECS: u32 = 60;

/// A route the server handed out (RFC 3442 classless static routes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRoute {
    pub dest: Ipv4Addr,
    pub len: u8,
    /// 0.0.0.0: the destination is on this link (no router).
    pub via: Ipv4Addr,
}

/// What the server gave us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientLease {
    pub addr: Ipv4Addr,
    /// The subnet as the server gave it: /32 is common at ISPs and cloud
    /// providers, with the gateway outside it but reachable on the link.
    pub prefix_len: u8,
    /// The default gateway.
    pub router: Option<Ipv4Addr>,
    /// Other routes from the server (option 121), never the default route.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<LeaseRoute>,
    pub dns: Vec<Ipv4Addr>,
    pub server: Ipv4Addr,
    #[serde(with = "super::server::mac_text")]
    pub server_mac: Mac,
    pub obtained_unix: u64,
    pub lease_secs: u32,
    pub t1_secs: u32,
    pub t2_secs: u32,
}

impl ClientLease {
    pub fn expires_unix(&self) -> u64 {
        self.obtained_unix + self.lease_secs as u64
    }
    /// The same network settings (a renewal that changes nothing).
    fn same_settings(&self, o: &ClientLease) -> bool {
        self.addr == o.addr
            && self.prefix_len == o.prefix_len
            && self.router == o.router
            && self.routes == o.routes
            && self.dns == o.dns
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

/// Something the router must act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Use this address, subnet, gateway and DNS.
    Bound(ClientLease),
    /// The address is gone: stop using it.
    Lost,
}

pub struct Client {
    pub interface: String,
    pub mac: Mac,
    pub hostname: Option<String>,
    pub phase: Phase,
    pub lease: Option<ClientLease>,
    /// The offer being requested (REQUESTING).
    offer: Option<ClientLease>,
    xid: u32,
    rng: u32,
    attempts: u32,
    next_tx: u64,
    /// A previous address to ask for again (from before a restart).
    remembered: Option<Ipv4Addr>,
}

impl Client {
    pub fn new(
        interface: String,
        mac: Mac,
        hostname: Option<String>,
        remembered: Option<Ipv4Addr>,
        seed: u32,
    ) -> Self {
        Client {
            interface,
            mac,
            hostname,
            phase: Phase::Init,
            lease: None,
            offer: None,
            xid: 0,
            rng: seed | 1,
            attempts: 0,
            next_tx: 0,
            remembered,
        }
    }

    /// Timers. Call about once a second; returns a frame to send and/or an
    /// event.
    pub fn tick(&mut self, now: u64) -> (Option<Vec<u8>>, Option<Event>) {
        match self.phase {
            Phase::Init => {
                self.attempts = 0;
                self.new_xid();
                self.phase = Phase::Selecting;
                self.schedule(now);
                (Some(self.discover()), None)
            }
            Phase::Selecting if now >= self.next_tx => {
                self.schedule(now);
                (Some(self.discover()), None)
            }
            Phase::Requesting if now >= self.next_tx => {
                if self.attempts >= MAX_REQUESTS {
                    self.phase = Phase::Init;
                    return self.tick(now);
                }
                self.schedule(now);
                (Some(self.request_offer()), None)
            }
            Phase::Bound | Phase::Renewing | Phase::Rebinding => self.lease_timers(now),
            _ => (None, None),
        }
    }

    fn lease_timers(&mut self, now: u64) -> (Option<Vec<u8>>, Option<Event>) {
        let Some(l) = self.lease.clone() else {
            self.phase = Phase::Init;
            return (None, None);
        };
        let age = now.saturating_sub(l.obtained_unix);
        if age >= l.lease_secs as u64 {
            // Expired without a renewal: the address must not be used.
            self.lease = None;
            self.phase = Phase::Init;
            return (None, Some(Event::Lost));
        }
        let (phase, unicast) = if age >= l.t2_secs as u64 {
            (Phase::Rebinding, false)
        } else if age >= l.t1_secs as u64 {
            (Phase::Renewing, true)
        } else {
            return (None, None);
        };
        if self.phase != phase {
            self.phase = phase;
            self.new_xid();
            self.next_tx = 0;
        }
        if now < self.next_tx {
            return (None, None);
        }
        // Retry at half the remaining time to the next deadline, at least
        // every 60 s (RFC 2131 4.4.5).
        let deadline = if unicast { l.t2_secs } else { l.lease_secs } as u64;
        self.next_tx = now + (deadline.saturating_sub(age) / 2).max(60);
        (Some(self.renew(&l, unicast)), None)
    }

    /// A message from a server.
    pub fn handle(&mut self, rx: &Received, now: u64) -> (Option<Vec<u8>>, Option<Event>) {
        let m = &rx.msg;
        if m.op != dhcp::OP_REPLY || m.xid != self.xid || m.chaddr != self.mac {
            return (None, None);
        }
        match (self.phase, m.msg_type()) {
            (Phase::Selecting, Some(dhcp::OFFER)) => {
                let Some(offer) = lease_from(m, rx.src_mac, now) else {
                    return (None, None);
                };
                self.offer = Some(offer);
                self.phase = Phase::Requesting;
                self.attempts = 0;
                self.schedule(now);
                (Some(self.request_offer()), None)
            }
            (Phase::Requesting | Phase::Renewing | Phase::Rebinding, Some(dhcp::ACK)) => {
                let Some(mut new) = lease_from(m, rx.src_mac, now) else {
                    return (None, None);
                };
                // An ACK may omit the server id when renewing.
                if new.server.is_unspecified() {
                    if let Some(old) = self.lease.as_ref().or(self.offer.as_ref()) {
                        new.server = old.server;
                    }
                }
                let changed = self
                    .lease
                    .as_ref()
                    .is_none_or(|old| !old.same_settings(&new));
                self.lease = Some(new.clone());
                self.offer = None;
                self.remembered = Some(new.addr);
                self.phase = Phase::Bound;
                (None, changed.then_some(Event::Bound(new)))
            }
            (Phase::Requesting | Phase::Renewing | Phase::Rebinding, Some(dhcp::NAK)) => {
                let had = self.lease.take().is_some();
                self.offer = None;
                self.remembered = None;
                self.phase = Phase::Init;
                (None, had.then_some(Event::Lost))
            }
            _ => (None, None),
        }
    }

    /// Give the address back (on shutdown or when DHCP is turned off).
    pub fn release(&mut self) -> Option<Vec<u8>> {
        let l = self.lease.take()?;
        self.phase = Phase::Init;
        self.new_xid();
        let mut m = self.message(dhcp::RELEASE);
        m.ciaddr = l.addr;
        m.set_ip(dhcp::OPT_SERVER_ID, l.server);
        Some(dhcp::build_frame(
            self.mac,
            l.server_mac,
            (l.addr, dhcp::CLIENT_PORT),
            (l.server, dhcp::SERVER_PORT),
            &m.encode(),
        ))
    }

    fn new_xid(&mut self) {
        // xorshift32: unpredictable enough for transaction ids.
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        self.xid = x;
    }

    fn schedule(&mut self, now: u64) {
        let backoff = (4u64 << self.attempts.min(4)).min(BACKOFF_MAX_SECS);
        self.attempts += 1;
        self.next_tx = now + backoff;
    }

    fn message(&self, kind: u8) -> Message {
        let mut m = Message::new(dhcp::OP_REQUEST, self.xid, self.mac);
        m.flags = dhcp::FLAG_BROADCAST;
        m.set(dhcp::OPT_MSG_TYPE, vec![kind]);
        let mut id = vec![1u8]; // hardware type Ethernet, then the MAC
        id.extend_from_slice(&self.mac);
        m.set(dhcp::OPT_CLIENT_ID, id);
        if kind != dhcp::RELEASE {
            m.set(
                dhcp::OPT_PARAM_LIST,
                vec![
                    dhcp::OPT_SUBNET_MASK,
                    dhcp::OPT_CLASSLESS_ROUTES,
                    dhcp::OPT_ROUTER,
                    dhcp::OPT_DNS,
                    dhcp::OPT_DOMAIN,
                    dhcp::OPT_LEASE_TIME,
                    dhcp::OPT_RENEWAL_TIME,
                    dhcp::OPT_REBINDING_TIME,
                    dhcp::OPT_MS_CLASSLESS_ROUTES,
                ],
            );
            if let Some(h) = &self.hostname {
                m.set(dhcp::OPT_HOSTNAME, h.as_bytes().to_vec());
            }
        }
        m
    }

    fn broadcast(&self, m: &Message) -> Vec<u8> {
        dhcp::build_frame(
            self.mac,
            eth::BROADCAST,
            (Ipv4Addr::UNSPECIFIED, dhcp::CLIENT_PORT),
            (Ipv4Addr::BROADCAST, dhcp::SERVER_PORT),
            &m.encode(),
        )
    }

    fn discover(&self) -> Vec<u8> {
        let mut m = self.message(dhcp::DISCOVER);
        if let Some(ip) = self.remembered {
            m.set_ip(dhcp::OPT_REQUESTED_IP, ip);
        }
        self.broadcast(&m)
    }

    fn request_offer(&self) -> Vec<u8> {
        let o = self.offer.as_ref().expect("requesting an offer");
        let mut m = self.message(dhcp::REQUEST);
        m.set_ip(dhcp::OPT_REQUESTED_IP, o.addr)
            .set_ip(dhcp::OPT_SERVER_ID, o.server);
        self.broadcast(&m)
    }

    fn renew(&self, l: &ClientLease, unicast: bool) -> Vec<u8> {
        let mut m = self.message(dhcp::REQUEST);
        m.ciaddr = l.addr;
        m.flags = 0; // we have an address now: unicast replies are fine
        if unicast {
            dhcp::build_frame(
                self.mac,
                l.server_mac,
                (l.addr, dhcp::CLIENT_PORT),
                (l.server, dhcp::SERVER_PORT),
                &m.encode(),
            )
        } else {
            dhcp::build_frame(
                self.mac,
                eth::BROADCAST,
                (l.addr, dhcp::CLIENT_PORT),
                (Ipv4Addr::BROADCAST, dhcp::SERVER_PORT),
                &m.encode(),
            )
        }
    }
}

/// The lease an OFFER or ACK describes, if it's usable.
fn lease_from(m: &Message, server_mac: Mac, now: u64) -> Option<ClientLease> {
    let addr = m.yiaddr;
    if addr.is_unspecified() || addr.is_broadcast() || addr.is_loopback() || addr.is_multicast() {
        return None;
    }
    // The mask as given, /31 and /32 included (RFC 3021; ISPs and clouds
    // hand out /32s with the gateway outside, reached on the link). No or a
    // nonsensical mask: assume nothing about neighbours, /32.
    let prefix_len = m
        .prefix_len()
        .filter(|l| (8..=32).contains(l))
        .unwrap_or(32);
    let usable = |ip: Ipv4Addr| {
        !(ip.is_unspecified()
            || ip.is_broadcast()
            || ip.is_loopback()
            || ip.is_multicast()
            || ip == addr)
    };
    // RFC 3442: with classless routes, the Router option MUST be ignored;
    // their 0.0.0.0/0 entry, if any, is the default gateway.
    let classless = m
        .classless_routes(dhcp::OPT_CLASSLESS_ROUTES)
        .or_else(|| m.classless_routes(dhcp::OPT_MS_CLASSLESS_ROUTES));
    let (router, routes) = match classless {
        Some(all) => {
            let router = all
                .iter()
                .find(|(_, len, via)| *len == 0 && usable(*via))
                .map(|r| r.2);
            let routes = all
                .into_iter()
                .filter(|(dest, len, via)| {
                    *len > 0 && !dest.is_multicast() && (via.is_unspecified() || usable(*via))
                })
                .map(|(dest, len, via)| LeaseRoute { dest, len, via })
                .collect();
            (router, routes)
        }
        // The first usable address of the Router option (some servers send
        // 0.0.0.0 to mean "none").
        None => (
            m.ips(dhcp::OPT_ROUTER).into_iter().find(|r| usable(*r)),
            vec![],
        ),
    };
    let lease_secs = m
        .u32(dhcp::OPT_LEASE_TIME)
        .unwrap_or(3600)
        .max(MIN_LEASE_SECS);
    let mut t1 = m.u32(dhcp::OPT_RENEWAL_TIME).unwrap_or(lease_secs / 2);
    let mut t2 = m
        .u32(dhcp::OPT_REBINDING_TIME)
        .unwrap_or(lease_secs / 8 * 7);
    if t2 >= lease_secs || t2 == 0 {
        t2 = lease_secs / 8 * 7;
    }
    if t1 >= t2 || t1 == 0 {
        t1 = t2 / 2;
    }
    Some(ClientLease {
        addr,
        prefix_len,
        router,
        routes,
        dns: m.ips(dhcp::OPT_DNS),
        server: m.ip(dhcp::OPT_SERVER_ID).unwrap_or(Ipv4Addr::UNSPECIFIED),
        server_mac,
        obtained_unix: now,
        lease_secs,
        t1_secs: t1,
        t2_secs: t2,
    })
}

#[cfg(test)]
mod tests {
    use super::super::server::{Server, ServerCfg};
    use super::*;

    const ROUTER: Mac = [2, 0, 0, 0, 0, 1];
    const ME: Mac = [2, 0, 0, 0, 0, 9];

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// A real server (ours) on the "ISP" side, so client and server are
    /// tested against each other.
    fn isp(lease_secs: u32) -> Server {
        Server::new(
            ServerCfg {
                interface: "isp".into(),
                mac: ROUTER,
                addr: ip("203.0.113.1"),
                subnet: "203.0.113.0/24".parse().unwrap(),
                range: (ip("203.0.113.50"), ip("203.0.113.59")),
                lease_secs,
                dns: vec![ip("9.9.9.9")],
                domain: None,
                reservations: vec![],
            },
            vec![],
        )
    }

    /// Deliver a frame to the other side, as the wire would.
    fn wire(frame: Option<Vec<u8>>) -> Received {
        dhcp::parse_frame(&frame.expect("a frame")).expect("a valid frame")
    }

    fn bind(c: &mut Client, s: &mut Server, now: u64) -> ClientLease {
        let (discover, _) = c.tick(now);
        let (offer, _) = s.handle(&wire(discover), now);
        let (request, ev) = c.handle(&wire(offer), now);
        assert!(ev.is_none());
        let (ack, _) = s.handle(&wire(request), now);
        let (none, ev) = c.handle(&wire(ack), now);
        assert!(none.is_none());
        match ev {
            Some(Event::Bound(l)) => l,
            e => panic!("expected a lease, got {e:?}"),
        }
    }

    #[test]
    fn gets_an_address_gateway_and_dns() {
        let mut s = isp(3600);
        let mut c = Client::new("wan".into(), ME, Some("eph".into()), None, 1234);
        let l = bind(&mut c, &mut s, 100);
        assert_eq!(l.addr, ip("203.0.113.50"));
        assert_eq!(l.prefix_len, 24);
        assert_eq!(l.router, Some(ip("203.0.113.1")));
        assert_eq!(l.dns, vec![ip("9.9.9.9")]);
        assert_eq!((l.t1_secs, l.t2_secs), (1800, 3150));
        assert_eq!(c.phase, Phase::Bound);
        assert_eq!(s.leases[0].hostname.as_deref(), Some("eph"));
    }

    /// An ACK with these options, for `lease_from`.
    fn ack(opts: &[(u8, Vec<u8>)]) -> Message {
        let mut m = Message::new(dhcp::OP_REPLY, 1, ME);
        m.yiaddr = ip("100.64.12.34");
        m.set(dhcp::OPT_MSG_TYPE, vec![dhcp::ACK]);
        for (c, v) in opts {
            m.set(*c, v.clone());
        }
        m
    }

    #[test]
    fn a_slash_32_lease_keeps_its_mask_and_off_subnet_gateway() {
        let m = ack(&[
            (dhcp::OPT_SUBNET_MASK, vec![255, 255, 255, 255]),
            (dhcp::OPT_ROUTER, vec![100, 64, 0, 1]),
        ]);
        let l = lease_from(&m, ROUTER, 0).unwrap();
        assert_eq!(l.prefix_len, 32, "not widened to /30");
        assert_eq!(l.router, Some(ip("100.64.0.1")));
        // No mask at all: /32 too, rather than guessing a /24.
        let l = lease_from(&ack(&[(dhcp::OPT_ROUTER, vec![100, 64, 0, 1])]), ROUTER, 0).unwrap();
        assert_eq!(l.prefix_len, 32);
    }

    #[test]
    fn unusable_routers_are_skipped() {
        let m = ack(&[(dhcp::OPT_ROUTER, vec![0, 0, 0, 0, 100, 64, 0, 1])]);
        assert_eq!(
            lease_from(&m, ROUTER, 0).unwrap().router,
            Some(ip("100.64.0.1"))
        );
        let m = ack(&[(dhcp::OPT_ROUTER, vec![0, 0, 0, 0])]);
        assert_eq!(lease_from(&m, ROUTER, 0).unwrap().router, None);
    }

    #[test]
    fn classless_routes_replace_the_router_option() {
        let m = ack(&[
            (dhcp::OPT_ROUTER, vec![100, 64, 0, 99]),
            (
                dhcp::OPT_CLASSLESS_ROUTES,
                vec![
                    0, 100, 64, 0, 1, 8, 10, 100, 64, 0, 2, 32, 192, 0, 2, 1, 0, 0, 0, 0,
                ],
            ),
        ]);
        let l = lease_from(&m, ROUTER, 0).unwrap();
        assert_eq!(
            l.router,
            Some(ip("100.64.0.1")),
            "the Router option is ignored"
        );
        assert_eq!(
            l.routes,
            vec![
                LeaseRoute {
                    dest: ip("10.0.0.0"),
                    len: 8,
                    via: ip("100.64.0.2")
                },
                LeaseRoute {
                    dest: ip("192.0.2.1"),
                    len: 32,
                    via: ip("0.0.0.0")
                },
            ]
        );
    }

    #[test]
    fn renews_quietly_and_rebinds_when_the_server_is_silent() {
        let mut s = isp(3600);
        let mut c = Client::new("wan".into(), ME, None, None, 99);
        bind(&mut c, &mut s, 0);
        // Nothing to do before T1.
        assert_eq!(c.tick(1000), (None, None));
        // At T1: a unicast REQUEST to the server, which renews it. Same
        // settings, so no event (nothing to reconfigure).
        let (req, _) = c.tick(1800);
        let rx = wire(req);
        assert_eq!(rx.dst_ip, ip("203.0.113.1"));
        assert_eq!(c.phase, Phase::Renewing);
        let (ack, _) = s.handle(&rx, 1800);
        assert_eq!(c.handle(&wire(ack), 1800), (None, None));
        assert_eq!(c.phase, Phase::Bound);
        // Next time the server doesn't answer: renew, rebind (broadcast)...
        assert!(c.tick(1800 + 1800).0.is_some());
        let (rebind, _) = c.tick(1800 + 3150);
        assert_eq!(wire(rebind).dst_ip, Ipv4Addr::BROADCAST);
        assert_eq!(c.phase, Phase::Rebinding);
        // ...and at expiry the address is lost.
        assert_eq!(c.tick(1800 + 3600).1, Some(Event::Lost));
        assert_eq!(c.phase, Phase::Init);
        assert!(c.lease.is_none());
    }

    #[test]
    fn a_nak_starts_over() {
        let mut s = isp(3600);
        let mut c = Client::new("wan".into(), ME, None, None, 7);
        let l = bind(&mut c, &mut s, 0);
        // The server forgot us and someone else has our address now.
        s.leases.clear();
        s.cfg.reservations = vec![([9; 6], l.addr)];
        let (req, _) = c.tick(1800);
        let (nak, _) = s.handle(&wire(req), 1800);
        assert_eq!(c.handle(&wire(nak), 1800).1, Some(Event::Lost));
        // Starting over finds a new address.
        let again = bind(&mut c, &mut s, 1801);
        assert_ne!(again.addr, l.addr);
    }

    #[test]
    fn ignores_replies_for_other_transactions_and_retries() {
        let mut s = isp(3600);
        let mut c = Client::new("wan".into(), ME, None, None, 5);
        let (d, _) = c.tick(0);
        let (offer, _) = s.handle(&wire(d), 0);
        let mut stale = wire(offer);
        stale.msg.xid ^= 1;
        assert_eq!(c.handle(&stale, 0), (None, None));
        // No answer: DISCOVER again after the backoff, not before.
        assert!(c.tick(3).0.is_none());
        assert!(c.tick(4).0.is_some());
    }

    #[test]
    fn asks_for_its_previous_address_after_a_restart() {
        let mut s = isp(3600);
        let mut c = Client::new("wan".into(), ME, None, Some(ip("203.0.113.57")), 3);
        assert_eq!(bind(&mut c, &mut s, 0).addr, ip("203.0.113.57"));
    }
}
