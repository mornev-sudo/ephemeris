//! DHCP server for an inside interface (RFC 2131 section 4.3).
//!
//! Pure logic: a received message in, a frame to send out. The caller
//! supplies the time and persists the leases, so this is fully testable.

use crate::logging::cat::DHCP_SERVER;
use eph_fib::Prefix;
use eph_packet::dhcp::{self, Message, Received};
use eph_packet::{eth, Mac};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use tracing::{debug, info, warn};

/// How long an offered address is held for the client that was offered it.
const OFFER_HOLD_SECS: u64 = 60;
/// An address a client declined (someone else uses it) isn't offered again
/// for this long.
const DECLINE_HOLD_SECS: u64 = 600;

/// Settings for one served interface, resolved from the config.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerCfg {
    pub interface: String,
    pub mac: Mac,
    /// The router's own address and subnet on this link.
    pub addr: Ipv4Addr,
    pub subnet: Prefix,
    /// Dynamic pool, inclusive.
    pub range: (Ipv4Addr, Ipv4Addr),
    pub lease_secs: u32,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    /// Fixed addresses for known hosts (inside the subnet, may be outside
    /// the pool).
    pub reservations: Vec<(Mac, Ipv4Addr)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseState {
    /// Offered, waiting for the client's REQUEST.
    Offered,
    Bound,
    /// Reported in use by someone else (DECLINE): not handed out for a while.
    Declined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    #[serde(with = "mac_text")]
    pub mac: Mac,
    pub ip: Ipv4Addr,
    pub expires_unix: u64,
    pub state: LeaseState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

pub struct Server {
    pub cfg: ServerCfg,
    pub leases: Vec<Lease>,
}

impl Server {
    pub fn new(cfg: ServerCfg, mut leases: Vec<Lease>) -> Self {
        // Keep only leases that still make sense for this configuration.
        leases.retain(|l| cfg.subnet.contains(l.ip) && l.ip != cfg.addr);
        Server { cfg, leases }
    }

    /// Forget expired leases. Returns true if anything changed.
    pub fn expire(&mut self, now: u64) -> bool {
        let before = self.leases.len();
        self.leases.retain(|l| l.expires_unix > now);
        self.leases.len() != before
    }

    /// Handle one message from a client. Returns the frame to send, if any,
    /// and whether the lease table changed (so it should be saved).
    pub fn handle(&mut self, rx: &Received, now: u64) -> (Option<Vec<u8>>, bool) {
        let m = &rx.msg;
        let iface = self.cfg.interface.clone();
        let iface = iface.as_str();
        let mac = eth::fmt_mac(&m.chaddr);
        // Relayed requests (giaddr) are for other subnets: not supported.
        if m.op != dhcp::OP_REQUEST || !m.giaddr.is_unspecified() {
            debug!(target: DHCP_SERVER, iface, mac, "ignored: {}",
                if m.op != dhcp::OP_REQUEST { "not a request" } else { "relayed (giaddr): relays aren't supported" });
            return (None, false);
        }
        debug!(target: DHCP_SERVER, iface, mac, hostname = m.text(dhcp::OPT_HOSTNAME).unwrap_or_default(),
            "{} (ciaddr {}, requested {})", dhcp::type_name(m.msg_type()), m.ciaddr,
            m.ip(dhcp::OPT_REQUESTED_IP).map_or("-".into(), |i| i.to_string()));
        self.expire(now);
        match m.msg_type() {
            Some(dhcp::DISCOVER) => {
                let Some(ip) = self.choose(m) else {
                    // Stay silent: another server may have room.
                    warn!(target: DHCP_SERVER, iface, mac,
                        "no free address in {}-{} for {mac}: not answering", self.cfg.range.0, self.cfg.range.1);
                    return (None, false);
                };
                debug!(target: DHCP_SERVER, iface, mac, "OFFER {ip} (held {OFFER_HOLD_SECS}s)");
                self.record(m, ip, LeaseState::Offered, now + OFFER_HOLD_SECS);
                (Some(self.reply(m, dhcp::OFFER, ip)), true)
            }
            Some(dhcp::REQUEST) => self.request(m, now),
            Some(dhcp::RELEASE) => {
                let before = self.leases.len();
                self.leases
                    .retain(|l| !(l.mac == m.chaddr && l.ip == m.ciaddr));
                info!(target: DHCP_SERVER, iface, mac, "{mac} released {}", m.ciaddr);
                (None, self.leases.len() != before)
            }
            Some(dhcp::DECLINE) => {
                let Some(ip) = m.ip(dhcp::OPT_REQUESTED_IP) else {
                    return (None, false);
                };
                // The client found the address in use (it ARPed for it):
                // a host with a static address inside the pool.
                warn!(target: DHCP_SERVER, iface, mac,
                    "{mac} declined {ip}: something else on the link uses it; not offering it for {DECLINE_HOLD_SECS}s");
                self.leases.retain(|l| l.ip != ip);
                self.leases.push(Lease {
                    mac: [0; 6],
                    ip,
                    expires_unix: now + DECLINE_HOLD_SECS,
                    state: LeaseState::Declined,
                    hostname: None,
                });
                (None, true)
            }
            Some(dhcp::INFORM) if !m.ciaddr.is_unspecified() => {
                debug!(target: DHCP_SERVER, iface, mac, "ACK (settings only) to {}", m.ciaddr);
                // Configuration only, no address (RFC 2131 4.3.5).
                (Some(self.reply(m, dhcp::ACK, Ipv4Addr::UNSPECIFIED)), false)
            }
            _ => (None, false),
        }
    }

    fn request(&mut self, m: &Message, now: u64) -> (Option<Vec<u8>>, bool) {
        let server_id = m.ip(dhcp::OPT_SERVER_ID);
        let requested = m.ip(dhcp::OPT_REQUESTED_IP);
        let ip = match (server_id, requested) {
            // SELECTING: answering an offer. Ours, or another server's?
            (Some(sid), Some(ip)) => {
                if sid != self.cfg.addr {
                    // The client chose someone else: free our offer.
                    warn!(target: DHCP_SERVER, iface = %self.cfg.interface, mac = %eth::fmt_mac(&m.chaddr),
                        "{} took an offer from another DHCP server ({sid}) on this link", eth::fmt_mac(&m.chaddr));
                    let before = self.leases.len();
                    self.leases
                        .retain(|l| !(l.mac == m.chaddr && l.state == LeaseState::Offered));
                    return (None, self.leases.len() != before);
                }
                ip
            }
            // INIT-REBOOT: a client that remembers its address.
            (None, Some(ip)) => ip,
            // RENEWING / REBINDING: the client is using ciaddr.
            (None, None) if !m.ciaddr.is_unspecified() => m.ciaddr,
            _ => return (None, false),
        };
        let mac = eth::fmt_mac(&m.chaddr);
        let iface = self.cfg.interface.clone();
        let iface = iface.as_str();
        if self.acceptable(m.chaddr, ip) {
            let renewal = self
                .leases
                .iter()
                .any(|l| l.mac == m.chaddr && l.ip == ip && l.state == LeaseState::Bound);
            let host = m.text(dhcp::OPT_HOSTNAME);
            if renewal {
                debug!(target: DHCP_SERVER, iface, mac, "ACK {ip}: renewed for {}s", self.cfg.lease_secs);
            } else {
                info!(target: DHCP_SERVER, iface, mac, "{ip} leased to {mac}{} for {}s",
                    host.map(|h| format!(" ({h})")).unwrap_or_default(), self.cfg.lease_secs);
            }
            self.record(m, ip, LeaseState::Bound, now + self.cfg.lease_secs as u64);
            (Some(self.reply(m, dhcp::ACK, ip)), true)
        } else {
            info!(target: DHCP_SERVER, iface, mac,
                "NAK: {mac} asked for {ip}, which {}", if self.in_pool(ip) { "belongs to another client" } else { "isn't ours to give" });
            // We're the only server on this link: say no, so the client
            // starts over instead of keeping a wrong address.
            (Some(self.reply(m, dhcp::NAK, Ipv4Addr::UNSPECIFIED)), false)
        }
    }

    /// May `mac` have `ip`?
    fn acceptable(&self, mac: Mac, ip: Ipv4Addr) -> bool {
        if let Some(&(_, r)) = self.cfg.reservations.iter().find(|(m, _)| *m == mac) {
            return ip == r;
        }
        if !self.in_pool(ip) || self.reserved_for_other(mac, ip) {
            return false;
        }
        self.leases.iter().all(|l| l.ip != ip || l.mac == mac)
    }

    /// An address to offer: the reservation, this client's previous
    /// address, the one it asks for, or the first free one.
    fn choose(&self, m: &Message) -> Option<Ipv4Addr> {
        if let Some(&(_, r)) = self
            .cfg
            .reservations
            .iter()
            .find(|(mac, _)| *mac == m.chaddr)
        {
            return Some(r);
        }
        if let Some(l) = self
            .leases
            .iter()
            .find(|l| l.mac == m.chaddr && l.state != LeaseState::Declined)
        {
            return Some(l.ip);
        }
        if let Some(ip) = m.ip(dhcp::OPT_REQUESTED_IP) {
            if self.acceptable(m.chaddr, ip) {
                return Some(ip);
            }
        }
        let (lo, hi) = (u32::from(self.cfg.range.0), u32::from(self.cfg.range.1));
        (lo..=hi)
            .map(Ipv4Addr::from)
            .find(|&ip| self.acceptable(m.chaddr, ip))
    }

    fn in_pool(&self, ip: Ipv4Addr) -> bool {
        let x = u32::from(ip);
        x >= u32::from(self.cfg.range.0)
            && x <= u32::from(self.cfg.range.1)
            && self.cfg.subnet.contains(ip)
            && ip != self.cfg.addr
    }

    fn reserved_for_other(&self, mac: Mac, ip: Ipv4Addr) -> bool {
        self.cfg
            .reservations
            .iter()
            .any(|(m, r)| *r == ip && *m != mac)
    }

    fn record(&mut self, m: &Message, ip: Ipv4Addr, state: LeaseState, expires: u64) {
        let hostname = m.text(dhcp::OPT_HOSTNAME).filter(|h| !h.is_empty());
        self.leases.retain(|l| l.mac != m.chaddr && l.ip != ip);
        self.leases.push(Lease {
            mac: m.chaddr,
            ip,
            expires_unix: expires,
            state,
            hostname,
        });
    }

    /// Build the reply frame, addressed per RFC 2131 4.1.
    fn reply(&self, req: &Message, kind: u8, yiaddr: Ipv4Addr) -> Vec<u8> {
        let c = &self.cfg;
        let mut r = Message::new(dhcp::OP_REPLY, req.xid, req.chaddr);
        r.flags = req.flags;
        r.yiaddr = yiaddr;
        if kind == dhcp::ACK && req.msg_type() == Some(dhcp::INFORM) {
            r.ciaddr = req.ciaddr;
        }
        r.set(dhcp::OPT_MSG_TYPE, vec![kind])
            .set_ip(dhcp::OPT_SERVER_ID, c.addr);
        if kind != dhcp::NAK {
            if kind != dhcp::ACK || req.msg_type() != Some(dhcp::INFORM) {
                r.set_u32(dhcp::OPT_LEASE_TIME, c.lease_secs)
                    .set_u32(dhcp::OPT_RENEWAL_TIME, c.lease_secs / 2)
                    .set_u32(dhcp::OPT_REBINDING_TIME, c.lease_secs / 8 * 7);
            }
            r.set_ip(dhcp::OPT_SUBNET_MASK, mask(c.subnet.len()))
                .set_ip(dhcp::OPT_ROUTER, c.addr);
            if !c.dns.is_empty() {
                r.set_ips(dhcp::OPT_DNS, &c.dns);
            }
            if let Some(d) = &c.domain {
                r.set(dhcp::OPT_DOMAIN, d.as_bytes().to_vec());
            }
        }
        let src = (c.addr, dhcp::SERVER_PORT);
        let (dst_mac, dst_ip) = if kind == dhcp::NAK {
            (eth::BROADCAST, Ipv4Addr::BROADCAST)
        } else if !req.ciaddr.is_unspecified() {
            (req.chaddr, req.ciaddr)
        } else if req.flags & dhcp::FLAG_BROADCAST != 0 {
            (eth::BROADCAST, Ipv4Addr::BROADCAST)
        } else {
            (req.chaddr, yiaddr)
        };
        dhcp::build_frame(
            c.mac,
            dst_mac,
            src,
            (dst_ip, dhcp::CLIENT_PORT),
            &r.encode(),
        )
    }
}

pub fn mask(len: u8) -> Ipv4Addr {
    Ipv4Addr::from(if len == 0 { 0 } else { u32::MAX << (32 - len) })
}

/// MAC addresses as "52:54:00:12:34:56" in the leases file.
pub mod mac_text {
    use eph_packet::{eth, Mac};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(m: &Mac, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&eth::fmt_mac(m))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Mac, D::Error> {
        let s = String::deserialize(d)?;
        eth::parse_mac(&s).ok_or_else(|| serde::de::Error::custom(format!("bad MAC {s:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTER: Mac = [2, 0, 0, 0, 0, 1];
    const A: Mac = [0x52, 0, 0, 0, 0, 0xa];
    const B: Mac = [0x52, 0, 0, 0, 0, 0xb];

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn server() -> Server {
        Server::new(
            ServerCfg {
                interface: "lan".into(),
                mac: ROUTER,
                addr: ip("10.0.0.1"),
                subnet: "10.0.0.0/24".parse().unwrap(),
                range: (ip("10.0.0.100"), ip("10.0.0.101")),
                lease_secs: 3600,
                dns: vec![ip("1.1.1.1")],
                domain: Some("home.arpa".into()),
                reservations: vec![],
            },
            vec![],
        )
    }

    fn client_msg(mac: Mac, kind: u8, f: impl FnOnce(&mut Message)) -> Received {
        let mut m = Message::new(dhcp::OP_REQUEST, 42, mac);
        m.set(dhcp::OPT_MSG_TYPE, vec![kind]);
        f(&mut m);
        Received {
            src_mac: mac,
            src_ip: m.ciaddr,
            dst_ip: Ipv4Addr::BROADCAST,
            msg: m,
        }
    }

    /// Run a reply frame back through the parser.
    fn parse(f: Option<Vec<u8>>) -> dhcp::Received {
        dhcp::parse_frame(&f.expect("a reply")).expect("a valid frame")
    }

    /// DISCOVER → OFFER → REQUEST → ACK, and what the client is told.
    fn bind(s: &mut Server, mac: Mac, now: u64) -> Ipv4Addr {
        let offer = parse(s.handle(&client_msg(mac, dhcp::DISCOVER, |_| {}), now).0);
        assert_eq!(offer.msg.msg_type(), Some(dhcp::OFFER));
        let got = offer.msg.yiaddr;
        let ack = parse(
            s.handle(
                &client_msg(mac, dhcp::REQUEST, |m| {
                    m.set_ip(dhcp::OPT_SERVER_ID, ip("10.0.0.1"))
                        .set_ip(dhcp::OPT_REQUESTED_IP, got);
                }),
                now,
            )
            .0,
        );
        assert_eq!(ack.msg.msg_type(), Some(dhcp::ACK));
        assert_eq!(ack.msg.yiaddr, got);
        assert_eq!(ack.msg.prefix_len(), Some(24));
        assert_eq!(ack.msg.ip(dhcp::OPT_ROUTER), Some(ip("10.0.0.1")));
        assert_eq!(ack.msg.ips(dhcp::OPT_DNS), vec![ip("1.1.1.1")]);
        assert_eq!(ack.msg.u32(dhcp::OPT_LEASE_TIME), Some(3600));
        got
    }

    #[test]
    fn leases_addresses_from_the_pool_and_remembers_them() {
        let mut s = server();
        let a = bind(&mut s, A, 1000);
        let b = bind(&mut s, B, 1000);
        assert_ne!(a, b);
        assert!(s.leases.iter().all(|l| l.state == LeaseState::Bound));
        // A asks again later: same address.
        assert_eq!(bind(&mut s, A, 2000), a);
        // The pool (2 addresses) is full: a third client gets no offer.
        let c = client_msg([0x52, 0, 0, 0, 0, 0xc], dhcp::DISCOVER, |_| {});
        assert!(s.handle(&c, 2000).0.is_none());
        // Once A's lease expires, the third client gets it.
        assert!(s.handle(&c, 1000 + 3600 * 2).0.is_some());
    }

    #[test]
    fn reservations_win_and_are_kept_from_others() {
        let mut s = server();
        s.cfg.reservations = vec![(B, ip("10.0.0.100"))];
        assert_eq!(
            bind(&mut s, A, 0),
            ip("10.0.0.101"),
            "the pool address B doesn't own"
        );
        assert_eq!(bind(&mut s, B, 0), ip("10.0.0.100"));
    }

    #[test]
    fn wrong_or_foreign_addresses_are_refused() {
        let mut s = server();
        let a = bind(&mut s, A, 0);
        // B claims A's address after a reboot: NAK.
        let r = parse(
            s.handle(
                &client_msg(B, dhcp::REQUEST, |m| {
                    m.set_ip(dhcp::OPT_REQUESTED_IP, a);
                }),
                0,
            )
            .0,
        );
        assert_eq!(r.msg.msg_type(), Some(dhcp::NAK));
        assert_eq!(r.dst_ip, Ipv4Addr::BROADCAST);
        // A client from another network: NAK.
        let r = parse(
            s.handle(
                &client_msg(B, dhcp::REQUEST, |m| {
                    m.set_ip(dhcp::OPT_REQUESTED_IP, ip("192.168.1.50"));
                }),
                0,
            )
            .0,
        );
        assert_eq!(r.msg.msg_type(), Some(dhcp::NAK));
    }

    #[test]
    fn renew_release_and_choosing_another_server() {
        let mut s = server();
        let a = bind(&mut s, A, 0);
        // RENEWING: unicast to the client's address.
        let r = parse(
            s.handle(&client_msg(A, dhcp::REQUEST, |m| m.ciaddr = a), 1800)
                .0,
        );
        assert_eq!(r.msg.msg_type(), Some(dhcp::ACK));
        assert_eq!(r.dst_ip, a);
        assert_eq!(s.leases[0].expires_unix, 1800 + 3600);
        // RELEASE frees it.
        let (_, changed) = s.handle(&client_msg(A, dhcp::RELEASE, |m| m.ciaddr = a), 1900);
        assert!(changed && s.leases.is_empty());
        // B is offered something but picks another server: our offer goes.
        s.handle(&client_msg(B, dhcp::DISCOVER, |_| {}), 2000);
        assert_eq!(s.leases.len(), 1);
        let (reply, _) = s.handle(
            &client_msg(B, dhcp::REQUEST, |m| {
                m.set_ip(dhcp::OPT_SERVER_ID, ip("10.0.0.254"))
                    .set_ip(dhcp::OPT_REQUESTED_IP, ip("10.0.0.50"));
            }),
            2000,
        );
        assert!(reply.is_none() && s.leases.is_empty());
    }

    #[test]
    fn declined_addresses_are_skipped() {
        let mut s = server();
        let a = bind(&mut s, A, 0);
        s.handle(
            &client_msg(A, dhcp::DECLINE, |m| {
                m.set_ip(dhcp::OPT_REQUESTED_IP, a);
            }),
            10,
        );
        // A tries again and gets the other address.
        assert_ne!(bind(&mut s, A, 20), a);
    }

    #[test]
    fn leases_survive_a_save_and_load() {
        let mut s = server();
        bind(&mut s, A, 0);
        let json = serde_json::to_string(&s.leases).unwrap();
        assert!(json.contains("52:00:00:00:00:0a"), "{json}");
        let back: Vec<Lease> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s.leases);
    }
}
