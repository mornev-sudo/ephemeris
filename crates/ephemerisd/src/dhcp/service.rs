//! The address service: one thread running every DHCP server and client,
//! and every PPPoE dialer, the configuration asks for.
//!
//! - Packets arrive from the workers (`Pipeline::punts`) and replies go out
//!   through worker 0 (`Control::Transmit`).
//! - Leases are saved in `<state dir>/dhcp/`, so hosts keep their addresses
//!   and the router asks for its own previous WAN address after a restart.
//! - When a client gets, changes or loses its lease, the new address,
//!   gateway and default route are applied live (`Shared::apply_live`).
//! - PPPoE works the same way: discovery and PPP control frames arrive
//!   here, a session coming up or going down is applied live.
//! - Configuration changes (a commit) are picked up within a second.

use super::client::{Client, Event};
use super::server::{Lease, Server, ServerCfg};
use super::{ClientStatus, PppoeStatus};
use crate::config::Config;
use crate::mgmt::Shared;
use crate::pppoe::client::{self as ppp, Client as Dialer};
use crate::report::Control;
use eph_dataplane::{PortId, Punt};
use eph_packet::{dhcp, pppoe};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub fn run(shared: &Shared, punts: Receiver<Punt>, stop: &AtomicBool, state_dir: &Path) {
    let dir = state_dir.join("dhcp");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!("DHCP: can't create {}: {e}", dir.display());
    }
    let mut svc = Service {
        shared,
        dir,
        servers: HashMap::new(),
        clients: HashMap::new(),
        dialers: HashMap::new(),
        seen: None,
        learned_dns: vec![],
        retry_apply: None,
    };
    let mut last_tick = 0;
    while !stop.load(Ordering::Relaxed) {
        match punts.recv_timeout(Duration::from_millis(500)) {
            Ok(p) => svc.packet(p),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        let now = now_unix();
        if now != last_tick {
            last_tick = now;
            svc.reconfigure();
            svc.tick(now);
        }
    }
    // Give WAN addresses back so the ISP can reuse them straight away.
    for (port, c) in svc.clients.iter_mut() {
        if let Some(f) = c.release() {
            svc.shared.transmit(*port, f);
        }
    }
    // ...and end PPPoE sessions properly (LCP Terminate, PADT).
    for (port, d) in svc.dialers.iter_mut() {
        for f in d.hang_up() {
            svc.shared.transmit(*port, f);
        }
    }
}

struct Service<'a> {
    shared: &'a Shared,
    dir: PathBuf,
    servers: HashMap<PortId, Server>,
    clients: HashMap<PortId, Client>,
    dialers: HashMap<PortId, Dialer>,
    /// The configuration the servers and clients were built from.
    seen: Option<Config>,
    /// DNS servers last handed to servers without their own.
    learned_dns: Vec<std::net::Ipv4Addr>,
    /// When to try again to apply leases / sessions that failed to apply.
    retry_apply: Option<u64>,
}

impl Service<'_> {
    fn packet(&mut self, p: Punt) {
        let now = now_unix();
        if let Some(f) = pppoe::Frame::parse(&p.frame) {
            if let Some(d) = self.dialers.get_mut(&p.port) {
                let (out, event) = d.handle(&f, now);
                for f in out {
                    self.shared.transmit(p.port, f);
                }
                self.dialer_event(p.port, event);
            }
            return;
        }
        let Some(rx) = dhcp::parse_frame(&p.frame) else {
            return;
        };
        if let Some(s) = self.servers.get_mut(&p.port) {
            let (reply, changed) = s.handle(&rx, now);
            if let Some(f) = reply {
                self.shared.transmit(p.port, f);
            }
            if changed {
                self.save_leases(p.port);
                // Show it straight away (the API reads what's published).
                self.publish();
            }
        } else if let Some(c) = self.clients.get_mut(&p.port) {
            let (send, event) = c.handle(&rx, now);
            if let Some(f) = send {
                self.shared.transmit(p.port, f);
            }
            self.client_event(p.port, event);
        }
    }

    /// Put the current leases and PPPoE sessions into effect. If that fails
    /// (say, a lease whose gateway can't be reached), say why in the status
    /// rather than only the log, and try again in 10 s.
    fn apply(&mut self, now: u64) {
        let running = self.shared.config.lock().unwrap().running().clone();
        let result = self.shared.apply_live(&running);
        let mut st = self.shared.dhcp.lock().unwrap();
        match result {
            Ok(()) => {
                if st.apply_error.take().is_some() {
                    info!("DHCP/PPPoE: addresses applied");
                }
                self.retry_apply = None;
            }
            Err(e) => {
                let e = format!("{e:#}");
                if st.apply_error.as_deref() != Some(e.as_str()) {
                    warn!("DHCP/PPPoE: can't apply the new address: {e}");
                }
                st.apply_error = Some(e);
                self.retry_apply = Some(now + 10);
            }
        }
    }

    fn tick(&mut self, now: u64) {
        if self.retry_apply.is_some_and(|t| now >= t) {
            self.apply(now);
        }
        let ports: Vec<PortId> = self.clients.keys().copied().collect();
        for port in ports {
            let c = self.clients.get_mut(&port).unwrap();
            let (send, event) = c.tick(now);
            if let Some(f) = send {
                self.shared.transmit(port, f);
            }
            self.client_event(port, event);
        }
        let ports: Vec<PortId> = self.dialers.keys().copied().collect();
        for port in ports {
            let (out, event) = self.dialers.get_mut(&port).unwrap().tick(now);
            for f in out {
                self.shared.transmit(port, f);
            }
            self.dialer_event(port, event);
        }
        let expired: Vec<PortId> = self
            .servers
            .iter_mut()
            .filter_map(|(p, s)| s.expire(now).then_some(*p))
            .collect();
        for p in expired {
            self.save_leases(p);
        }
        self.publish();
    }

    fn client_event(&mut self, port: PortId, event: Option<Event>) {
        let Some(event) = event else {
            self.publish();
            return;
        };
        let c = &self.clients[&port];
        match &event {
            Event::Bound(l) => {
                info!(
                    "DHCP: {} got {}/{} (gateway {}, lease {} s)",
                    c.interface,
                    l.addr,
                    l.prefix_len,
                    l.router.map_or("none".into(), |r| r.to_string()),
                    l.lease_secs
                );
                let _ = save_json(&self.dir.join(format!("client-{}.json", c.interface)), l);
            }
            Event::Lost => warn!("DHCP: {} lost its address", c.interface),
        }
        self.publish();
        // Apply the new address / gateway / default route to the data plane.
        self.apply(now_unix());
        // LANs that use learned DNS servers hear about new ones.
        self.seen = None;
    }

    fn dialer_event(&mut self, port: PortId, event: Option<ppp::Event>) {
        let Some(event) = event else {
            return;
        };
        let d = &self.dialers[&port];
        match &event {
            ppp::Event::Up(l) => info!(
                "PPPoE: {} connected to {} (session {:#06x}): {} peer {}, MTU {}",
                d.cfg.interface, l.ac_name, l.session, l.addr, l.peer, l.mtu
            ),
            ppp::Event::Down(why) => warn!("PPPoE: {} down: {why}", d.cfg.interface),
        }
        self.publish();
        self.apply(now_unix());
        self.seen = None; // LANs using learned DNS hear about the ISP's
    }

    /// Make the API's view (and the live config's) match ours.
    fn publish(&self) {
        let mut st = self.shared.dhcp.lock().unwrap();
        st.clients = self
            .clients
            .values()
            .map(|c| {
                (
                    c.interface.clone(),
                    ClientStatus {
                        phase: c.phase,
                        lease: c.lease.clone(),
                    },
                )
            })
            .collect();
        st.leases = self
            .servers
            .values()
            .map(|s| (s.cfg.interface.clone(), s.leases.clone()))
            .collect();
        st.pppoe = self
            .dialers
            .values()
            .map(|d| {
                (
                    d.cfg.interface.clone(),
                    PppoeStatus {
                        phase: d.phase,
                        link: d.link.clone(),
                        last_error: d.last_error.clone(),
                    },
                )
            })
            .collect();
    }

    /// Build servers and clients for the running configuration (when it,
    /// or the learned DNS servers, changed).
    fn reconfigure(&mut self) {
        let running = self.shared.config.lock().unwrap().running().clone();
        let learned = self.shared.dhcp.lock().unwrap().learned_dns();
        if self.seen.as_ref() == Some(&running) && learned == self.learned_dns {
            return;
        }
        self.learned_dns = learned;
        let ports = self.shared.ports.read().unwrap().clone();
        let mac_of = |name: &str| ports.iter().find(|p| p.name == name).map(|p| (p.id, p.mac));

        // Servers: rebuilt from the config, keeping their leases.
        let mut servers = HashMap::new();
        for (i, (addr, net)) in running
            .interfaces
            .iter()
            .zip(running.interface_addrs().unwrap_or_default())
        {
            let (Some(d), Some((port, mac))) = (&i.dhcp, mac_of(&i.name)) else {
                continue;
            };
            let Ok(r) = d.resolve(&i.name, addr, net) else {
                continue; // validated at commit; can't happen
            };
            let cfg = ServerCfg {
                interface: i.name.clone(),
                mac,
                addr,
                subnet: net,
                range: r.range,
                lease_secs: d.lease_secs,
                dns: if r.dns.is_empty() {
                    self.learned_dns.clone()
                } else {
                    r.dns
                },
                domain: d.domain.clone(),
                reservations: r.reservations,
            };
            let leases = match self.servers.remove(&port) {
                Some(old) => old.leases,
                None => {
                    info!("DHCP: serving {} on {}", d.range, i.name);
                    load_json::<Vec<Lease>>(&self.leases_file(&i.name)).unwrap_or_default()
                }
            };
            servers.insert(port, Server::new(cfg, leases));
        }
        self.servers = servers;

        // Clients: kept while the interface stays on DHCP.
        let hostname = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty());
        let mut clients = HashMap::new();
        for i in running.interfaces.iter().filter(|i| i.is_dhcp_client()) {
            let Some((port, mac)) = mac_of(&i.name) else {
                continue;
            };
            let c = match self.clients.remove(&port) {
                Some(c) => c,
                None => {
                    let remembered = load_json::<super::client::ClientLease>(
                        &self.dir.join(format!("client-{}.json", i.name)),
                    )
                    .map(|l| l.addr);
                    info!("DHCP: requesting an address on {}", i.name);
                    Client::new(i.name.clone(), mac, hostname.clone(), remembered, seed())
                }
            };
            clients.insert(port, c);
        }
        // Interfaces that stopped using DHCP give their address back.
        let mut lost = false;
        for (port, mut c) in self.clients.drain() {
            lost |= c.lease.is_some();
            if let Some(f) = c.release() {
                self.shared.transmit(port, f);
            }
        }
        self.clients = clients;

        // PPPoE dialers: kept while their settings stay the same.
        let mut dialers = HashMap::new();
        for i in running.interfaces.iter().filter(|i| i.is_pppoe()) {
            let (Some((port, mac)), Some(p)) = (mac_of(&i.name), &i.pppoe) else {
                continue;
            };
            let settings = ppp::Settings {
                interface: i.name.clone(),
                mac,
                username: p.username.clone(),
                password: p.password.clone(),
                service: p.service.clone(),
                mtu: i.ip_mtu(),
            };
            let d = match self.dialers.remove(&port) {
                Some(d) if d.cfg == settings => d,
                old => {
                    if let Some(mut old) = old {
                        lost |= old.link.is_some();
                        for f in old.hang_up() {
                            self.shared.transmit(port, f);
                        }
                    }
                    info!("PPPoE: dialling on {} as {}", i.name, p.username);
                    Dialer::new(settings, seed())
                }
            };
            dialers.insert(port, d);
        }
        for (port, mut d) in self.dialers.drain() {
            lost |= d.link.is_some();
            for f in d.hang_up() {
                self.shared.transmit(port, f);
            }
        }
        self.dialers = dialers;
        self.seen = Some(running.clone());
        self.publish();
        if lost {
            let _ = self.shared.apply_live(&running);
        }
    }

    fn leases_file(&self, iface: &str) -> PathBuf {
        self.dir.join(format!("leases-{iface}.json"))
    }

    fn save_leases(&self, port: PortId) {
        if let Some(s) = self.servers.get(&port) {
            if let Err(e) = save_json(&self.leases_file(&s.cfg.interface), &s.leases) {
                warn!("DHCP: saving leases for {}: {e}", s.cfg.interface);
            }
        }
    }
}

impl Shared {
    /// Send a frame through the data plane (worker 0).
    pub fn transmit(&self, port: PortId, frame: Vec<u8>) {
        if let Some(tx) = self.control.lock().unwrap().first() {
            let _ = tx.send(Control::Transmit { port, frame });
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn seed() -> u32 {
    let mut b = [0u8; 4];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut b)
    });
    u32::from_ne_bytes(b) ^ now_unix() as u32
}

fn load_json<T: serde::de::DeserializeOwned>(p: &Path) -> Option<T> {
    serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
}

/// Write via a temporary file and rename, so a power cut leaves the old or
/// the new file, never half of one.
fn save_json<T: serde::Serialize>(p: &Path, v: &T) -> std::io::Result<()> {
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(v)?)?;
    std::fs::rename(tmp, p)
}
