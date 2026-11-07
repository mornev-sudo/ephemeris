//! The router's configuration. The model, parsing and every check live in
//! the `eph-config` crate, so anything that writes configs (a controller,
//! say) checks them exactly as the router does; what depends on the
//! running router (DHCP leases, PPPoE sessions, this machine's memory) is
//! here.

pub use eph_config::*;

use anyhow::Result;
use eph_dataplane::overlay::DEFAULT_MTU;
use eph_dataplane::{NextHop, Role};
use eph_fib::Prefix;
use std::net::Ipv4Addr;

/// The config as it applies right now, with what the outside interfaces
/// learned while running.
pub trait Live {
    fn with_leases(
        &self,
        leases: &std::collections::HashMap<String, crate::dhcp::client::ClientLease>,
    ) -> Config {
        self.with_leases_noting(leases, &mut Vec::new())
    }
    /// `with_leases`, noting in `ignored` what it left out and why.
    fn with_leases_noting(
        &self,
        leases: &std::collections::HashMap<String, crate::dhcp::client::ClientLease>,
        ignored: &mut Vec<Ignored>,
    ) -> Config;
    fn with_links(&self, st: &crate::dhcp::DhcpState) -> Config {
        self.with_links_noting(st, &mut Vec::new())
    }
    /// `with_links`, noting in `ignored` what it left out and why.
    fn with_links_noting(&self, st: &crate::dhcp::DhcpState, ignored: &mut Vec<Ignored>) -> Config;
    /// What of the current leases and sessions this config leaves out.
    fn ignored_links(&self, st: &crate::dhcp::DhcpState) -> Vec<Ignored> {
        let mut ignored = Vec::new();
        self.with_links_noting(st, &mut ignored);
        ignored
    }
}

/// Something a DHCP server or PPPoE peer handed out that the router left
/// out (see [`own_networks`]): on which interface, and what and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ignored {
    pub interface: String,
    pub what: String,
}

/// The networks this config sets itself: fixed interface subnets and the
/// SD-WAN's prefixes (other sites' and overlay routes), and with `statics`
/// static routes too (not the default route). What a DHCP server or PPPoE
/// peer hands out mustn't land inside one: as the same or a longer prefix
/// it would win the lookup, sending inside, static or SD-WAN traffic out of
/// the WAN to whoever answered there.
///
/// A lease's own subnet and gateway are only held to the first kind: a WAN
/// address inside a broad static route (an upstream router's 192.168.1.0/24
/// with 192.168.0.0/16 routed inside, say) is a plain double NAT, and
/// refusing it would cut the router off.
fn own_networks(cfg: &Config, statics: bool) -> Vec<Prefix> {
    let fixed = cfg
        .interfaces
        .iter()
        .filter(|i| !i.has_dynamic_address())
        .filter_map(|i| i.address.parse::<Prefix>().ok());
    let sites = cfg.sites.iter().flat_map(|s| &s.prefixes);
    let overlay = cfg.overlay_routes.iter().map(|r| &r.prefix);
    let routes = cfg.routes.iter().filter(|_| statics).map(|r| &r.prefix);
    fixed
        .chain(
            sites
                .chain(overlay)
                .chain(routes)
                .filter_map(|p| p.parse::<Prefix>().ok()),
        )
        .filter(|p| p.len() > 0)
        .collect()
}

/// The configured network that `p` would take over (`p` inside it), if any.
fn takes_over(own: &[Prefix], p: Prefix) -> Option<Prefix> {
    own.iter()
        .copied()
        .find(|o| o.contains(p.addr()) && p.len() >= o.len())
}

fn host(ip: Ipv4Addr) -> Prefix {
    Prefix::new(ip, 32).expect("a /32")
}

impl Live for Config {
    /// This config as it applies right now: interfaces with `address =
    /// "dhcp"` get the address and gateway their lease gave them, and the
    /// first such lease with a gateway supplies the default route (unless a
    /// static one is configured). Without a lease they stay unaddressed.
    ///
    /// A lease whose subnet or gateway lies inside one of this config's own
    /// networks is ignored, as is any server route into one or into a
    /// static route, or via a gateway inside one (see [`own_networks`]).
    fn with_leases_noting(
        &self,
        leases: &std::collections::HashMap<String, crate::dhcp::client::ClientLease>,
        ignored: &mut Vec<Ignored>,
    ) -> Config {
        let mut c = self.clone();
        let static_default = self
            .routes
            .iter()
            .any(|r| r.prefix.parse::<Prefix>().is_ok_and(|p| p.len() == 0));
        let mut default_set = static_default;
        let own = own_networks(self, false);
        let routed = own_networks(self, true);
        for i in &mut c.interfaces {
            let Some(l) = i.is_dhcp_client().then(|| leases.get(&i.name)).flatten() else {
                continue;
            };
            let Some(net) = Prefix::new(l.addr, l.prefix_len) else {
                continue;
            };
            if let Some(o) =
                takes_over(&own, net).or_else(|| l.router.and_then(|r| takes_over(&own, host(r))))
            {
                ignored.push(Ignored {
                    interface: i.name.clone(),
                    what: format!(
                        "the lease from {} ({}/{}, gateway {}): inside {o}, configured here",
                        l.server,
                        l.addr,
                        l.prefix_len,
                        l.router.map_or("none".into(), |r| r.to_string())
                    ),
                });
                continue;
            }
            i.addr_now = Some((l.addr, l.prefix_len));
            // Gateways outside the subnet (a /32 lease, say) are still on
            // this link: reachable directly, like a PPPoE link's far end.
            let subnet = Prefix::new(l.addr, l.prefix_len);
            let mut onlink = |ip: Ipv4Addr, len: u8| {
                if let Some(p) = Prefix::new(ip, len) {
                    if !subnet.is_some_and(|s| s.contains(ip) && s.len() <= len)
                        && !i.onlink.contains(&p)
                    {
                        i.onlink.push(p);
                    }
                }
            };
            if let Some(r) = l.router {
                onlink(r, 32);
            }
            // Routes from the server (option 121): on-link ones are
            // connected, the rest go via their router. A static route for
            // the same prefix wins.
            for r in &l.routes {
                let dest = Prefix::new(r.dest, r.len);
                let into = dest.and_then(|d| takes_over(&routed, d)).or_else(|| {
                    (!r.via.is_unspecified())
                        .then(|| takes_over(&own, host(r.via)))
                        .flatten()
                });
                if let Some(o) = into {
                    ignored.push(Ignored {
                        interface: i.name.clone(),
                        what: format!(
                            "the route {}/{} via {} from {}: inside {o}, configured here",
                            r.dest, r.len, r.via, l.server
                        ),
                    });
                    continue;
                }
                if r.via.is_unspecified() {
                    onlink(r.dest, r.len);
                    continue;
                }
                onlink(r.via, 32);
                let prefix = format!("{}/{}", r.dest, r.len);
                let mine =
                    |x: &RouteCfg| x.prefix.parse::<Prefix>().ok() == prefix.parse::<Prefix>().ok();
                if !self.routes.iter().any(mine) && !c.routes.iter().any(mine) {
                    c.routes.push(RouteCfg {
                        prefix,
                        via: r.via.to_string(),
                    });
                }
            }
            if let Some(r) = l.router {
                i.gateway = Some(r.to_string());
                if !default_set {
                    c.routes.push(RouteCfg {
                        prefix: "0.0.0.0/0".into(),
                        via: r.to_string(),
                    });
                    default_set = true;
                }
            }
        }
        c
    }

    /// This config as it applies right now: DHCP leases (`with_leases`) and
    /// PPPoE sessions. A session gives its interface a /32, with the ISP's
    /// end as the gateway and (if nothing else supplies one) the default
    /// route. A session whose address or far end lies inside one of this
    /// config's own networks is ignored, as leases are.
    fn with_links_noting(&self, st: &crate::dhcp::DhcpState, ignored: &mut Vec<Ignored>) -> Config {
        let mut c = self.with_leases_noting(&st.client_leases(), ignored);
        let own = own_networks(self, false);
        let mut default_set = c
            .routes
            .iter()
            .any(|r| r.prefix.parse::<Prefix>().is_ok_and(|p| p.len() == 0));
        for i in &mut c.interfaces {
            let Some(l) = i
                .is_pppoe()
                .then(|| st.pppoe.get(&i.name).and_then(|p| p.link.as_ref()))
                .flatten()
            else {
                continue;
            };
            let inside = takes_over(&own, host(l.addr)).or_else(|| {
                (!l.peer.is_unspecified())
                    .then(|| takes_over(&own, host(l.peer)))
                    .flatten()
            });
            if let Some(o) = inside {
                ignored.push(Ignored {
                    interface: i.name.clone(),
                    what: format!(
                        "the PPPoE session ({}, far end {}): inside {o}, configured here",
                        l.addr, l.peer
                    ),
                });
                continue;
            }
            i.addr_now = Some((l.addr, 32));
            i.gateway = Some(l.peer.to_string());
            i.pppoe_session = Some((l.session, l.ac_mac, l.mtu));
            if !l.peer.is_unspecified() {
                i.onlink.push(Prefix::new(l.peer, 32).expect("a /32"));
            }
            if !default_set && !l.peer.is_unspecified() {
                c.routes.push(RouteCfg {
                    prefix: "0.0.0.0/0".into(),
                    via: l.peer.to_string(),
                });
                default_set = true;
            }
        }
        c
    }
}

/// What nic-setup needs from configuration text (`ephemerisd
/// --nic-setup`): each data-plane card once, the worker count and where the
/// router's own connections go. Read from the parsed TOML, so a `device =`
/// line inside a string (a PPPoE password, say) is just text.
pub fn nic_setup(text: &str) -> Result<String> {
    let cfg: Config = toml::from_str(text)?;
    let mut out = String::new();
    let mut seen = Vec::new();
    for i in &cfg.interfaces {
        if !seen.contains(&&i.device) {
            seen.push(&i.device);
            out += &format!("device {}\n", i.device);
        }
    }
    out += &format!("workers {}\n", cfg.dataplane.workers);
    let outbound = match cfg.management.outbound {
        Outbound::Management => "management",
        Outbound::Dataplane => "dataplane",
    };
    out += &format!("outbound {outbound}\n");
    Ok(out)
}

pub fn print_summary(cfg: &Config) -> Result<()> {
    let ports = cfg.ports(|_| Ok([0; 6]))?;
    let fib = cfg.fib(&ports)?;
    println!("Configuration OK\n\nInterfaces:");
    for p in &ports {
        let role = if p.role == Role::Outside {
            "outside"
        } else {
            "inside"
        };
        let policy = if p.allow_new_sessions {
            "new sessions allowed"
        } else {
            "replies only"
        };
        let mss = p
            .mss_adjust
            .map(|m| format!(", mss adjust {m}"))
            .unwrap_or_default();
        println!(
            "  {:<10} {:<10} {:<18} {role:<8} {policy}{mss}",
            p.name,
            cfg.interfaces[p.id as usize].link_name(),
            format!("{}/{}", p.addr, p.subnet.len())
        );
    }
    let nat = cfg.nat()?;
    println!(
        "\nSource NAT: masquerade inside -> outside {}",
        if nat.masquerade { "on" } else { "off" }
    );
    for (r, rc) in nat.rules.iter().zip(&cfg.nat.rules) {
        println!(
            "  rule {:<14} from {:<18} to {:<18} out {:<8} -> {}",
            r.name,
            rc.source.as_deref().unwrap_or("any"),
            rc.destination.as_deref().unwrap_or("any"),
            rc.outbound.as_deref().unwrap_or("any"),
            match &rc.translate[..] {
                "pool" => format!("pool {}", rc.pool.as_deref().unwrap_or("?")),
                t => t.to_string(),
            }
        );
    }
    println!("\nForwarding table:");
    let overlay = cfg.overlay()?;
    for (prefix, nh) in fib.routes() {
        match *nh {
            NextHop::Ip {
                port,
                gateway: Some(gw),
            } => {
                println!(
                    "  {prefix:<18} via {gw:<15} dev {}",
                    ports[port as usize].name
                )
            }
            NextHop::Ip {
                port,
                gateway: None,
            } => {
                println!(
                    "  {prefix:<18} {:<19} dev {}",
                    "connected", ports[port as usize].name
                )
            }
            NextHop::Site(i) => println!("  {prefix:<18} overlay to site {}", overlay.sites[i]),
        }
    }
    if overlay.enabled() {
        println!(
            "\nSD-WAN: site {}, overlay MTU {}",
            overlay.site_id, overlay.mtu
        );
        if overlay.mtu > DEFAULT_MTU {
            println!(
                "  note: an overlay MTU above {DEFAULT_MTU} needs an underlay MTU of at least {}",
                overlay.mtu as usize + 60
            );
        }
        for t in &overlay.tethers {
            let key = if t.key.is_some() {
                "encrypted"
            } else {
                "NO KEY: stays down"
            };
            println!(
                "  tether {:<12} {} -> {} (site {}, {key})",
                t.name, ports[t.port as usize].name, t.remote, t.peer_site
            );
        }
        for c in overlay.classes.iter().skip(1) {
            let prefer: Vec<&str> = c
                .prefer
                .iter()
                .map(|&t| overlay.tethers[t as usize].name.as_str())
                .collect();
            println!("  class  {:<12} prefer [{}]", c.name, prefer.join(", "));
        }
    }
    let d = &cfg.dataplane;
    println!(
        "\nData plane: {} worker(s), xdp_mode={}, bind_mode={}, ring_size={}, busy_poll={}",
        d.workers, d.xdp_mode, d.bind_mode, d.ring_size, d.busy_poll
    );
    // Sized for this machine, as at start (or the defaults, elsewhere).
    let plan = crate::memory::plan(
        cfg,
        fib.memory_bytes() as u64,
        crate::memory::machine().as_ref(),
    )?;
    let sc = cfg
        .sessions
        .to_config(plan.sessions_per_worker, plan.workers);
    println!(
        "Sessions: up to {}{} per worker, tcp_strict={}, timeouts tcp={}s udp={}s/{}s icmp={}s",
        sc.max_sessions,
        if plan.auto { " (auto)" } else { "" },
        sc.tcp_strict,
        sc.timeouts.tcp_established,
        sc.timeouts.udp,
        sc.timeouts.udp_stream,
        sc.timeouts.icmp
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Config> {
        Config::parse(s)
    }

    const DHCP_CFG: &str = r#"
[[interface]]
name = "lan"
device = "ens19"
address = "10.10.1.1/24"

[interface.dhcp]
range = "10.10.1.100-10.10.1.199"
lease_secs = 3600
domain = "home.arpa"

[[interface.dhcp.reservation]]
mac = "52:54:00:12:34:56"
address = "10.10.1.10"
name = "nas"

[[interface]]
name = "wan"
device = "ens20"
address = "dhcp"
role = "outside"
"#;

    const PPPOE_CFG: &str = r#"
[[interface]]
name = "lan"
device = "ens19"
address = "10.10.1.1/24"

[[interface]]
name = "wan"
device = "ens20"
address = "pppoe"
role = "outside"

[interface.pppoe]
username = "alice@isp"
password = "s3cret"
"#;

    #[test]
    fn routes_via_a_dhcp_network_wait_for_the_lease() {
        use crate::dhcp::client::ClientLease;
        let with_route =
            format!("{DHCP_CFG}\n[[route]]\nprefix = \"192.168.77.0/24\"\nvia = \"203.0.113.9\"\n");
        // No lease yet: valid, and the route waits outside the FIB.
        let c = parse(&with_route).unwrap();
        let ports = c.ports(|_| Ok([0; 6])).unwrap();
        assert!(c
            .fib(&ports)
            .unwrap()
            .lookup("192.168.77.1".parse().unwrap())
            .is_none());
        // With a lease on that network, it's in.
        let mut leases = std::collections::HashMap::new();
        leases.insert(
            "wan".to_string(),
            ClientLease {
                addr: "203.0.113.50".parse().unwrap(),
                prefix_len: 24,
                router: None,
                routes: vec![],
                dns: vec![],
                server: "203.0.113.1".parse().unwrap(),
                server_mac: [0; 6],
                obtained_unix: 0,
                lease_secs: 3600,
                t1_secs: 1800,
                t2_secs: 3150,
            },
        );
        let e = c.with_leases(&leases);
        let fib = e.fib(&e.ports(|_| Ok([0; 6])).unwrap()).unwrap();
        assert!(fib.lookup("192.168.77.1".parse().unwrap()).is_some());
        // ...and a gateway on no network at all is still an error then.
        let bad = parse(&with_route.replace("203.0.113.9", "172.31.0.1"))
            .unwrap()
            .with_leases(&leases);
        assert!(bad.fib(&bad.ports(|_| Ok([0; 6])).unwrap()).is_err());
        // Without any DHCP interface, nothing waits: still an error.
        let static_only =
            parse(&DHCP_CFG.replace("address = \"dhcp\"", "address = \"203.0.113.50/24\""))
                .unwrap();
        let mut s2 = static_only.clone();
        s2.routes.push(RouteCfg {
            prefix: "192.168.77.0/24".into(),
            via: "172.31.0.1".into(),
        });
        assert!(s2.fib(&s2.ports(|_| Ok([0; 6])).unwrap()).is_err());
    }

    #[test]
    fn pppoe_config_and_session() {
        use crate::dhcp::{DhcpState, PppoeStatus};
        use crate::pppoe::client::{Link, Phase};
        let c = parse(PPPOE_CFG).unwrap();
        let ports = c.ports(|_| Ok([0; 6])).unwrap();
        assert_eq!(ports[1].pppoe, eph_dataplane::Pppoe::Dialing);
        assert_eq!(
            ports[1].mss_adjust,
            Some(1452),
            "MSS fits the PPPoE MTU by default"
        );
        // Session up: a /32, the ISP's end as gateway and default route.
        let mut st = DhcpState::default();
        st.pppoe.insert(
            "wan".into(),
            PppoeStatus {
                phase: Phase::Up,
                link: Some(Link {
                    session: 0x42,
                    ac_mac: [2, 0, 0, 0, 0, 0xac],
                    ac_name: "bras".into(),
                    addr: "203.0.113.50".parse().unwrap(),
                    peer: "203.0.113.1".parse().unwrap(),
                    dns: vec!["9.9.9.9".parse().unwrap()],
                    mtu: 1492,
                    up_since_unix: 0,
                }),
                last_error: None,
            },
        );
        let e = c.with_links(&st);
        assert_eq!(e.interfaces[1].address, "pppoe");
        assert_eq!(
            e.interface_addrs().unwrap()[1].0,
            "203.0.113.50".parse::<Ipv4Addr>().unwrap()
        );
        let ports = e.ports(|_| Ok([0; 6])).unwrap();
        assert_eq!(
            ports[1].pppoe,
            eph_dataplane::Pppoe::Up {
                session: 0x42,
                peer: [2, 0, 0, 0, 0, 0xac],
                mtu: 1492
            }
        );
        let fib = e.fib(&ports).unwrap();
        for dst in ["8.8.8.8", "203.0.113.1"] {
            assert!(
                matches!(
                    fib.lookup(dst.parse().unwrap()),
                    Some(NextHop::Ip { port: 1, .. })
                ),
                "{dst} out of the PPPoE link"
            );
        }
        assert_eq!(
            st.learned_dns(),
            vec!["9.9.9.9".parse::<Ipv4Addr>().unwrap()]
        );
        // The file itself is untouched by a session.
        assert_eq!(
            toml::to_string(&c).unwrap(),
            toml::to_string(&parse(PPPOE_CFG).unwrap()).unwrap()
        );
    }

    fn isp_lease(
        addr: &str,
        len: u8,
        router: Option<&str>,
        routes: Vec<crate::dhcp::client::LeaseRoute>,
    ) -> std::collections::HashMap<String, crate::dhcp::client::ClientLease> {
        let mut leases = std::collections::HashMap::new();
        leases.insert(
            "wan".to_string(),
            crate::dhcp::client::ClientLease {
                addr: addr.parse().unwrap(),
                prefix_len: len,
                router: router.map(|r| r.parse().unwrap()),
                routes,
                dns: vec![],
                server: "100.64.0.1".parse().unwrap(),
                server_mac: [0; 6],
                obtained_unix: 0,
                lease_secs: 3600,
                t1_secs: 1800,
                t2_secs: 3150,
            },
        );
        leases
    }

    /// The 0.9.0 bug: a /32 lease (gateway outside it) couldn't be applied,
    /// so the WAN kept no address and a 0.0.0.0/32 "connected" route.
    #[test]
    fn a_slash_32_lease_with_its_gateway_outside_works() {
        let c = parse(DHCP_CFG).unwrap();
        // Before the lease: the WAN contributes no route at all.
        let ports = c.ports(|_| Ok([0; 6])).unwrap();
        let fib = c.fib(&ports).unwrap();
        assert!(
            !fib.routes()
                .iter()
                .any(|(p, _)| p.addr().is_unspecified() && p.len() == 32),
            "no 0.0.0.0/32 placeholder route"
        );
        // With it: address, on-link gateway, default route through it.
        let e = c.with_leases(&isp_lease("100.64.12.34", 32, Some("100.64.0.1"), vec![]));
        let ports = e.ports(|_| Ok([0; 6])).unwrap();
        assert_eq!(ports[1].onlink, vec!["100.64.0.1/32".parse().unwrap()]);
        let fib = e.fib(&ports).expect("the lease applies");
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            fib.lookup(ip("8.8.8.8")),
            Some(&NextHop::Ip {
                port: 1,
                gateway: Some(ip("100.64.0.1"))
            })
        );
        // A gateway inside an ordinary subnet needs no extra entry.
        let e = c.with_leases(&isp_lease("203.0.113.50", 24, Some("203.0.113.1"), vec![]));
        assert!(e.ports(|_| Ok([0; 6])).unwrap()[1].onlink.is_empty());
    }

    #[test]
    fn classless_routes_from_the_lease() {
        use crate::dhcp::client::LeaseRoute;
        let c = parse(DHCP_CFG).unwrap();
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let routes = vec![
            LeaseRoute {
                dest: ip("172.16.0.0"),
                len: 12,
                via: ip("100.64.0.2"),
            },
            LeaseRoute {
                dest: ip("192.0.2.0"),
                len: 24,
                via: ip("0.0.0.0"),
            },
        ];
        let e = c.with_leases(&isp_lease("100.64.12.34", 32, Some("100.64.0.1"), routes));
        let ports = e.ports(|_| Ok([0; 6])).unwrap();
        let fib = e.fib(&ports).unwrap();
        assert_eq!(
            fib.lookup(ip("172.16.5.5")),
            Some(&NextHop::Ip {
                port: 1,
                gateway: Some(ip("100.64.0.2"))
            })
        );
        assert_eq!(
            fib.lookup(ip("192.0.2.9")),
            Some(&NextHop::Ip {
                port: 1,
                gateway: None
            }),
            "on-link: straight to the host"
        );
    }

    #[test]
    fn nic_setup_reads_the_toml_not_its_lines() {
        let text = format!(
            "{PPPOE_CFG}\n[[interface]]\nname = \"lan-b\"\ndevice = \"ens19\"\nvlan = 10\naddress = \"10.10.9.1/24\"\n\n\
             [dataplane]\nworkers = 4\n"
        )
        .replace(
            "password = \"s3cret\"",
            "password = \"\"\"\ndevice = \"ens18\"\nworkers = 9\"\"\"",
        );
        assert_eq!(
            nic_setup(&text).unwrap(),
            "device ens19\ndevice ens20\nworkers 4\noutbound management\n"
        );
        assert!(nic_setup("[[interface]\n").is_err());
    }

    /// A DHCP server on the WAN can't take over networks configured here:
    /// the LAN, a static route's gateway, a static route, the SD-WAN.
    #[test]
    fn a_lease_cant_take_over_configured_networks() {
        use crate::dhcp::client::LeaseRoute;
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let route = |d: &str, len, via: &str| LeaseRoute {
            dest: ip(d),
            len,
            via: ip(via),
        };
        let mut c = parse(&format!(
            "{DHCP_CFG}\n[[route]]\nprefix = \"10.50.0.0/16\"\nvia = \"10.10.1.254\"\n"
        ))
        .unwrap();
        c.overlay_routes.push(OverlayRouteCfg {
            prefix: "10.20.0.0/16".into(),
            site: 2,
        });
        let wan = |e: &Config| e.interfaces[1].addr_now;
        // Inside the LAN: as the lease's subnet, or its gateway.
        for lease in [
            isp_lease("10.10.1.200", 25, Some("10.10.1.129"), vec![]),
            isp_lease("100.64.12.34", 32, Some("10.10.1.254"), vec![]),
        ] {
            let e = c.with_leases(&lease);
            assert_eq!(wan(&e), None, "lease ignored");
            assert!(e.routes.iter().all(|r| r.prefix != "0.0.0.0/0"));
        }
        // Server routes into the LAN, a static route, the SD-WAN, or via a
        // LAN address: dropped; the lease and its other routes stay.
        let e = c.with_leases(&isp_lease(
            "100.64.12.34",
            32,
            Some("100.64.0.1"),
            vec![
                route("10.10.1.0", 25, "100.64.0.1"),
                route("10.10.1.0", 25, "0.0.0.0"),
                route("10.50.3.0", 24, "100.64.0.1"),
                route("10.20.0.0", 17, "100.64.0.1"),
                route("172.16.0.0", 12, "10.10.1.254"),
                route("192.0.2.0", 24, "100.64.0.2"),
            ],
        ));
        assert_eq!(wan(&e), Some((ip("100.64.12.34"), 32)));
        // Each one left out is noted, for the WAN status and the log.
        let mut ignored = vec![];
        c.with_leases_noting(
            &isp_lease(
                "100.64.12.34",
                32,
                Some("100.64.0.1"),
                vec![route("10.20.0.0", 17, "100.64.0.1")],
            ),
            &mut ignored,
        );
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].interface, "wan");
        assert!(
            ignored[0].what.contains("inside 10.20.0.0/16"),
            "{:?}",
            ignored[0]
        );
        let learned: Vec<_> = e.routes.iter().map(|r| r.prefix.as_str()).collect();
        assert_eq!(learned, ["10.50.0.0/16", "192.0.2.0/24", "0.0.0.0/0"]);
        let mut e = e;
        e.overlay_routes.clear(); // the FIB wants an [overlay] for it
        let ports = e.ports(|_| Ok([0; 6])).unwrap();
        assert!(!ports[1].onlink.iter().any(|p| p.len() < 32));
        let fib = e.fib(&ports).unwrap();
        for (dst, port) in [("10.10.1.5", 0), ("10.50.3.1", 0)] {
            assert!(
                matches!(fib.lookup(ip(dst)), Some(NextHop::Ip { port: p, .. }) if *p == port),
                "{dst}"
            );
        }
        // A broader WAN subnet than the LAN is fine: the LAN still wins.
        let e = c.with_leases(&isp_lease("10.200.0.5", 8, Some("10.200.0.1"), vec![]));
        assert_eq!(wan(&e), Some((ip("10.200.0.5"), 8)));
        // So is a double NAT inside a broad static route.
        let mut nat = c.clone();
        nat.routes[0].prefix = "192.168.0.0/16".into();
        let e = nat.with_leases(&isp_lease("192.168.1.50", 24, Some("192.168.1.1"), vec![]));
        assert_eq!(wan(&e), Some((ip("192.168.1.50"), 24)));
    }

    #[test]
    fn a_pppoe_session_inside_the_lan_is_ignored() {
        use crate::dhcp::{DhcpState, PppoeStatus};
        use crate::pppoe::client::{Link, Phase};
        let c = parse(PPPOE_CFG).unwrap();
        let mut st = DhcpState::default();
        st.pppoe.insert(
            "wan".into(),
            PppoeStatus {
                phase: Phase::Up,
                link: Some(Link {
                    session: 0x42,
                    ac_mac: [2, 0, 0, 0, 0, 0xac],
                    ac_name: "bras".into(),
                    addr: "203.0.113.50".parse().unwrap(),
                    peer: "10.10.1.254".parse().unwrap(),
                    dns: vec![],
                    mtu: 1492,
                    up_since_unix: 0,
                }),
                last_error: None,
            },
        );
        let e = c.with_links(&st);
        assert_eq!(e.interfaces[1].addr_now, None);
        assert!(e.routes.is_empty());
        let ignored = c.ignored_links(&st);
        assert_eq!(ignored.len(), 1);
        assert!(
            ignored[0].what.contains("PPPoE session"),
            "{:?}",
            ignored[0]
        );
    }

    #[test]
    fn a_lease_becomes_the_address_and_default_route() {
        use crate::dhcp::client::ClientLease;
        let c = parse(DHCP_CFG).unwrap();
        let mut leases = std::collections::HashMap::new();
        leases.insert(
            "wan".to_string(),
            ClientLease {
                addr: "203.0.113.50".parse().unwrap(),
                prefix_len: 24,
                router: Some("203.0.113.1".parse().unwrap()),
                routes: vec![],
                dns: vec![],
                server: "203.0.113.1".parse().unwrap(),
                server_mac: [0; 6],
                obtained_unix: 0,
                lease_secs: 3600,
                t1_secs: 1800,
                t2_secs: 3150,
            },
        );
        let e = c.with_leases(&leases);
        assert_eq!(e.interfaces[1].address, "dhcp", "still a DHCP interface");
        assert_eq!(
            e.interface_addrs().unwrap()[1].1.to_string(),
            "203.0.113.0/24"
        );
        assert_eq!(
            e.ports(|_| Ok([0; 6])).unwrap()[1].dhcp,
            eph_dataplane::Dhcp::Client,
            "renewals still reach the client"
        );
        assert_eq!(e.routes[0].via, "203.0.113.1");
        let ports = e.ports(|_| Ok([0; 6])).unwrap();
        assert_eq!(ports[1].gateway, Some("203.0.113.1".parse().unwrap()));
        let fib = e.fib(&ports).unwrap();
        assert!(
            fib.lookup("8.8.8.8".parse().unwrap()).is_some(),
            "default route installed"
        );
        // A static default route wins over the lease's gateway.
        let mut c2 = c.clone();
        c2.routes.push(RouteCfg {
            prefix: "0.0.0.0/0".into(),
            via: "10.10.1.254".into(),
        });
        assert_eq!(c2.with_leases(&leases).routes.len(), 1);
    }
}
