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
    ) -> Config;
    fn with_links(&self, st: &crate::dhcp::DhcpState) -> Config;
}

impl Live for Config {
    /// This config as it applies right now: interfaces with `address =
    /// "dhcp"` get the address and gateway their lease gave them, and the
    /// first such lease with a gateway supplies the default route (unless a
    /// static one is configured). Without a lease they stay unaddressed.
    fn with_leases(
        &self,
        leases: &std::collections::HashMap<String, crate::dhcp::client::ClientLease>,
    ) -> Config {
        let mut c = self.clone();
        let static_default = self
            .routes
            .iter()
            .any(|r| r.prefix.parse::<Prefix>().is_ok_and(|p| p.len() == 0));
        let mut default_set = static_default;
        for i in &mut c.interfaces {
            let Some(l) = i.is_dhcp_client().then(|| leases.get(&i.name)).flatten() else {
                continue;
            };
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
    /// route.
    fn with_links(&self, st: &crate::dhcp::DhcpState) -> Config {
        let mut c = self.with_leases(&st.client_leases());
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
