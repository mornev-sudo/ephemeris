//! The router's own DNS when its connections go out through the data plane
//! (`[management] outbound = "dataplane"`): systemd-resolved gets the DNS
//! servers learned on the outside interfaces (DHCP leases, PPPoE) for the
//! host path's link, `eph-host`, as the servers for every domain. With
//! `"management"`, that link's DNS settings are dropped again and the
//! management port's are used, as before.

use crate::config::Outbound;
use std::net::Ipv4Addr;

/// The host path's link (`host::DEVICE`, which only exists on Linux).
const LINK: &str = "eph-host";

/// Tell systemd-resolved (the learned servers changed, or the config).
pub fn apply(outbound: Outbound, learned: &[Ipv4Addr]) {
    let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let calls = match outbound {
        Outbound::Dataplane if !learned.is_empty() => {
            let mut dns = args(&["dns", LINK]);
            dns.extend(learned.iter().map(|a| a.to_string()));
            vec![
                dns,
                args(&["domain", LINK, "~."]),
                args(&["default-route", LINK, "yes"]),
            ]
        }
        _ => vec![args(&["revert", LINK])],
    };
    run(&calls, learned);
}

#[cfg(all(target_os = "linux", not(test)))]
fn run(calls: &[Vec<String>], learned: &[Ipv4Addr]) {
    use crate::logging::cat;
    for args in calls {
        let ok = std::process::Command::new("resolvectl")
            .args(args)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            tracing::warn!(target: cat::MGMT, "resolvectl {}: failed", args.join(" "));
            return;
        }
    }
    if calls.len() > 1 {
        tracing::info!(target: cat::MGMT, "the router's own DNS: {learned:?}, through the data plane");
    }
}

#[cfg(not(all(target_os = "linux", not(test))))]
fn run(_: &[Vec<String>], _: &[Ipv4Addr]) {}
