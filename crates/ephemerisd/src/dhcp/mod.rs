//! DHCP: a server for inside interfaces and a client for outside ones.
//!
//! The data plane hands DHCP packets on DHCP-enabled ports to the control
//! plane (see `Pipeline::punts`). [`server`] and [`client`] are the protocol
//! logic, pure and unit-tested. The service that runs them, persists leases
//! and applies what the client learns lives in `service`.

pub mod client;
pub mod server;
#[cfg(target_os = "linux")]
pub mod service;

use client::{ClientLease, Phase};
use serde::Serialize;
use std::collections::HashMap;

/// What the DHCP service knows, for the rest of the router (the live config
/// and the API).
#[derive(Debug, Default, Clone, Serialize)]
pub struct DhcpState {
    /// The router's own DHCP clients, by interface name.
    pub clients: HashMap<String, ClientStatus>,
    /// Leases handed out, by interface name.
    pub leases: HashMap<String, Vec<server::Lease>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientStatus {
    pub phase: Phase,
    pub lease: Option<ClientLease>,
}

impl DhcpState {
    /// The leases the router's interfaces currently hold.
    pub fn client_leases(&self) -> HashMap<String, ClientLease> {
        self.clients
            .iter()
            .filter_map(|(n, c)| Some((n.clone(), c.lease.clone()?)))
            .collect()
    }

    /// DNS servers learned from the router's own leases, for LANs that
    /// don't configure their own.
    pub fn learned_dns(&self) -> Vec<std::net::Ipv4Addr> {
        let mut names: Vec<&String> = self.clients.keys().collect();
        names.sort();
        names
            .into_iter()
            .filter_map(|n| self.clients[n].lease.as_ref())
            .flat_map(|l| l.dns.iter().copied())
            .fold(vec![], |mut v, d| {
                if !v.contains(&d) {
                    v.push(d);
                }
                v
            })
    }
}
