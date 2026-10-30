//! The router's configuration: the model of `ephemeris.toml`, parsing,
//! and every check a config must pass before a router will run it.
//!
//! It's a library of its own so that anything that writes configs (the
//! router's portal and API, `ephctl`, a controller managing many routers)
//! checks them with exactly the router's rules: [`Config::parse`] accepts a
//! config here if and only if a router running this version would. That
//! includes building its NAT table, forwarding table and SD-WAN overlay
//! (with [`eph_dataplane`]), which catches gateways on no subnet and the
//! like. Nothing here touches a network card or the running router.

pub mod logging;

use anyhow::{bail, Context, Result};
use eph_dataplane::nat::{NatAction, NatConfig, NatRule};
use eph_dataplane::overlay::{Class, Overlay, PeerCrypto, Tether, TetherKey, DEFAULT_MTU};
use eph_dataplane::{
    build_fib, NextHop, OverlayRoute, Port, Role, SessionConfig, StaticRoute, Timeouts,
};
use eph_fib::{Fib, Prefix};
use eph_packet::{eth, Mac};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub dataplane: DataplaneCfg,
    #[serde(default)]
    pub sessions: SessionsCfg,
    #[serde(default)]
    pub management: ManagementCfg,
    /// Log levels per category, and the log files (see `logging`).
    #[serde(default)]
    pub logging: crate::logging::LoggingCfg,
    /// SSH logins: keys only, or keys and the admin password.
    #[serde(default)]
    pub ssh: SshCfg,
    #[serde(rename = "interface")]
    pub interfaces: Vec<InterfaceCfg>,
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteCfg>,
    /// Source NAT (on by default: inside → outside is translated to the
    /// outside interface's address).
    #[serde(default)]
    pub nat: NatCfg,
    /// SD-WAN overlay (absent = plain router).
    #[serde(default)]
    pub overlay: Option<OverlayCfg>,
    /// The other routers in the SD-WAN, and how to reach them. Tethers to
    /// them are created automatically, following the sites' roles.
    #[serde(default, rename = "site")]
    pub sites: Vec<SiteCfg>,
    /// Hand-written tethers (advanced; `[[site]]` covers most setups).
    #[serde(default, rename = "tether")]
    pub tethers: Vec<TetherCfg>,
    #[serde(default, rename = "overlay_route")]
    pub overlay_routes: Vec<OverlayRouteCfg>,
    #[serde(default, rename = "class")]
    pub classes: Vec<ClassCfg>,
    /// The controller managing this router, once enrolled
    /// (docs/controller-api.md). Written by enrolment; removing it unenrols.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<ControllerCfg>,
}

/// `[controller]`: where the router's controller is, and its pinned key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerCfg {
    /// The controller's base URL: `https://` only, with no user info, query
    /// or fragment.
    pub url: String,
    /// The controller's certificate key, pinned at enrolment: `sha256:`
    /// and the SHA-256 of its SubjectPublicKeyInfo in lowercase hex.
    pub pin: String,
}

impl ControllerCfg {
    pub fn validate(&self) -> Result<()> {
        check_controller_url(&self.url)?;
        self.pin_bytes()?;
        Ok(())
    }

    /// The pinned SHA-256.
    pub fn pin_bytes(&self) -> Result<[u8; 32]> {
        let hex = self
            .pin
            .strip_prefix("sha256:")
            .context("controller.pin must start with \"sha256:\"")?;
        parse_fingerprint(hex).context("controller.pin")
    }
}

/// A controller URL: `https://host[:port][/path]`, nothing else.
pub fn check_controller_url(url: &str) -> Result<()> {
    let Some(rest) = url.strip_prefix("https://") else {
        bail!("the controller URL must start with https://");
    };
    if rest.contains(['@', '?', '#']) || rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("the controller URL must have no user info, query or fragment");
    }
    let host = rest.split('/').next().unwrap_or("");
    let name = host.rsplit_once(':').map_or(host, |(h, port)| {
        if port.parse::<u16>().is_ok_and(|p| p > 0) {
            h
        } else {
            ""
        }
    });
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
    {
        bail!("the controller URL needs a host name or IPv4 address (and an optional port)");
    }
    Ok(())
}

/// An enrolment string, `eph-enrol:v1:<url>#<token>@<fingerprint>`
/// (docs/controller-api.md): everything a router needs to enrol once.
#[derive(Clone, PartialEq, Eq)]
pub struct Enrolment {
    pub url: String,
    /// 32 random bytes in base64url without padding (43 characters).
    pub token: String,
    /// SHA-256 of the controller certificate's SubjectPublicKeyInfo.
    pub fingerprint: [u8; 32],
}

impl Enrolment {
    pub const PREFIX: &'static str = "eph-enrol:v1:";

    /// Parse it, refusing anything that isn't exactly the format.
    pub fn parse(s: &str) -> Result<Self> {
        let Some(rest) = s.trim().strip_prefix(Self::PREFIX) else {
            bail!("an enrolment string starts with {}", Self::PREFIX);
        };
        let (url, rest) = rest
            .split_once('#')
            .context("an enrolment string has a '#' before the token")?;
        let (token, fingerprint) = rest
            .split_once('@')
            .context("an enrolment string has an '@' before the fingerprint")?;
        check_controller_url(url)?;
        if token.len() != 43
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("the enrolment token must be 43 base64url characters");
        }
        let fingerprint = parse_fingerprint(fingerprint).context("the enrolment fingerprint")?;
        Ok(Enrolment {
            url: url.to_string(),
            token: token.to_string(),
            fingerprint,
        })
    }

    /// The `[controller]` section a successful enrolment writes.
    pub fn controller(&self) -> ControllerCfg {
        ControllerCfg {
            url: self.url.clone(),
            pin: format!("sha256:{}", hex(&self.fingerprint)),
        }
    }
}

impl std::fmt::Display for Enrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (url, token) = (&self.url, &self.token);
        write!(
            f,
            "{}{url}#{token}@{}",
            Self::PREFIX,
            hex(&self.fingerprint)
        )
    }
}

/// The token is a secret: never in logs or debug output.
impl std::fmt::Debug for Enrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrolment")
            .field("url", &self.url)
            .field("fingerprint", &hex(&self.fingerprint))
            .finish_non_exhaustive()
    }
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A SHA-256 fingerprint: exactly 64 lowercase hex characters.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        bail!("must be lowercase hex");
    }
    parse_hex32(s)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayCfg {
    /// This site's id; every site in the overlay needs a different one.
    pub site_id: u16,
    #[serde(default = "default_overlay_port")]
    pub udp_port: u16,
    /// Largest inner IP packet carried (underlay MTU 1500 minus 60 bytes of
    /// IPv4, UDP, header and authentication tag).
    #[serde(default = "default_overlay_mtu")]
    pub mtu: u16,
    /// May hosts at other sites start sessions to this site?
    #[serde(default = "default_true")]
    pub allow_new_sessions: bool,
    /// This router's name in the SD-WAN (what other routers call it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// This router's role: which other sites it builds tethers to.
    #[serde(default)]
    pub role: SiteRole,
    /// The cipher for session keys (sites with a public key): "auto"
    /// (AES-256-GCM when both routers have AES in hardware, else
    /// ChaCha20-Poly1305), or only "aes-256-gcm" or "chacha20-poly1305".
    #[serde(default, skip_serializing_if = "is_auto")]
    pub cipher: crate::CipherPref,
}

fn is_auto(c: &crate::CipherPref) -> bool {
    *c == crate::CipherPref::Auto
}

/// Who builds tethers to whom. Hubs connect to every site; spokes only to
/// hubs; meshes to hubs and other meshes. Sites that don't connect directly
/// reach each other through a hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteRole {
    Hub,
    Spoke,
    #[default]
    Mesh,
}

impl SiteRole {
    /// Do sites with these roles build tethers to each other?
    pub fn peers_with(self, other: SiteRole) -> bool {
        use SiteRole::*;
        matches!((self, other), (Hub, _) | (_, Hub) | (Mesh, Mesh))
    }
}

/// Another router in the SD-WAN.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteCfg {
    pub name: String,
    /// Its `[overlay] site_id`.
    pub id: u16,
    #[serde(default)]
    pub role: SiteRole,
    /// Its WAN addresses. Empty: it has none fixed (e.g. DHCP from its ISP);
    /// its address is learned when it gets in touch, so it must be the one
    /// that knows ours.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// The networks behind it, e.g. ["10.2.0.0/16"].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<String>,
    /// Without fixed addresses: how many WAN links it sends from (fibre and
    /// LTE: 2). Each gets a path of its own here, following that link's
    /// address and NAT port.
    #[serde(default = "default_links", skip_serializing_if = "is_one")]
    pub links: u8,
    /// The key this router and that site share: 64 hex characters, the same
    /// on both. Without one (and without `public_key`), no tether to it
    /// comes up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Its SD-WAN public key (64 hex characters; `ephctl sdwan identity` on
    /// that router). With one, tethers use fresh session keys from a
    /// handshake, replaced every two minutes, and `key` (optional) is mixed
    /// into the handshake. Without one, packets are sealed with `key`
    /// directly, as before 0.12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

fn default_links() -> u8 {
    1
}
fn is_one(n: &u8) -> bool {
    *n == 1
}

fn default_overlay_port() -> u16 {
    4800
}
fn default_overlay_mtu() -> u16 {
    DEFAULT_MTU
}

/// One overlay path: "reach site N over this WAN interface".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TetherCfg {
    pub name: String,
    /// The local WAN interface (by `[[interface]]` name).
    pub interface: String,
    /// The other router's address on the far end of that WAN.
    pub remote: Ipv4Addr,
    /// Underlay gateway, if `remote` isn't on the interface's own subnet.
    pub gateway: Option<Ipv4Addr>,
    /// The other router's site id.
    pub site: u16,
    /// Pre-shared key: 64 hex characters (32 random bytes, e.g. from
    /// `openssl rand -hex 32`), the same on both routers and on every tether
    /// to the same site. Without one (and without `public_key`) the tether
    /// stays down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The other router's SD-WAN public key: session keys from a handshake
    /// (see `[[site]]`). The same on every tether to the same site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayRouteCfg {
    pub prefix: String,
    pub site: u16,
}

/// An application class and its path policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassCfg {
    pub name: String,
    /// "tcp", "udp", "icmp" or a protocol number.
    pub protocol: Option<String>,
    /// Destination port or range: "443" or "10000-20000".
    pub ports: Option<String>,
    pub dscp: Option<u8>,
    /// Tether names in order of preference.
    #[serde(default)]
    pub prefer: Vec<String>,
    pub max_latency_ms: Option<u32>,
    pub max_jitter_ms: Option<u32>,
    pub max_loss_pct: Option<f32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DataplaneCfg {
    /// Worker threads. Worker N serves RX queue N of every interface.
    pub workers: u32,
    /// "auto" | "native" | "generic"
    pub xdp_mode: String,
    /// "auto" | "copy" | "zerocopy"
    pub bind_mode: String,
    /// Size of each AF_XDP ring (power of two).
    pub ring_size: u32,
    /// Spin at 100% CPU even when idle (lowest latency, DPDK style).
    pub busy_poll: bool,
    /// Optional CPU to pin each worker to, in worker order.
    pub cpus: Vec<usize>,
    /// Log a statistics line this often (0 = never; the portal and
    /// `ephctl status` show the same, without filling the journal).
    pub stats_interval_secs: u64,
    /// How many of the newest sessions to log with each statistics line.
    pub show_sessions: usize,
}

impl Default for DataplaneCfg {
    fn default() -> Self {
        DataplaneCfg {
            workers: 1,
            xdp_mode: "auto".into(),
            bind_mode: "auto".into(),
            ring_size: 2048,
            busy_poll: false,
            cpus: vec![],
            stats_interval_secs: 0,
            show_sessions: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceCfg {
    /// Friendly name used in logs, e.g. "lan-a".
    pub name: String,
    /// Linux network device, e.g. "ens19".
    pub device: String,
    /// 802.1Q VLAN ID (1-4094): this interface is the tagged traffic for
    /// that VLAN on `device`. Several interfaces can share a device, each
    /// with its own VLAN (and at most one untagged). Unset: untagged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// The router's address and prefix length on this link, e.g.
    /// "10.10.1.1/24", or "dhcp" to get it (and a default route) from a DHCP
    /// server on the link, as most ISP connections do.
    pub address: String,
    /// "inside" (your networks, the default) or "outside" (the internet).
    #[serde(default)]
    pub role: RoleCfg,
    /// The router's own services reachable on this interface's address:
    /// "https" (the portal, port 8443) and/or "ssh" (port 22). Inside
    /// interfaces only; none by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub management: Vec<String>,
    /// Only clients in these prefixes may use them (empty: anyone who can
    /// reach the address).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub management_from: Vec<String>,
    /// May traffic arriving here start new sessions? Defaults to yes on
    /// inside and no on outside interfaces (only replies get in).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_new_sessions: Option<bool>,
    /// TCP MSS adjust: lower the MSS that TCP SYNs through this interface
    /// announce to at most this value (e.g. 1452 for PPPoE). Unset: no change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mss_adjust: Option<u16>,
    /// Largest IP packet on this link, 576-1500 (default 1500; PPPoE: at
    /// most and by default 1492). Bigger packets get "fragmentation needed".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// The next router on this link towards everything else (an ISP's
    /// gateway), for a statically addressed outside interface. SD-WAN
    /// tethers leaving here use it. With `address = "dhcp"` it comes from
    /// the lease instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Serve DHCP on this interface (inside interfaces).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<DhcpServerCfg>,
    /// Dial the ISP over PPPoE (`address = "pppoe"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pppoe: Option<PppoeCfg>,
    /// The PPPoE session while it's up (filled in by `with_links`, never
    /// part of the file): session id, concentrator MAC, MTU.
    #[serde(skip)]
    pub pppoe_session: Option<(u16, Mac, u16)>,
    /// The address a DHCP lease or PPPoE session gave this interface right
    /// now (`with_links`; never in the file). `address` keeps saying
    /// "dhcp" / "pppoe", so the interface stays in that mode, e.g. DHCP
    /// renewals keep reaching the client.
    #[serde(skip)]
    pub addr_now: Option<(Ipv4Addr, u8)>,
    /// Neighbours outside the subnet (`with_links`; never in the file): a
    /// DHCP gateway outside a /32 lease, on-link routes from the DHCP
    /// server, a PPPoE link's far end.
    #[serde(skip)]
    pub onlink: Vec<Prefix>,
}

/// The largest IP packet on plain Ethernet, and the most an interface may
/// carry (bigger "jumbo" frames would need larger packet buffers).
pub const ETHERNET_MTU: u16 = 1500;

/// PPPoE login for an outside interface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PppoeCfg {
    pub username: String,
    pub password: String,
    /// Service-Name to ask for (some ISPs need one); empty: any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service: String,
    /// Older place for the link's MTU; the interface's `mtu` is preferred
    /// (and wins when both are set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
}

/// DHCP server settings for one interface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpServerCfg {
    /// Addresses to lease: "10.10.1.100-10.10.1.199".
    pub range: String,
    /// Lease time in seconds (default one day).
    #[serde(default = "default_lease_secs")]
    pub lease_secs: u32,
    /// DNS servers to hand out. Empty: the ones the router got with its own
    /// DHCP lease on an outside interface, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    /// Domain name for the hosts, e.g. "home.arpa".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Fixed addresses for known devices.
    #[serde(default, rename = "reservation", skip_serializing_if = "Vec::is_empty")]
    pub reservations: Vec<ReservationCfg>,
}

fn default_lease_secs() -> u32 {
    86400
}

/// A DHCP server section, checked and turned into addresses.
#[derive(Debug, Clone, PartialEq)]
pub struct DhcpServerResolved {
    pub range: (Ipv4Addr, Ipv4Addr),
    pub dns: Vec<Ipv4Addr>,
    pub reservations: Vec<(Mac, Ipv4Addr)>,
}

impl DhcpServerCfg {
    /// Check it against the interface's address and subnet.
    pub fn resolve(&self, iface: &str, addr: Ipv4Addr, net: Prefix) -> Result<DhcpServerResolved> {
        let ctx = |what: String| format!("interface {iface} dhcp: {what}");
        let (lo, hi) = self.range.split_once('-').with_context(|| {
            ctx(format!(
                "range {:?} must look like 10.0.0.100-10.0.0.199",
                self.range
            ))
        })?;
        let lo: Ipv4Addr = lo
            .trim()
            .parse()
            .with_context(|| ctx(format!("range start {lo:?}")))?;
        let hi: Ipv4Addr = hi
            .trim()
            .parse()
            .with_context(|| ctx(format!("range end {hi:?}")))?;
        if u32::from(lo) > u32::from(hi) {
            bail!(ctx(format!("range {lo}-{hi} goes backwards")));
        }
        for ip in [lo, hi] {
            if !net.contains(ip) || ip == net.addr() || ip == broadcast(net) {
                bail!(ctx(format!("{ip} isn't a host address on {net}")));
            }
        }
        if self.lease_secs < 120 {
            bail!(ctx("lease_secs must be at least 120".into()));
        }
        let dns = self
            .dns
            .iter()
            .map(|d| d.parse().with_context(|| ctx(format!("dns server {d:?}"))))
            .collect::<Result<Vec<Ipv4Addr>>>()?;
        if let Some(d) = &self.domain {
            if d.is_empty()
                || d.len() > 253
                || !d.split('.').all(|l| {
                    !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                bail!(ctx(format!("domain {d:?} isn't a domain name")));
            }
        }
        let mut reservations: Vec<(Mac, Ipv4Addr)> = Vec::new();
        for r in &self.reservations {
            let mac = eph_packet::eth::parse_mac(&r.mac)
                .with_context(|| ctx(format!("reservation MAC {:?}", r.mac)))?;
            let ip: Ipv4Addr = r
                .address
                .parse()
                .with_context(|| ctx(format!("reservation address {:?}", r.address)))?;
            if !net.contains(ip) || ip == addr || ip == net.addr() || ip == broadcast(net) {
                bail!(ctx(format!(
                    "reserved address {ip} isn't a free host address on {net}"
                )));
            }
            if reservations.iter().any(|&(m, i)| m == mac || i == ip) {
                bail!(ctx(format!("{} / {ip} is reserved twice", r.mac)));
            }
            reservations.push((mac, ip));
        }
        Ok(DhcpServerResolved {
            range: (lo, hi),
            dns,
            reservations,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationCfg {
    /// The device's MAC address, e.g. "52:54:00:12:34:56".
    pub mac: String,
    pub address: String,
    /// What it is (for people; not sent to the device).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoleCfg {
    #[default]
    Inside,
    Outside,
}

impl InterfaceCfg {
    /// Does this interface get its address by DHCP?
    pub fn is_dhcp_client(&self) -> bool {
        self.address.eq_ignore_ascii_case("dhcp")
    }
    /// Does this interface dial its ISP over PPPoE?
    pub fn is_pppoe(&self) -> bool {
        self.address.eq_ignore_ascii_case("pppoe")
    }
    /// The largest IP packet on this link: `mtu`, else (PPPoE) the older
    /// `pppoe.mtu`, else 1500 (PPPoE: 1492).
    pub fn ip_mtu(&self) -> u16 {
        if self.is_pppoe() {
            self.mtu
                .or(self.pppoe.as_ref().and_then(|p| p.mtu))
                .unwrap_or(eph_packet::pppoe::DEFAULT_MTU)
        } else {
            self.mtu.unwrap_or(ETHERNET_MTU)
        }
    }
    /// The link as people name it: "ens19", or "ens19.10" for VLAN 10.
    pub fn link_name(&self) -> String {
        match self.vlan {
            Some(v) => format!("{}.{v}", self.device),
            None => self.device.clone(),
        }
    }
    /// Is the address handed out by someone else (DHCP or PPPoE)?
    pub fn has_dynamic_address(&self) -> bool {
        self.is_dhcp_client() || self.is_pppoe()
    }
    pub fn role(&self) -> Role {
        match self.role {
            RoleCfg::Inside => Role::Inside,
            RoleCfg::Outside => Role::Outside,
        }
    }
    pub fn allows_new_sessions(&self) -> bool {
        self.allow_new_sessions
            .unwrap_or(self.role == RoleCfg::Inside)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NatCfg {
    /// Translate inside → outside traffic (not matched by a rule) to the
    /// outside interface's address.
    pub masquerade: bool,
    #[serde(rename = "pool", skip_serializing_if = "Vec::is_empty")]
    pub pools: Vec<NatPoolCfg>,
    #[serde(rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<NatRuleCfg>,
}

impl Default for NatCfg {
    fn default() -> Self {
        NatCfg {
            masquerade: true,
            pools: vec![],
            rules: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatPoolCfg {
    pub name: String,
    /// Addresses: "203.0.113.10", "203.0.113.16/29" or "203.0.113.10-203.0.113.20".
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatRuleCfg {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Outbound interface name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    /// "interface", "pool" or "none".
    pub translate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SessionsCfg {
    /// Session table capacity per worker thread: a number, or "auto" to
    /// size it from the memory the machine has at start (see `memory`).
    pub max_per_worker: SessionsMax,
    /// Only a TCP SYN may open a session (no mid-stream pickup).
    pub tcp_strict: bool,
    pub tcp_handshake_timeout_secs: u64,
    pub tcp_established_timeout_secs: u64,
    pub udp_timeout_secs: u64,
    pub udp_stream_timeout_secs: u64,
    pub icmp_timeout_secs: u64,
    /// TCP after a FIN (until both sides closed), and after both FINs or a
    /// reset (stray retransmits).
    pub tcp_closing_timeout_secs: u64,
    pub tcp_closed_timeout_secs: u64,
    /// Every other IP protocol (GRE, ESP, ...).
    pub other_timeout_secs: u64,
    /// Table full: drop a session that never got an answer (or a closing
    /// TCP one) to make room, instead of refusing the new session.
    pub early_drop: bool,
    /// Most sessions one address may have open at once, for the whole
    /// router (0: no limit). Split evenly between the workers, as a host's
    /// flows are.
    pub max_per_host: u32,
    /// Per-application timeouts (`[[sessions.timeout]]`), first match wins.
    #[serde(rename = "timeout", skip_serializing_if = "Vec::is_empty")]
    pub app_timeouts: Vec<AppTimeoutCfg>,
}

/// `[[sessions.timeout]]`: timeouts for sessions to some server ports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppTimeoutCfg {
    /// What it's for, e.g. "dns" (shown in the portal, nothing else).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// "tcp" or "udp".
    pub protocol: String,
    /// The server port, or a range: "53", "3478-3481".
    pub ports: String,
    /// Idle timeout once answered (TCP: established).
    pub idle_secs: u64,
    /// Idle timeout before the first answer (TCP: the handshake), if not
    /// the protocol's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unanswered_secs: Option<u64>,
}

/// `sessions.max_per_worker`: a fixed size, or sized from memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionsMax {
    #[default]
    Auto,
    Fixed(u32),
}

impl Serialize for SessionsMax {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            SessionsMax::Auto => s.serialize_str("auto"),
            SessionsMax::Fixed(n) => s.serialize_u32(*n),
        }
    }
}

/// A number, or "auto". (The portal's form sends numbers as text too.)
impl<'de> Deserialize<'de> for SessionsMax {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = SessionsMax;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a number of sessions or \"auto\"")
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<SessionsMax, E> {
                u32::try_from(v)
                    .map(SessionsMax::Fixed)
                    .map_err(|_| E::custom("too many sessions"))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<SessionsMax, E> {
                u64::try_from(v)
                    .map_err(|_| E::custom("must be at least 1"))
                    .and_then(|v| self.visit_u64(v))
            }
            /// An emptied field in the portal.
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<SessionsMax, E> {
                Ok(SessionsMax::Auto)
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<SessionsMax, E> {
                let v = v.trim();
                if v.is_empty() || v.eq_ignore_ascii_case("auto") {
                    return Ok(SessionsMax::Auto);
                }
                v.parse::<u64>()
                    .map_err(|_| E::custom("expected a number of sessions or \"auto\""))
                    .and_then(|n| self.visit_u64(n))
            }
        }
        d.deserialize_any(V)
    }
}

/// `sessions.max_per_host` unless set: far above a busy PC (a few hundred)
/// or a torrent client (a few thousand); only a runaway host gets near it.
pub const DEFAULT_MAX_PER_HOST: u32 = 50_000;

impl Default for SessionsCfg {
    fn default() -> Self {
        let s = SessionConfig::default();
        SessionsCfg {
            max_per_worker: SessionsMax::Auto,
            tcp_strict: s.tcp_strict,
            tcp_handshake_timeout_secs: s.timeouts.tcp_handshake,
            tcp_established_timeout_secs: s.timeouts.tcp_established,
            udp_timeout_secs: s.timeouts.udp,
            udp_stream_timeout_secs: s.timeouts.udp_stream,
            icmp_timeout_secs: s.timeouts.icmp,
            tcp_closing_timeout_secs: s.timeouts.tcp_closing,
            tcp_closed_timeout_secs: s.timeouts.tcp_closed,
            other_timeout_secs: s.timeouts.other,
            early_drop: s.early_drop,
            max_per_host: DEFAULT_MAX_PER_HOST,
            app_timeouts: vec![],
        }
    }
}

impl SessionsCfg {
    /// `[[sessions.timeout]]` in the data plane's form.
    pub fn app_timeouts(&self) -> Result<Vec<eph_dataplane::AppTimeout>> {
        if self.app_timeouts.len() > eph_dataplane::MAX_APP_TIMEOUTS {
            bail!(
                "at most {} [[sessions.timeout]] entries",
                eph_dataplane::MAX_APP_TIMEOUTS
            );
        }
        self.app_timeouts
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let what = || match &a.name {
                    Some(n) => format!("sessions.timeout {n:?}"),
                    None => format!("sessions.timeout #{}", i + 1),
                };
                let proto = match a.protocol.as_str() {
                    "tcp" => eph_packet::ipv4::PROTO_TCP,
                    "udp" => eph_packet::ipv4::PROTO_UDP,
                    p => bail!("{}: protocol {p:?} must be \"tcp\" or \"udp\"", what()),
                };
                let (lo, hi) = a.ports.split_once('-').unwrap_or((&a.ports, &a.ports));
                let ports = match (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                    (Ok(lo), Ok(hi)) if lo <= hi && lo > 0 => (lo, hi),
                    _ => bail!("{}: ports must be like \"53\" or \"3478-3481\"", what()),
                };
                if a.idle_secs == 0 || a.unanswered_secs == Some(0) {
                    bail!("{}: timeouts must be at least 1 second", what());
                }
                Ok(eph_dataplane::AppTimeout {
                    proto,
                    ports,
                    idle_secs: a.idle_secs.min(eph_dataplane::MAX_IDLE_SECS),
                    unanswered_secs: a
                        .unanswered_secs
                        .map(|u| u.min(eph_dataplane::MAX_IDLE_SECS)),
                })
            })
            .collect()
    }

    /// The data plane's settings, for tables of `max_sessions` in each of
    /// `workers` workers (the configured size, or what `memory::plan`
    /// worked out for "auto"). No
    /// session may sit idle for more than a day
    /// ([`eph_dataplane::MAX_IDLE_SECS`]): longer timeouts are capped.
    pub fn to_config(&self, max_sessions: u32, workers: u32) -> SessionConfig {
        let cap = |name: &str, v: u64| {
            if v > eph_dataplane::MAX_IDLE_SECS {
                tracing::warn!(target: crate::logging::cat::CONFIG,
                    "sessions.{name} = {v}: using {}, the most a session may stay idle",
                    eph_dataplane::MAX_IDLE_SECS
                );
            }
            v.min(eph_dataplane::MAX_IDLE_SECS)
        };
        SessionConfig {
            max_sessions,
            tcp_strict: self.tcp_strict,
            timeouts: Timeouts {
                tcp_handshake: cap(
                    "tcp_handshake_timeout_secs",
                    self.tcp_handshake_timeout_secs,
                ),
                tcp_established: cap(
                    "tcp_established_timeout_secs",
                    self.tcp_established_timeout_secs,
                ),
                udp: cap("udp_timeout_secs", self.udp_timeout_secs),
                udp_stream: cap("udp_stream_timeout_secs", self.udp_stream_timeout_secs),
                icmp: cap("icmp_timeout_secs", self.icmp_timeout_secs),
                tcp_closing: cap("tcp_closing_timeout_secs", self.tcp_closing_timeout_secs)
                    .min(eph_dataplane::MAX_CLOSING_SECS),
                tcp_closed: cap("tcp_closed_timeout_secs", self.tcp_closed_timeout_secs)
                    .min(eph_dataplane::MAX_CLOSING_SECS),
                other: cap("other_timeout_secs", self.other_timeout_secs),
            },
            // Checked by `validate`, so nothing is lost here.
            apps: self.app_timeouts().unwrap_or_default().into(),
            early_drop: self.early_drop,
            max_per_host: self.max_per_host.div_ceil(workers.max(1)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCfg {
    pub prefix: String,
    pub via: String,
}

/// `[ssh]` in the config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SshCfg {
    /// May the admin password be used to log in over SSH? false: keys only
    /// (refused while no key is installed). The console always takes the
    /// password.
    pub password_login: bool,
}

impl Default for SshCfg {
    fn default() -> Self {
        SshCfg {
            password_login: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ManagementCfg {
    /// Serve the REST API and web portal.
    pub enabled: bool,
    /// Where ephemerisd serves plain HTTP. On the router this stays on
    /// loopback: nginx serves the portal over HTTPS (port 8443) and passes
    /// requests on. A non-loopback address is only used with
    /// `insecure_remote_http`.
    pub listen: String,
    /// API token; generated on first start if the file doesn't exist.
    pub token_file: String,
    /// Host names the portal may be reached by, besides addresses,
    /// `localhost` and the router's own host name (requests for any other
    /// name are refused: DNS rebinding).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    /// Allow `listen` on a non-loopback address: the API (password, cookie,
    /// token) then crosses the network unencrypted. For labs only.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub insecure_remote_http: bool,
    /// Where the router's own connections go out: software updates, DNS,
    /// time. Takes effect at the next restart.
    #[serde(skip_serializing_if = "Outbound::is_default")]
    pub outbound: Outbound,
}

/// `[management] outbound`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outbound {
    /// Over the management port, as the system's own network config
    /// routes it (DHCP on it, by default).
    #[default]
    Management,
    /// Through the data plane: routed like a LAN host's traffic and
    /// source-NATed to the way out's address, so a router with no
    /// management network still updates itself (see eph_dataplane::host).
    /// The management port then only reaches its own subnet.
    Dataplane,
}

impl Outbound {
    fn is_default(&self) -> bool {
        *self == Outbound::Management
    }
}

impl ManagementCfg {
    /// The address to bind: `listen`, unless that would put plain HTTP on
    /// the network without `insecure_remote_http`; then the same port on
    /// loopback. The bool is true when that substitution happened.
    pub fn bind_addr(&self) -> (std::net::SocketAddr, bool) {
        let addr: std::net::SocketAddr = self.listen.parse().expect("validated");
        if addr.ip().is_loopback() || self.insecure_remote_http {
            (addr, false)
        } else {
            ((Ipv4Addr::LOCALHOST, addr.port()).into(), true)
        }
    }
}

impl Default for ManagementCfg {
    fn default() -> Self {
        ManagementCfg {
            enabled: true,
            listen: "127.0.0.1:8080".into(),
            token_file: "/var/lib/ephemeris/api-token".into(),
            hostnames: vec![],
            insecure_remote_http: false,
            outbound: Outbound::Management,
        }
    }
}

/// Allowed `mss_adjust` values: from the smallest MSS every IPv4 host must
/// accept (RFC 879) up to what a 1500-byte MTU carries. Anything larger would
/// never lower a real SYN's MSS.
const MSS_ADJUST_RANGE: std::ops::RangeInclusive<u16> = 536..=1460;

/// A friendly name: used in logs, routes and NAT rules.
fn valid_name(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// What Linux accepts as a network interface name (IFNAMSIZ - 1 bytes).
fn valid_ifname(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s != "."
        && s != ".."
        && !s.chars().any(|c| c == '/' || c == ':' || c.is_whitespace())
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    /// Parse and fully validate configuration text (including resolving the
    /// routes into a forwarding table), without touching the data plane.
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Can a running router switch from `self` to `new` without restarting?
    /// Addresses, policy and routes can change live; anything that shapes the
    /// sockets, threads or memory (interfaces, workers, table sizes) can't.
    pub fn live_applicable(&self, new: &Config) -> bool {
        self.dataplane == new.dataplane
            && self.sessions == new.sessions
            && self.management == new.management
            && self.overlay == new.overlay
            && self.sites == new.sites
            && self.tethers == new.tethers
            && self.classes == new.classes
            && self.interfaces.len() == new.interfaces.len()
            && self
                .interfaces
                .iter()
                .zip(&new.interfaces)
                .all(|(a, b)| a.name == b.name && a.device == b.device && a.vlan == b.vlan)
    }

    /// The network cards the interfaces use, each once, in the order they
    /// first appear. A port's `card` is its device's index here.
    pub fn cards(&self) -> Vec<&str> {
        let mut cards: Vec<&str> = Vec::new();
        for i in &self.interfaces {
            if !cards.contains(&i.device.as_str()) {
                cards.push(&i.device);
            }
        }
        cards
    }

    fn validate(&self) -> Result<()> {
        if let Some(c) = &self.controller {
            c.validate()?;
        }
        let d = &self.dataplane;
        if d.workers == 0 {
            bail!("dataplane.workers must be at least 1");
        }
        if !d.ring_size.is_power_of_two() || !(64..=16384).contains(&d.ring_size) {
            bail!("dataplane.ring_size must be a power of two between 64 and 16384");
        }
        if d.workers > 256 {
            bail!("dataplane.workers must be at most 256");
        }
        if !d.cpus.is_empty() && d.cpus.len() != d.workers as usize {
            bail!("dataplane.cpus must list exactly one CPU per worker");
        }
        if let Some(c) = d.cpus.iter().find(|&&c| c >= 1024) {
            bail!("dataplane.cpus: CPU {c} doesn't exist (CPUs are numbered from 0, below 1024)");
        }
        if let SessionsMax::Fixed(n) = self.sessions.max_per_worker {
            if n == 0 || n > crate::SESSIONS_MAX {
                bail!(
                    "sessions.max_per_worker must be between 1 and {}, or \"auto\"",
                    crate::SESSIONS_MAX
                );
            }
        }
        // Timeouts above a day are capped when applied (`to_config`), not
        // refused: a config saved by an older release must still start.
        let s = &self.sessions;
        for (name, v) in [
            ("tcp_handshake_timeout_secs", s.tcp_handshake_timeout_secs),
            (
                "tcp_established_timeout_secs",
                s.tcp_established_timeout_secs,
            ),
            ("udp_timeout_secs", s.udp_timeout_secs),
            ("udp_stream_timeout_secs", s.udp_stream_timeout_secs),
            ("icmp_timeout_secs", s.icmp_timeout_secs),
            ("tcp_closing_timeout_secs", s.tcp_closing_timeout_secs),
            ("tcp_closed_timeout_secs", s.tcp_closed_timeout_secs),
            ("other_timeout_secs", s.other_timeout_secs),
        ] {
            if v == 0 {
                bail!("sessions.{name} must be at least 1");
            }
        }
        self.sessions.app_timeouts()?;
        if self.management.enabled {
            self.management
                .listen
                .parse::<std::net::SocketAddr>()
                .with_context(|| format!("management.listen {:?}", self.management.listen))?;
        }
        for h in &self.management.hostnames {
            let label_ok = |l: &str| {
                (1..=63).contains(&l.len())
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            };
            if h.len() > 253 || !h.split('.').all(label_ok) {
                bail!("management.hostnames: {h:?} isn't a host name");
            }
        }
        self.logging.validate()?;
        if self.interfaces.is_empty() {
            bail!("at least one [[interface]] is required");
        }
        for (n, i) in self.interfaces.iter().enumerate() {
            let which = if i.name.is_empty() {
                format!("interface #{}", n + 1)
            } else {
                format!("interface {}", i.name)
            };
            if !valid_name(&i.name) {
                bail!(
                    "{which}: needs a name (letters, digits, '-', '_' or '.', up to 32 characters)"
                );
            }
            if i.device.is_empty() {
                bail!("{which}: choose the network card (device) it uses");
            }
            if !valid_ifname(&i.device) {
                bail!(
                    "{which}: {:?} isn't a valid Linux interface name (e.g. ens19)",
                    i.device
                );
            }
            if let Some(v) = i.vlan {
                if !(1..=eth::VLAN_ID_MAX).contains(&v) {
                    bail!("{which}: vlan must be between 1 and {}", eth::VLAN_ID_MAX);
                }
            }
            for m in &i.management {
                if !["https", "ssh"].contains(&m.as_str()) {
                    bail!(
                        "{which}: management {m:?}: choose \"https\" (the portal) and/or \"ssh\""
                    );
                }
            }
            // The router's own SSH and portal are never offered to the
            // internet (the data plane refuses them there as well).
            if !i.management.is_empty() && i.role == RoleCfg::Outside {
                bail!(
                    "{which}: SSH and the portal can only be reached on inside interfaces, not on an outside one"
                );
            }
            if !i.management_from.is_empty() && i.management.is_empty() {
                bail!("{which}: management_from without management (\"https\", \"ssh\") has no effect");
            }
            for p in &i.management_from {
                p.parse::<Prefix>()
                    .map_err(|e| anyhow::anyhow!("{which}: management_from {p:?}: {e}"))?;
            }
            if let Some(mss) = i.mss_adjust {
                if !MSS_ADJUST_RANGE.contains(&mss) {
                    bail!(
                        "{which}: mss_adjust must be between {} and {} (MTU minus 40)",
                        MSS_ADJUST_RANGE.start(),
                        MSS_ADJUST_RANGE.end()
                    );
                }
            }
        }
        let addrs = self.interface_addrs()?;
        for (i, a) in self.interfaces.iter().enumerate() {
            for b in &self.interfaces[i + 1..] {
                if a.device == b.device && a.vlan == b.vlan {
                    match a.vlan {
                        Some(v) => bail!(
                            "interfaces {} and {} are both VLAN {v} on {}",
                            a.name,
                            b.name,
                            a.device
                        ),
                        None => bail!(
                            "interfaces {} and {} both use {} untagged (give one of them a vlan)",
                            a.name,
                            b.name,
                            a.device
                        ),
                    }
                }
                if a.name == b.name {
                    bail!("two interfaces are named {}", a.name);
                }
            }
            if !(576..=ETHERNET_MTU).contains(&a.ip_mtu()) {
                bail!(
                    "interface {}: mtu must be between 576 and {ETHERNET_MTU}",
                    a.name
                );
            }
            if a.is_pppoe() {
                let Some(p) = &a.pppoe else {
                    bail!("interface {}: address = \"pppoe\" needs an [interface.pppoe] section (username, password)", a.name);
                };
                if p.username.is_empty() {
                    bail!("interface {}: PPPoE needs a username", a.name);
                }
                if !(576..=eph_packet::pppoe::DEFAULT_MTU).contains(&a.ip_mtu()) {
                    bail!(
                        "interface {}: mtu over PPPoE must be between 576 and 1492",
                        a.name
                    );
                }
                if a.role != RoleCfg::Outside {
                    bail!(
                        "interface {}: PPPoE is for outside interfaces (role = \"outside\")",
                        a.name
                    );
                }
                if a.dhcp.is_some() || a.gateway.is_some() {
                    bail!("interface {}: a PPPoE interface can't serve DHCP or set a gateway (the ISP's end is the gateway)", a.name);
                }
                continue;
            } else if a.pppoe.is_some() {
                bail!(
                    "interface {}: [interface.pppoe] only applies with address = \"pppoe\"",
                    a.name
                );
            }
            if a.is_dhcp_client() {
                if a.dhcp.is_some() {
                    bail!(
                        "interface {}: can't both get its address by DHCP and serve DHCP",
                        a.name
                    );
                }
                if a.gateway.is_some() {
                    bail!(
                        "interface {}: the gateway comes from DHCP; remove `gateway`",
                        a.name
                    );
                }
                continue; // no address to check until a lease arrives
            }
            let (ip, net) = addrs[i];
            if let Some(g) = &a.gateway {
                let g: Ipv4Addr = g
                    .parse()
                    .with_context(|| format!("interface {}: gateway {g:?}", a.name))?;
                if !net.contains(g) || g == ip {
                    bail!(
                        "interface {}: gateway {g} isn't another address on {net}",
                        a.name
                    );
                }
            }
            if let Some(d) = &a.dhcp {
                d.resolve(&a.name, ip, net)?;
            }
            if net.len() < 31 && (ip == net.addr() || ip == broadcast(net)) {
                bail!(
                    "interface {}: {ip} is the network or broadcast address of {net}",
                    a.name
                );
            }
            for (j, &(_, other)) in addrs.iter().enumerate().skip(i + 1) {
                if self.interfaces[j].has_dynamic_address() {
                    continue;
                }
                if net.contains(other.addr()) || other.contains(net.addr()) {
                    bail!(
                        "interfaces {} and {} have overlapping subnets",
                        a.name,
                        self.interfaces[j].name
                    );
                }
            }
        }
        self.nat()?;
        // Resolving the routes catches gateways that aren't on any subnet.
        self.fib(&self.ports(|_| Ok([0; 6]))?)?;
        Ok(())
    }

    pub fn interface_addrs(&self) -> Result<Vec<(Ipv4Addr, Prefix)>> {
        self.interfaces
            .iter()
            .map(|i| {
                if i.has_dynamic_address() {
                    // The lease's / session's address (see `with_links`),
                    // or none yet.
                    if let Some((ip, len)) = i.addr_now {
                        let net = Prefix::new(ip, len).context("bad prefix length")?;
                        return Ok((ip, net));
                    }
                    return Ok((
                        Ipv4Addr::UNSPECIFIED,
                        Prefix::new(Ipv4Addr::UNSPECIFIED, 32).unwrap(),
                    ));
                }
                let (ip, len) = i.address.split_once('/').with_context(|| {
                    format!(
                        "interface {}: address must look like 10.0.0.1/24 (or be \"dhcp\")",
                        i.name
                    )
                })?;
                let ip: Ipv4Addr = ip
                    .parse()
                    .with_context(|| format!("interface {}", i.name))?;
                let len: u8 = len
                    .parse()
                    .with_context(|| format!("interface {}", i.name))?;
                let net = Prefix::new(ip, len)
                    .with_context(|| format!("interface {}: bad prefix length", i.name))?;
                Ok((ip, net))
            })
            .collect()
    }

    pub fn static_routes(&self) -> Result<Vec<StaticRoute>> {
        self.routes
            .iter()
            .map(|r| {
                Ok(StaticRoute {
                    prefix: r.prefix.parse().map_err(anyhow::Error::msg)?,
                    via: r
                        .via
                        .parse()
                        .with_context(|| format!("route {}: bad gateway", r.prefix))?,
                })
            })
            .collect()
    }

    /// Build the port table; `mac_of` supplies each device's MAC address.
    pub fn ports(&self, mut mac_of: impl FnMut(&InterfaceCfg) -> Result<Mac>) -> Result<Vec<Port>> {
        let addrs = self.interface_addrs()?;
        let cards = self.cards();
        self.interfaces
            .iter()
            .zip(addrs)
            .enumerate()
            .map(|(id, (i, (addr, subnet)))| {
                Ok(Port {
                    id: id as u16,
                    name: i.name.clone(),
                    mac: mac_of(i)?,
                    addr,
                    subnet,
                    allow_new_sessions: i.allows_new_sessions(),
                    role: i.role(),
                    // TCP segments must fit a smaller MTU (PPPoE, or set).
                    mss_adjust: i
                        .mss_adjust
                        .or_else(|| (i.ip_mtu() < ETHERNET_MTU).then(|| i.ip_mtu() - 40)),
                    dhcp: if i.is_dhcp_client() {
                        eph_dataplane::Dhcp::Client
                    } else if i.dhcp.is_some() {
                        eph_dataplane::Dhcp::Server
                    } else {
                        eph_dataplane::Dhcp::Off
                    },
                    gateway: i.gateway.as_deref().and_then(|g| g.parse().ok()),
                    onlink: i.onlink.clone(),
                    mtu: i.ip_mtu(),
                    card: cards.iter().position(|&c| c == i.device).unwrap_or(0) as u16,
                    vlan: i.vlan,
                    host: eph_dataplane::host::HostAccess {
                        https: i.management.iter().any(|m| m == "https"),
                        ssh: i.management.iter().any(|m| m == "ssh"),
                        from: i
                            .management_from
                            .iter()
                            .filter_map(|p| p.parse().ok())
                            .collect(),
                    },
                    pppoe: match (i.is_pppoe(), i.pppoe_session) {
                        (false, _) => eph_dataplane::Pppoe::Off,
                        (true, None) => eph_dataplane::Pppoe::Dialing,
                        (true, Some((session, peer, mtu))) => {
                            eph_dataplane::Pppoe::Up { session, peer, mtu }
                        }
                    },
                })
            })
            .collect()
    }

    pub fn fib(&self, ports: &[Port]) -> Result<Fib<NextHop>> {
        let overlay = self.overlay()?;
        let mut routes = self
            .overlay_routes
            .iter()
            .map(|r| {
                let prefix = r.prefix.parse().map_err(anyhow::Error::msg)?;
                let site_idx = overlay
                    .sites
                    .iter()
                    .position(|&s| s == r.site)
                    .with_context(|| {
                        format!("overlay_route {}: no tether to site {}", r.prefix, r.site)
                    })?;
                Ok(OverlayRoute { prefix, site_idx })
            })
            .collect::<Result<Vec<_>>>()?;
        // Each site's networks: directly to it if we have tethers to it,
        // otherwise through the first hub we have tethers to.
        let me = self.overlay.as_ref().map(|o| o.role).unwrap_or_default();
        let hub = self
            .sites
            .iter()
            .find(|s| s.role == SiteRole::Hub && me.peers_with(s.role))
            .and_then(|h| overlay.sites.iter().position(|&x| x == h.id));
        for s in &self.sites {
            let direct = overlay.sites.iter().position(|&x| x == s.id);
            let Some(site_idx) = direct.filter(|_| me.peers_with(s.role)).or(hub) else {
                continue; // unreachable from here: no tethers to it or a hub
            };
            for p in &s.prefixes {
                let prefix = p
                    .parse()
                    .map_err(|e| anyhow::anyhow!("site {}: prefix {p:?}: {e}", s.name))?;
                routes.push(OverlayRoute { prefix, site_idx });
            }
        }
        // While an interface waits for its DHCP lease, a route through a
        // gateway on no connected subnet may be meant for that interface's
        // network: it waits for the lease instead of being an error.
        let mut statics = self.static_routes()?;
        let waiting = self
            .interfaces
            .iter()
            .zip(ports)
            .any(|(i, p)| i.has_dynamic_address() && p.addr.is_unspecified());
        if waiting {
            statics.retain(|r| ports.iter().any(|p| p.reaches(r.via)));
        }
        build_fib(ports, &statics, &routes).map_err(anyhow::Error::msg)
    }

    /// Compile the NAT section into the data plane's form.
    pub fn nat(&self) -> Result<NatConfig> {
        let n = &self.nat;
        let mut pools = Vec::new();
        for (i, p) in n.pools.iter().enumerate() {
            if n.pools[..i].iter().any(|q| q.name == p.name) {
                bail!("two NAT pools are named {}", p.name);
            }
            let mut addrs = Vec::new();
            for a in &p.addresses {
                expand_addresses(a, &mut addrs)
                    .with_context(|| format!("NAT pool {}: {a:?}", p.name))?;
            }
            if addrs.is_empty() {
                bail!("NAT pool {} has no addresses", p.name);
            }
            pools.push(addrs);
        }
        let prefix = |s: &Option<String>, what: &str, rule: &str| -> Result<Option<Prefix>> {
            s.as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let s = if s.contains('/') {
                        s.to_string()
                    } else {
                        format!("{s}/32")
                    };
                    s.parse::<Prefix>().map_err(anyhow::Error::msg)
                })
                .transpose()
                .with_context(|| format!("NAT rule {rule}: {what}"))
        };
        let mut rules = Vec::new();
        for r in &n.rules {
            let action =
                match r.translate.as_str() {
                    "interface" => NatAction::Interface,
                    "none" => NatAction::Exempt,
                    "pool" => {
                        let name = r.pool.as_deref().with_context(|| {
                            format!("NAT rule {}: translate = \"pool\" needs `pool`", r.name)
                        })?;
                        NatAction::Pool(n.pools.iter().position(|p| p.name == name).with_context(
                            || format!("NAT rule {}: no pool named {name:?}", r.name),
                        )?)
                    }
                    t => bail!(
                    "NAT rule {}: translate must be \"interface\", \"pool\" or \"none\", not {t:?}",
                    r.name
                ),
                };
            let outbound = r
                .outbound
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|o| {
                    self.interfaces
                        .iter()
                        .position(|i| i.name == o)
                        .map(|i| i as u16)
                        .with_context(|| format!("NAT rule {}: no interface named {o:?}", r.name))
                })
                .transpose()?;
            rules.push(NatRule {
                name: r.name.clone(),
                source: prefix(&r.source, "source", &r.name)?,
                destination: prefix(&r.destination, "destination", &r.name)?,
                outbound,
                action,
            });
        }
        Ok(NatConfig {
            masquerade: n.masquerade,
            pools,
            rules,
        })
    }

    /// Compile the SD-WAN section into the data plane's form (ids, not names).
    pub fn overlay(&self) -> Result<Overlay> {
        let mut o = Overlay::disabled();
        let Some(oc) = &self.overlay else {
            if !self.tethers.is_empty() || !self.overlay_routes.is_empty() || !self.sites.is_empty()
            {
                bail!("[[site]], [[tether]] and [[overlay_route]] need an [overlay] section");
            }
            return Ok(o);
        };
        o.site_id = oc.site_id;
        o.udp_port = oc.udp_port;
        o.mtu = oc.mtu;
        // Tethers over a PPPoE WAN lose 8 more bytes: shrink the default.
        if oc.mtu == DEFAULT_MTU && self.interfaces.iter().any(|i| i.is_pppoe()) {
            o.mtu = DEFAULT_MTU - eph_packet::pppoe::SESSION_HDR_LEN as u16;
        }
        o.allow_new_sessions = oc.allow_new_sessions;
        if !(576..=9000).contains(&oc.mtu) {
            bail!("overlay.mtu must be between 576 and 9000");
        }
        let addrs = self.interface_addrs()?;
        // Hand-written tethers first, then one per (outside interface, peer
        // address) for every site this router's role connects it to.
        let mut all: Vec<(TetherCfg, bool)> =
            self.tethers.iter().map(|t| (t.clone(), false)).collect();
        all.extend(self.site_tethers()?.into_iter().map(|t| (t, true)));
        for (i, (t, generated)) in all.iter().enumerate() {
            let t = &t.clone();
            let port = self
                .interfaces
                .iter()
                .position(|x| x.name == t.interface)
                .with_context(|| {
                    format!("tether {}: no interface named {:?}", t.name, t.interface)
                })?;
            let subnet = addrs[port].1;
            match t.gateway {
                // Generated tethers use the interface's gateway (configured
                // or from DHCP) for peers off the link.
                _ if *generated => {}
                None if !subnet.contains(t.remote) => bail!(
                    "tether {}: remote {} is not on {}'s subnet {subnet}; set `gateway`",
                    t.name,
                    t.remote,
                    t.interface
                ),
                Some(gw) if !subnet.contains(gw) => {
                    bail!(
                        "tether {}: gateway {gw} is not on {}'s subnet {subnet}",
                        t.name,
                        t.interface
                    )
                }
                _ => {}
            }
            if t.site == oc.site_id {
                bail!("tether {}: site {} is this site", t.name, t.site);
            }
            if all[..i].iter().any(|(x, _)| x.name == t.name) {
                bail!("two tethers are named {}", t.name);
            }
            let crypto = match t.public_key.as_deref() {
                None => PeerCrypto::PreShared,
                Some(k) => PeerCrypto::Handshake {
                    public: parse_public_key(k)
                        .map_err(|e| anyhow::anyhow!("tether {}: public_key {e:#}", t.name))?,
                },
            };
            let site_idx = match o.sites.iter().position(|&s| s == t.site) {
                Some(i) => {
                    if o.peers[i] != crypto {
                        bail!(
                            "tethers to site {} need the same public_key (tether {})",
                            t.site,
                            t.name
                        );
                    }
                    i
                }
                None => {
                    o.sites.push(t.site);
                    o.peers.push(crypto);
                    o.sites.len() - 1
                }
            };
            let key = t
                .key
                .as_deref()
                .map(parse_key)
                .transpose()
                .map_err(|e| anyhow::anyhow!("tether {}: key {e:#}", t.name))?;
            // Both sites seal with the key, so a site's tethers share one.
            if let Some(other) = o.tethers.iter().find(|x| x.site_idx == site_idx) {
                if other.key != key {
                    bail!(
                        "tethers {} and {} lead to the same site ({}) and need the same key",
                        other.name,
                        t.name,
                        t.site
                    );
                }
            }
            o.tethers.push(Tether {
                id: i as u16,
                name: t.name.clone(),
                port: port as u16,
                remote: t.remote,
                gateway: t.gateway,
                peer_site: t.site,
                site_idx,
                key,
            });
        }
        for c in &self.classes {
            let proto = match c.protocol.as_deref() {
                None => None,
                Some("tcp") => Some(6),
                Some("udp") => Some(17),
                Some("icmp") => Some(1),
                Some(n) => Some(
                    n.parse()
                        .with_context(|| format!("class {}: protocol {n:?}", c.name))?,
                ),
            };
            let ports = c
                .ports
                .as_deref()
                .map(|p| -> Result<(u16, u16)> {
                    let (lo, hi) = p.split_once('-').unwrap_or((p, p));
                    Ok((lo.trim().parse()?, hi.trim().parse()?))
                })
                .transpose()
                .with_context(|| {
                    format!("class {}: ports must be \"443\" or \"10000-20000\"", c.name)
                })?;
            let prefer = c
                .prefer
                .iter()
                .map(|n| {
                    o.tethers
                        .iter()
                        .find(|t| &t.name == n)
                        .map(|t| t.id)
                        .with_context(|| format!("class {}: no tether named {n:?}", c.name))
                })
                .collect::<Result<Vec<_>>>()?;
            o.classes.push(Class {
                name: c.name.clone(),
                proto,
                ports,
                dscp: c.dscp,
                prefer,
                max_latency_ms: c.max_latency_ms,
                max_jitter_ms: c.max_jitter_ms,
                max_loss_pct: c.max_loss_pct,
            });
        }
        Ok(o)
    }

    /// The tethers `[[site]]` entries imply, named "<site>-<interface>" (and
    /// "-2", "-3"... for further addresses of the same site).
    pub fn site_tethers(&self) -> Result<Vec<TetherCfg>> {
        let Some(oc) = &self.overlay else {
            return Ok(vec![]);
        };
        let mut out = vec![];
        for (i, s) in self.sites.iter().enumerate() {
            if !valid_name(&s.name) {
                bail!(
                    "site {:?}: needs a name (letters, digits, '-', '_' or '.')",
                    s.name
                );
            }
            if s.id == oc.site_id {
                bail!("site {}: id {} is this router's own site_id", s.name, s.id);
            }
            if let Some(o) = self.sites[..i]
                .iter()
                .find(|o| o.id == s.id || o.name == s.name)
            {
                bail!("sites {} and {} have the same name or id", o.name, s.name);
            }
            if let Some(k) = &s.key {
                parse_key(k).map_err(|e| anyhow::anyhow!("site {}: key {e:#}", s.name))?;
            }
            if let Some(k) = &s.public_key {
                parse_public_key(k)
                    .map_err(|e| anyhow::anyhow!("site {}: public_key {e:#}", s.name))?;
            }
            if !(1..=8).contains(&s.links) {
                bail!("site {}: links must be between 1 and 8", s.name);
            }
            let remotes: Vec<Ipv4Addr> = s
                .addresses
                .iter()
                .map(|a| {
                    a.parse()
                        .with_context(|| format!("site {}: address {a:?}", s.name))
                })
                .collect::<Result<_>>()?;
            for p in &s.prefixes {
                p.parse::<Prefix>()
                    .map_err(|e| anyhow::anyhow!("site {}: prefix {p:?}: {e}", s.name))?;
            }
            if !oc.role.peers_with(s.role) {
                continue;
            }
            // No fixed address: learn it, a path per link of the site's on
            // each of our WANs.
            let remotes = if remotes.is_empty() {
                vec![Ipv4Addr::UNSPECIFIED; s.links as usize]
            } else {
                remotes
            };
            for wan in self
                .interfaces
                .iter()
                .filter(|x| x.role == RoleCfg::Outside)
            {
                for (n, &remote) in remotes.iter().enumerate() {
                    let name = if n == 0 {
                        format!("{}-{}", s.name, wan.name)
                    } else {
                        format!("{}-{}-{}", s.name, wan.name, n + 1)
                    };
                    out.push(TetherCfg {
                        name,
                        interface: wan.name.clone(),
                        remote,
                        gateway: None,
                        site: s.id,
                        key: s.key.clone(),
                        public_key: s.public_key.clone(),
                    });
                }
            }
        }
        Ok(out)
    }
}

/// "a.b.c.d", "a.b.c.d/nn" or "a.b.c.d-e.f.g.h" -> addresses (at most 4096).
fn expand_addresses(s: &str, out: &mut Vec<Ipv4Addr>) -> Result<()> {
    let s = s.trim();
    let (lo, hi): (u32, u32) = if let Some((a, b)) = s.split_once('-') {
        (
            a.trim().parse::<Ipv4Addr>()?.into(),
            b.trim().parse::<Ipv4Addr>()?.into(),
        )
    } else if s.contains('/') {
        let p: Prefix = s.parse().map_err(anyhow::Error::msg)?;
        let lo = u32::from(p.addr());
        (lo, lo | (u32::MAX.checked_shr(p.len() as u32).unwrap_or(0)))
    } else {
        let a: u32 = s.parse::<Ipv4Addr>()?.into();
        (a, a)
    };
    if hi < lo || hi - lo >= 4096 {
        bail!("range must be ascending and at most 4096 addresses");
    }
    out.extend((lo..=hi).map(Ipv4Addr::from));
    Ok(())
}

/// A tether key: exactly 64 hex characters, not all zero.
fn parse_key(s: &str) -> Result<TetherKey> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("must be 64 hex characters (generate one with: openssl rand -hex 32)");
    }
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    if k == [0; 32] {
        bail!("must not be all zeros");
    }
    Ok(TetherKey(k))
}

/// A router's SD-WAN public key: 64 hex characters, not all zero.
pub fn parse_public_key(s: &str) -> Result<[u8; 32]> {
    let k = crate::parse_hex32(s.trim())
        .context("must be 64 hex characters (ephctl sdwan identity on that router)")?;
    if k == [0; 32] {
        bail!("must not be all zeros");
    }
    Ok(k)
}

fn broadcast(net: Prefix) -> Ipv4Addr {
    (u32::from(net.addr()) | (u32::MAX >> net.len())).into()
}

/// The most sessions per worker `sessions.max_per_worker` may ask for.
pub const SESSIONS_MAX: u32 = 16_000_000;

/// Which cipher a router accepts for session keys (`[overlay] cipher`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CipherPref {
    /// AES-256-GCM when both routers have AES in hardware, else ChaCha20.
    #[default]
    Auto,
    /// Only this one: a router that can't use it gets no keys.
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

/// 32 bytes from exactly 64 hex characters (keys).
pub fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("must be 64 hex characters");
    }
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Config> {
        let c: Config = toml::from_str(s)?;
        c.validate()?;
        Ok(c)
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../../../config/ephemeris.example.toml");
        let c = parse(text).unwrap();
        let ports = c.ports(|_| Ok([0; 6])).unwrap();
        c.fib(&ports).unwrap();
    }

    #[test]
    fn max_per_worker_is_a_number_or_auto() {
        let max = |v: &str| -> Result<SessionsMax> {
            Ok(parse(&format!(
                "[sessions]\nmax_per_worker = {v}\n[[interface]]\nname = \"lan\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\n"
            ))?
            .sessions
            .max_per_worker)
        };
        assert_eq!(max("1000").unwrap(), SessionsMax::Fixed(1000));
        assert_eq!(max("\"auto\"").unwrap(), SessionsMax::Auto);
        assert_eq!(
            max("\"5000\"").unwrap(),
            SessionsMax::Fixed(5000),
            "the portal's text"
        );
        let json: SessionsCfg = serde_json::from_str(r#"{"max_per_worker": null}"#).unwrap();
        assert_eq!(
            json.max_per_worker,
            SessionsMax::Auto,
            "an emptied portal field"
        );
        for bad in ["0", "16000001", "-1", "\"lots\"", "99999999999"] {
            assert!(max(bad).is_err(), "{bad}");
        }
        // Left out: auto. Written back as it was read.
        let c = Config::parse(
            "[[interface]]\nname = \"lan\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\n",
        )
        .unwrap();
        assert_eq!(c.sessions.max_per_worker, SessionsMax::Auto);
        assert!(toml::to_string(&c)
            .unwrap()
            .contains("max_per_worker = \"auto\""));
        let mut c = c;
        c.sessions.max_per_worker = SessionsMax::Fixed(4096);
        assert!(toml::to_string(&c)
            .unwrap()
            .contains("max_per_worker = 4096"));
    }

    #[test]
    fn session_timeouts_are_capped_at_a_day() {
        let text = include_str!("../../../config/ephemeris.example.toml");
        let mut c = parse(text).unwrap();
        // A config with a very long timeout still loads...
        c.sessions.tcp_established_timeout_secs = 7 * 86_400;
        c.sessions.udp_stream_timeout_secs = 2 * 86_400;
        c.validate().unwrap();
        // ...but no session stays idle for more than a day.
        let t = c.sessions.to_config(1000, 1).timeouts;
        assert_eq!(t.tcp_established, eph_dataplane::MAX_IDLE_SECS);
        assert_eq!(t.udp_stream, eph_dataplane::MAX_IDLE_SECS);
        assert_eq!(t.udp, 30, "shorter ones are left alone");
        c.sessions.icmp_timeout_secs = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn per_application_session_timeouts() {
        let base = include_str!("../../../config/ephemeris.example.toml");
        let with = |t: &str| parse(&format!("{base}\n{t}")).and_then(|c| c.validate().map(|_| c));
        let c = with(
            r#"
[[sessions.timeout]]
name = "dns"
protocol = "udp"
ports = "53"
idle_secs = 10
unanswered_secs = 5

[[sessions.timeout]]
protocol = "udp"
ports = "3478-3481"
idle_secs = 600
"#,
        )
        .unwrap();
        let apps = c.sessions.to_config(1000, 1).apps;
        assert_eq!(apps.len(), 2);
        assert_eq!(
            apps[0],
            eph_dataplane::AppTimeout {
                proto: 17,
                ports: (53, 53),
                idle_secs: 10,
                unanswered_secs: Some(5)
            }
        );
        assert_eq!(
            (apps[1].ports, apps[1].unanswered_secs),
            ((3478, 3481), None)
        );
        for bad in [
            "protocol = \"icmp\"\nports = \"1\"\nidle_secs = 1",
            "protocol = \"udp\"\nports = \"60-50\"\nidle_secs = 1",
            "protocol = \"udp\"\nports = \"dns\"\nidle_secs = 1",
            "protocol = \"udp\"\nports = \"53\"\nidle_secs = 0",
        ] {
            assert!(
                with(&format!("[[sessions.timeout]]\n{bad}")).is_err(),
                "{bad}"
            );
        }
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

    #[test]
    fn dhcp_server_and_client_config() {
        let c = parse(DHCP_CFG).unwrap();
        let lan = &c.interfaces[0];
        let d = lan.dhcp.as_ref().unwrap();
        assert_eq!(d.reservations[0].name.as_deref(), Some("nas"));
        let r = d
            .resolve(
                "lan",
                "10.10.1.1".parse().unwrap(),
                "10.10.1.0/24".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(r.range.1, "10.10.1.199".parse::<Ipv4Addr>().unwrap());
        let ports = c.ports(|_| Ok([0; 6])).unwrap();
        assert_eq!(ports[0].dhcp, eph_dataplane::Dhcp::Server);
        assert_eq!(ports[1].dhcp, eph_dataplane::Dhcp::Client);
        assert!(ports[1].addr.is_unspecified(), "no address before a lease");
        // Round trip through the GUI's serializer keeps the nested tables.
        let text = toml::to_string(&c).unwrap();
        assert_eq!(parse(&text).unwrap(), c, "{text}");
    }

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
    fn bad_pppoe_settings_are_refused() {
        let err =
            |from: &str, to: &str| parse(&PPPOE_CFG.replace(from, to)).unwrap_err().to_string();
        assert!(err(
            "[interface.pppoe]\nusername = \"alice@isp\"\npassword = \"s3cret\"\n",
            ""
        )
        .contains("needs an [interface.pppoe]"));
        assert!(err("username = \"alice@isp\"", "username = \"\"").contains("username"));
        assert!(err("role = \"outside\"", "role = \"inside\"").contains("outside interfaces"));
        assert!(err("password = \"s3cret\"", "password = \"s3cret\"\nmtu = 1500").contains("mtu"));
        let stray = PPPOE_CFG.replace("address = \"pppoe\"", "address = \"203.0.113.2/24\"");
        assert!(parse(&stray)
            .unwrap_err()
            .to_string()
            .contains("only applies"));
    }

    #[test]
    fn bad_dhcp_settings_are_refused() {
        let err =
            |from: &str, to: &str| parse(&DHCP_CFG.replace(from, to)).unwrap_err().to_string();
        assert!(err("10.10.1.100-10.10.1.199", "10.10.1.199-10.10.1.100").contains("backwards"));
        assert!(err("10.10.1.100-10.10.1.199", "10.10.1.100-10.10.2.5")
            .contains("isn't a host address"));
        assert!(err("address = \"10.10.1.10\"", "address = \"10.10.1.1\"")
            .contains("isn't a free host"));
        assert!(err("mac = \"52:54:00:12:34:56\"", "mac = \"nope\"").contains("MAC"));
        assert!(err("domain = \"home.arpa\"", "domain = \"bad domain\"").contains("domain"));
        // A DHCP-client interface can't serve DHCP or set a gateway.
        let both = DHCP_CFG.replace("address = \"10.10.1.1/24\"", "address = \"dhcp\"");
        assert!(parse(&both).unwrap_err().to_string().contains("both"));
    }

    #[test]
    fn interface_mtu() {
        let with = |extra: &str| {
            parse(&DHCP_CFG.replacen(
                "address = \"10.10.1.1/24\"",
                &format!("address = \"10.10.1.1/24\"\n{extra}"),
                1,
            ))
        };
        let c = with("mtu = 1400").unwrap();
        let ports = c.ports(|_| Ok([0; 6])).unwrap();
        assert_eq!((ports[0].mtu, ports[0].mss_adjust), (1400, Some(1360)));
        assert_eq!(ports[1].mtu, 1500);
        assert!(with("mtu = 9000").unwrap_err().to_string().contains("mtu"));
        assert!(with("mtu = 500").unwrap_err().to_string().contains("mtu"));
    }

    /// A spoke ("cpt") with one WAN, in a network with two hubs, another
    /// spoke and a mesh site.
    const SITES_CFG: &str = r#"
[[interface]]
name = "lan"
device = "ens19"
address = "10.1.0.1/24"

[[interface]]
name = "wan"
device = "ens20"
address = "198.51.100.2/24"
role = "outside"
gateway = "198.51.100.1"

[overlay]
site_id = 1
name = "cpt"
role = "spoke"

[[site]]
name = "jhb"
id = 2
role = "hub"
addresses = ["203.0.113.2", "192.0.2.2"]
prefixes = ["10.2.0.0/16"]
key = "1111111111111111111111111111111111111111111111111111111111111111"

[[site]]
name = "dbn"
id = 3
role = "spoke"
prefixes = ["10.3.0.0/16"]

[[site]]
name = "pta"
id = 4
role = "mesh"
addresses = ["203.0.113.4"]
prefixes = ["10.4.0.0/16"]
key = "2222222222222222222222222222222222222222222222222222222222222222"
"#;

    #[test]
    fn site_roles_decide_who_connects() {
        use SiteRole::*;
        let peers = |a: SiteRole, b: SiteRole| a.peers_with(b);
        assert!(peers(Hub, Hub) && peers(Hub, Spoke) && peers(Hub, Mesh));
        assert!(peers(Spoke, Hub) && !peers(Spoke, Spoke) && !peers(Spoke, Mesh));
        assert!(peers(Mesh, Hub) && !peers(Mesh, Spoke) && peers(Mesh, Mesh));
    }

    #[test]
    fn sites_become_tethers_and_routes() {
        let c = parse(SITES_CFG).unwrap();
        let o = c.overlay().unwrap();
        // A spoke only connects to the hub: one tether per hub address.
        let names: Vec<&str> = o.tethers.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["jhb-wan", "jhb-wan-2"]);
        assert_eq!(o.sites, [2]);
        assert!(o.tethers.iter().all(|t| t.key.is_some()));
        // Every other site's networks are reachable through the hub.
        let ports = c.ports(|_| Ok([0; 6])).unwrap();
        let fib = c.fib(&ports).unwrap();
        for dst in ["10.2.1.1", "10.3.1.1", "10.4.1.1"] {
            assert_eq!(
                fib.lookup(dst.parse().unwrap()),
                Some(&NextHop::Site(0)),
                "{dst} via the hub"
            );
        }
    }

    #[test]
    fn a_site_with_a_public_key_uses_the_handshake() {
        let pk = "ab".repeat(32);
        // jhb: public key (and its key becomes the handshake's extra key).
        let text = SITES_CFG.replacen(
            "prefixes = [\"10.2.0.0/16\"]",
            &format!("prefixes = [\"10.2.0.0/16\"]\npublic_key = \"{pk}\""),
            1,
        );
        let o = parse(&text).unwrap().overlay().unwrap();
        assert_eq!(o.crypto(0), PeerCrypto::Handshake { public: [0xab; 32] });
        assert!(
            o.tethers.iter().all(|t| t.key.is_some()),
            "kept as the extra key"
        );
        // Without `key` it's fine too: the handshake doesn't need one.
        let o = parse(&text.replacen(
            "key = \"1111111111111111111111111111111111111111111111111111111111111111\"\n",
            "",
            1,
        ))
        .unwrap()
        .overlay()
        .unwrap();
        assert!(matches!(o.crypto(0), PeerCrypto::Handshake { .. }));
        // The rest stay on their pre-shared key.
        let o = parse(SITES_CFG).unwrap().overlay().unwrap();
        assert_eq!(o.crypto(0), PeerCrypto::PreShared);
        // Bad keys are refused.
        for bad in ["abcd", &"zz".repeat(32), &"00".repeat(32)] {
            let t = text.replace(&pk, bad);
            assert!(
                parse(&t).and_then(|c| c.overlay()).is_err(),
                "public_key {bad:?}"
            );
        }
        // Hand-written tethers to one site must agree.
        let mut c = parse(&text).unwrap();
        c.tethers.push(TetherCfg {
            name: "extra".into(),
            interface: "wan".into(),
            remote: "198.51.100.9".parse().unwrap(),
            gateway: None,
            site: 2,
            key: Some("1".repeat(64)),
            public_key: Some("cd".repeat(32)),
        });
        assert!(c
            .overlay()
            .unwrap_err()
            .to_string()
            .contains("same public_key"));
    }

    #[test]
    fn a_hub_learns_peers_without_addresses() {
        // The same network seen from the hub.
        let hub = SITES_CFG
            .replace(
                "site_id = 1\nname = \"cpt\"\nrole = \"spoke\"",
                "site_id = 2\nname = \"jhb\"\nrole = \"hub\"",
            )
            .replace(
                "name = \"jhb\"\nid = 2\nrole = \"hub\"",
                "name = \"cpt\"\nid = 1\nrole = \"spoke\"",
            );
        let c = parse(&hub).unwrap();
        let o = c.overlay().unwrap();
        let t = |n: &str| o.tethers.iter().find(|t| t.name == n).unwrap();
        // dbn has no address: learned. It also has no key, so it stays down.
        assert!(t("dbn-wan").remote.is_unspecified() && t("dbn-wan").key.is_none());
        assert_eq!(
            t("pta-wan").remote,
            "203.0.113.4".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(o.sites.len(), 3, "a hub connects to everyone");
        assert!(o.tethers.iter().all(|t| !t.name.starts_with("dbn-wan-")));
        // dbn has two WAN links (fibre and LTE, both behind NAT): a path
        // for each, followed separately.
        let two = hub.replace(
            "prefixes = [\"10.3.0.0/16\"]",
            "prefixes = [\"10.3.0.0/16\"]\nlinks = 2",
        );
        let o = parse(&two).unwrap().overlay().unwrap();
        let dbn: Vec<&str> = o
            .tethers
            .iter()
            .filter(|t| t.name.starts_with("dbn"))
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(dbn, ["dbn-wan", "dbn-wan-2"]);
        assert!(parse(&two.replace("links = 2", "links = 9"))
            .and_then(|c| c.overlay())
            .is_err());
    }

    #[test]
    fn bad_sites_are_refused() {
        let err =
            |from: &str, to: &str| parse(&SITES_CFG.replace(from, to)).unwrap_err().to_string();
        assert!(err("id = 3", "id = 1").contains("own site_id"));
        assert!(err("id = 3", "id = 2").contains("same name or id"));
        assert!(err("\"10.3.0.0/16\"", "\"10.3.0.0/33\"").contains("prefix"));
        assert!(err("key = \"1111", "key = \"zz11").contains("key"));
        assert!(err("addresses = [\"203.0.113.4\"]", "addresses = [\"nope\"]").contains("address"));
    }

    #[test]
    fn interfaces_need_a_name_and_a_device() {
        let iface = |name: &str, device: &str| {
            format!(
                "[[interface]]\nname = {name:?}\ndevice = {device:?}\naddress = \"10.0.0.1/24\"\n"
            )
        };
        let err = |t: String| parse(&t).unwrap_err().to_string();
        assert!(err(iface("lan", "")).contains("choose the network card"));
        assert!(err(iface("", "ens19")).contains("interface #1: needs a name"));
        assert!(err(iface("my lan", "ens19")).contains("needs a name"));
        assert!(err(iface("lan", "en s19")).contains("valid Linux interface name"));
        assert!(err(iface("lan", "a-very-long-device-name")).contains("valid Linux interface name"));
        let two = format!(
            "{}[[interface]]\nname = \"lan\"\ndevice = \"ens20\"\naddress = \"10.0.1.1/24\"\n",
            iface("lan", "ens19")
        );
        assert!(err(two).contains("two interfaces are named lan"));
        assert!(parse(&iface("lan", "ens19")).is_ok());
    }

    #[test]
    fn management_access_only_on_inside_interfaces() {
        let iface = |role: &str, extra: &str| {
            format!(
                "[[interface]]\nname = \"x\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\nrole = {role:?}\n{extra}"
            )
        };
        let c = parse(&iface(
            "inside",
            "management = [\"https\", \"ssh\"]\nmanagement_from = [\"10.0.0.0/25\"]\n",
        ))
        .unwrap();
        let p = &c.ports(|_| Ok([0; 6])).unwrap()[0];
        assert!(p.host.https && p.host.ssh);
        assert_eq!(p.host.from, vec!["10.0.0.0/25".parse().unwrap()]);
        // None unless asked for.
        let c = parse(&iface("inside", "")).unwrap();
        assert!(!c.ports(|_| Ok([0; 6])).unwrap()[0].host.any());

        let err = |extra: &str, role: &str| parse(&iface(role, extra)).unwrap_err().to_string();
        assert!(err("management = [\"ssh\"]\n", "outside")
            .contains("only be reached on inside interfaces"));
        assert!(err("management = [\"https\"]\n", "outside")
            .contains("only be reached on inside interfaces"));
        assert!(err("management = [\"telnet\"]\n", "inside").contains("choose \"https\""));
        assert!(err("management_from = [\"10.0.0.0/8\"]\n", "inside").contains("has no effect"));
        assert!(err(
            "management = [\"ssh\"]\nmanagement_from = [\"nope\"]\n",
            "inside"
        )
        .contains("management_from"));
    }

    #[test]
    fn worker_cpus_must_exist() {
        let cfg = |cpus: &str| {
            parse(&format!(
                "[dataplane]\nworkers = 1\ncpus = [{cpus}]\n[[interface]]\nname = \"lan\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\n"
            ))
        };
        assert!(cfg("3").is_ok());
        assert!(cfg("1024")
            .unwrap_err()
            .to_string()
            .contains("CPU 1024 doesn't exist"));
    }

    #[test]
    fn vlans_share_a_card() {
        let iface = |name: &str, device: &str, vlan: Option<u16>, addr: &str| {
            let vlan = vlan.map(|v| format!("vlan = {v}\n")).unwrap_or_default();
            format!(
                "[[interface]]\nname = {name:?}\ndevice = {device:?}\n{vlan}address = {addr:?}\n"
            )
        };
        let text = [
            iface("lan", "ens19", None, "10.0.1.1/24"),
            iface("guest", "ens19", Some(10), "10.0.10.1/24"),
            iface("wan", "ens20", Some(7), "pppoe"),
            "role = \"outside\"\n[interface.pppoe]\nusername = \"u\"\npassword = \"p\"\n".into(),
            iface("iot", "ens19", Some(20), "10.0.20.1/24"),
        ]
        .concat();
        let c = parse(&text).unwrap();
        assert_eq!(c.cards(), ["ens19", "ens20"]);
        let ports = c.ports(|_| Ok([0; 6])).unwrap();
        let link: Vec<_> = ports
            .iter()
            .map(|p| (p.name.as_str(), p.card, p.vlan))
            .collect();
        assert_eq!(
            link,
            [
                ("lan", 0, None),
                ("guest", 0, Some(10)),
                ("wan", 1, Some(7)),
                ("iot", 0, Some(20))
            ]
        );
        assert_eq!(c.interfaces[1].link_name(), "ens19.10");
        // Written back as it was read.
        assert!(toml::to_string(&c).unwrap().contains("vlan = 10"));

        let err = |t: String| parse(&t).unwrap_err().to_string();
        let two = |a: Option<u16>, b: Option<u16>| {
            iface("a", "ens19", a, "10.0.1.1/24") + &iface("b", "ens19", b, "10.0.2.1/24")
        };
        assert!(err(two(None, None)).contains("both use ens19 untagged"));
        assert!(err(two(Some(5), Some(5))).contains("both VLAN 5 on ens19"));
        assert!(parse(&two(None, Some(5))).is_ok());
        assert!(parse(&two(Some(5), Some(6))).is_ok());
        for bad in [0, 4095, 5000] {
            assert!(err(iface("a", "ens19", Some(bad), "10.0.1.1/24"))
                .contains("vlan must be between 1 and 4094"));
        }
        // Moving an interface to another VLAN reshapes the sockets: restart.
        let moved = parse(&text.replace("vlan = 20", "vlan = 21")).unwrap();
        assert!(!c.live_applicable(&moved));
        assert!(c.live_applicable(&c.clone()));
    }

    #[test]
    fn rejects_overlapping_subnets() {
        let e = parse(
            r#"
            [[interface]]
            name = "a"
            device = "eth1"
            address = "10.0.0.1/16"
            [[interface]]
            name = "b"
            device = "eth2"
            address = "10.0.5.1/24"
            "#,
        )
        .unwrap_err();
        assert!(e.to_string().contains("overlapping"), "{e}");
    }

    #[test]
    fn rejects_unreachable_gateway() {
        let e = parse(
            r#"
            [[interface]]
            name = "a"
            device = "eth1"
            address = "10.0.0.1/24"
            [[route]]
            prefix = "0.0.0.0/0"
            via = "192.168.1.1"
            "#,
        )
        .unwrap_err();
        assert!(e.to_string().contains("not on any connected subnet"), "{e}");
    }

    #[test]
    fn plain_http_stays_on_loopback_unless_asked() {
        const BASE: &str = r#"
            [[interface]]
            name = "lan"
            device = "eth1"
            address = "10.0.0.1/24"
        "#;
        let with = |management: &str| parse(&format!("[management]\n{management}\n{BASE}"));
        let addr = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        let c = parse(BASE).unwrap();
        assert_eq!(c.management.bind_addr(), (addr("127.0.0.1:8080"), false));
        // An older config asking for the network: kept on loopback.
        let c = with(r#"listen = "0.0.0.0:8080""#).unwrap();
        assert_eq!(c.management.bind_addr(), (addr("127.0.0.1:8080"), true));
        let c = with("listen = \"0.0.0.0:9000\"\ninsecure_remote_http = true").unwrap();
        assert_eq!(c.management.bind_addr(), (addr("0.0.0.0:9000"), false));
        assert!(with(r#"hostnames = ["evil name"]"#).is_err());
        assert!(with(r#"hostnames = ["router.example.net"]"#).is_ok());
    }

    #[test]
    fn the_controller_section_is_checked() {
        let base = "[[interface]]\nname = \"lan\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\n";
        let pin = format!("sha256:{}", "ab".repeat(32));
        let with = |url: &str, pin: &str| {
            parse(&format!(
                "{base}[controller]\nurl = \"{url}\"\npin = \"{pin}\"\n"
            ))
        };
        for ok in [
            "https://controller.example.net/",
            "https://10.0.0.5:8443",
            "https://orrery.example.net/acme/",
        ] {
            let c = with(ok, &pin).unwrap();
            assert_eq!(c.controller.unwrap().pin_bytes().unwrap(), [0xab; 32]);
        }
        for bad in [
            "http://controller.example.net/",
            "https://user@controller.example.net/",
            "https://controller.example.net/?x=1",
            "https://controller.example.net/#token",
            "https://:8443/",
            "https://host:0/",
            "https://bad host/",
        ] {
            assert!(with(bad, &pin).is_err(), "{bad}");
        }
        for bad in [
            "ab".repeat(32),
            format!("sha1:{}", "ab".repeat(32)),
            format!("sha256:{}", "AB".repeat(32)),
            format!("sha256:{}", "ab".repeat(31)),
        ] {
            assert!(with("https://c.example.net/", &bad).is_err(), "{bad}");
        }
        assert!(parse(base).unwrap().controller.is_none());
    }

    #[test]
    fn enrolment_strings_are_exact() {
        let token = "A".repeat(42) + "_";
        let fp = "0f".repeat(32);
        let good = format!("eph-enrol:v1:https://c.example.net/#{token}@{fp}");
        let e = Enrolment::parse(&good).unwrap();
        assert_eq!(
            (e.url.as_str(), e.token.as_str()),
            ("https://c.example.net/", token.as_str())
        );
        assert_eq!(e.fingerprint, [0x0f; 32]);
        assert_eq!(e.to_string(), good, "round trip");
        assert_eq!(e.controller().pin, format!("sha256:{fp}"));
        assert!(!format!("{e:?}").contains(&token), "the token never prints");
        for bad in [
            format!("eph-enrol:v2:https://c.example.net/#{token}@{fp}"),
            format!("eph-enrol:v1:http://c.example.net/#{token}@{fp}"),
            format!("eph-enrol:v1:https://c.example.net/{token}@{fp}"),
            format!("eph-enrol:v1:https://c.example.net/#{token}{fp}"),
            format!("eph-enrol:v1:https://c.example.net/#{}@{fp}", &token[1..]),
            format!("eph-enrol:v1:https://c.example.net/#{}+@{fp}", &token[1..]),
            format!(
                "eph-enrol:v1:https://c.example.net/#{token}@{}",
                fp.to_uppercase()
            ),
            format!("eph-enrol:v1:https://u@c.example.net/#{token}@{fp}"),
        ] {
            assert!(Enrolment::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_routers_own_traffic_goes_out_where_asked() {
        let base = "[[interface]]\nname = \"lan\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\n";
        assert_eq!(
            parse(base).unwrap().management.outbound,
            Outbound::Management
        );
        let c = parse(&format!("[management]\noutbound = \"dataplane\"\n{base}")).unwrap();
        assert_eq!(c.management.outbound, Outbound::Dataplane);
        assert!(parse(&format!("[management]\noutbound = \"wan\"\n{base}")).is_err());
        // Changing it needs a restart (nic-setup sets the route at start).
        assert!(!parse(base).unwrap().live_applicable(&c));
    }

    #[test]
    fn tether_keys_are_checked() {
        let cfg = |k1: &str, k2: &str| {
            format!(
                r#"
                [overlay]
                site_id = 1
                [[interface]]
                name = "wan"
                device = "eth1"
                address = "192.0.2.1/30"
                [[interface]]
                name = "wan2"
                device = "eth2"
                address = "198.51.100.1/30"
                [[tether]]
                name = "a"
                interface = "wan"
                remote = "192.0.2.2"
                site = 2
                {k1}
                [[tether]]
                name = "b"
                interface = "wan2"
                remote = "198.51.100.2"
                site = 2
                {k2}
                "#
            )
        };
        let k = |hex: &str| format!("key = \"{hex}\"");
        let good = "ab".repeat(32);
        let c = parse(&cfg(&k(&good), &k(&good))).unwrap();
        let o = c.overlay().unwrap();
        assert_eq!(o.tethers[0].key, Some(TetherKey([0xab; 32])));
        assert!(format!("{:?}", o.tethers[0]).contains("redacted"));
        // No key: allowed, but that tether stays down.
        let c = parse(&cfg("", "")).unwrap();
        assert!(c.overlay().unwrap().tethers.iter().all(|t| t.key.is_none()));
        let err = |a: String, b: String| parse(&cfg(&a, &b)).unwrap_err().to_string();
        assert!(err(k("abc"), k(&good)).contains("64 hex characters"));
        assert!(err(k(&"zz".repeat(32)), k(&good)).contains("64 hex characters"));
        let zeros = "00".repeat(32);
        assert!(err(k(&zeros), k(&zeros)).contains("all zeros"));
        let other = "cd".repeat(32);
        assert!(err(k(&good), k(&other)).contains("need the same key"));
    }

    #[test]
    fn mss_adjust_reaches_the_port_and_is_range_checked() {
        let iface = |mss: u32| {
            format!(
                "[[interface]]\nname = \"wan\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\nmss_adjust = {mss}\n"
            )
        };
        let c = parse(&iface(1452)).unwrap();
        let ports = c.ports(|_| Ok([0; 6])).unwrap();
        assert_eq!(ports[0].mss_adjust, Some(1452));
        for bad in [535, 1461] {
            let e = parse(&iface(bad)).unwrap_err().to_string();
            assert!(e.contains("mss_adjust must be between 536 and 1460"), "{e}");
        }
        assert!(parse(&iface(70000)).is_err(), "not a u16");
        let none = "[[interface]]\nname = \"lan\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\n";
        let ports = parse(none).unwrap().ports(|_| Ok([0; 6])).unwrap();
        assert_eq!(ports[0].mss_adjust, None);
    }
}
