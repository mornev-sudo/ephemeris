//! `ephctl`: the Ephemeris CLI. A thin client of the same REST API the web
//! portal uses, so the CLI, the portal and (later) a central controller can
//! never disagree about what the router can do.

// No unsafe code here: packet parsing, routing and forwarding logic is
// all safe Rust, and the compiler keeps it that way.
#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::io::{IsTerminal, Write};

#[derive(Parser)]
#[command(version, about = "Manage a Ephemeris router")]
struct Cli {
    /// API address.
    #[arg(long, env = "EPHCTL_URL", default_value = "http://127.0.0.1:8080")]
    url: String,
    /// API token (default: read /var/lib/ephemeris/api-token on the router).
    #[arg(long, env = "EPHCTL_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Print raw JSON instead of tables.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Interfaces, counters, drops and session totals.
    Status,
    /// Live sessions, newest first (at most 1000).
    Sessions {
        #[arg(short, long, default_value_t = 50)]
        limit: usize,
    },
    /// The ARP table.
    Neighbors,
    /// DHCP: the addresses the router got, and the leases it handed out.
    Dhcp,
    /// Internet connections: each outside interface (static, DHCP or PPPoE).
    Wan,
    /// The forwarding table.
    Routes,
    /// SD-WAN: tethers, their measured health, and which path each class uses.
    Overlay,
    /// SD-WAN sites and their shared keys.
    Sdwan {
        #[command(subcommand)]
        cmd: SdwanCmd,
    },
    /// Being managed by a controller (docs/controller-api.md).
    Controller {
        #[command(subcommand)]
        cmd: ControllerCmd,
    },
    /// Add or remove static routes (validated and committed immediately).
    Route {
        #[command(subcommand)]
        cmd: RouteCmd,
    },
    /// Candidate / commit / rollback configuration workflow.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Logs: recent lines, the audit trail, and log levels per category.
    Log {
        #[command(subcommand)]
        cmd: LogCmd,
    },
    /// Restart ephemerisd (needed after interface or worker changes).
    Restart,
    /// OS image version and A/B updates.
    System {
        #[command(subcommand)]
        cmd: SystemCmd,
    },
}

#[derive(Subcommand)]
enum SystemCmd {
    /// Running build and the state of the last update job.
    Status,
    /// CPU, memory, disk, per-thread CPU, and how full every table is.
    Resources,
    /// List installed and available versions.
    Check,
    /// Install the newest version into the idle slot. The router keeps
    /// running; reboot when `ephctl system status` says it's installed.
    Update,
    /// Reboot (into an installed update, if there is one).
    Reboot {
        /// Reboot even while an update is still installing (it's cancelled).
        #[arg(long)]
        force: bool,
    },
    /// Change the admin password (web "admin" and console/SSH "root").
    Password {
        /// Set a new password without the current one (forgotten password).
        /// Works because ephctl, run as root on the router, uses the API token.
        #[arg(long)]
        reset: bool,
    },
}

#[derive(Subcommand)]
enum LogCmd {
    /// Recent log lines (from memory: since ephemerisd started, at most
    /// the last 5000). Older ones: debug.log, or journalctl -u ephemerisd.
    Show {
        /// Only this category (see `ephctl log levels`).
        #[arg(short, long)]
        category: Option<String>,
        /// Only this level and more severe: error, warn, info, debug, trace.
        #[arg(short, long)]
        level: Option<String>,
        /// How many lines.
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Keep printing new lines as they come (Ctrl-C to stop).
        #[arg(short, long)]
        follow: bool,
    },
    /// Every category, its level, and for how long a raised one lasts.
    Levels,
    /// Set a category's level: ephctl log set dhcp-client debug [--for 30m].
    /// Debug and trace switch themselves off (default 10 minutes; --for
    /// forever to keep them). Packet categories at debug trace packets in
    /// the data plane: narrow it with `ephctl log host`.
    Set {
        category: String,
        level: String,
        /// How long: 90s, 30m, 2h, forever.
        #[arg(long = "for")]
        for_: Option<String>,
    },
    /// Trace only packets to or from this address or prefix ("off": all).
    Host { host: String },
    /// Every category back to its configured level; no host filter.
    Reset,
    /// The audit trail: logins, changes, restarts (audit.log).
    Audit {
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
}

#[derive(Subcommand)]
enum ControllerCmd {
    /// This router's public key towards a controller: its management
    /// identity (Ed25519, not the SD-WAN key), which enrolment registers.
    Identity,
}

#[derive(Subcommand)]
enum SdwanCmd {
    /// This router and the other sites: role, direct or through a hub, and
    /// how tethers to each are encrypted.
    Sites,
    /// This router's SD-WAN public key: other routers put it in their entry
    /// for this one (`public_key`).
    Identity,
    /// Show a site's public key; --set uses session keys from a handshake
    /// with it from now on, --clear goes back to the pre-shared key
    /// (committed; takes effect after `ephctl restart`).
    PublicKey {
        site: String,
        /// Its public key (64 hex characters: `ephctl sdwan identity` there).
        #[arg(long, conflicts_with = "clear")]
        set: Option<String>,
        #[arg(long)]
        clear: bool,
    },
    /// Show the key shared with a site; --generate or --set replaces it
    /// (committed; takes effect after `ephctl restart`).
    Key {
        site: String,
        /// Replace it with a new random key.
        #[arg(long, conflicts_with = "set")]
        generate: bool,
        /// Replace it with this one (64 hex characters, from the other router).
        #[arg(long)]
        set: Option<String>,
    },
    /// Print a [[site]] entry describing this router, with the key it shares
    /// with SITE: paste it into SITE's configuration (`ephctl config edit`).
    Entry { site: String },
}

/// How tethers to a site (a row of /overlay/sites) are encrypted, in words.
fn encryption(x: &serde_json::Value) -> String {
    if x["connected"] != true {
        return "not needed".into();
    }
    if x["public_key"].is_string() {
        let h = &x["handshake"];
        return match h["key_age_s"].as_u64() {
            Some(age) => format!("handshake, {}, keys {age}s old", str(&h["cipher"])),
            None if h["pending"] == true => "handshake, waiting".into(),
            None => "handshake, no keys yet".into(),
        };
    }
    if x["has_key"] == true {
        "pre-shared key".into()
    } else {
        "MISSING".into()
    }
}

#[derive(Subcommand)]
enum RouteCmd {
    /// ephctl route add 192.168.50.0/24 10.10.2.254
    Add { prefix: String, via: String },
    /// ephctl route del 192.168.50.0/24
    Del { prefix: String },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the running configuration.
    Show,
    /// Edit the configuration in $EDITOR, then validate and show the diff.
    Edit,
    /// Stage a configuration file as the candidate and show the diff.
    Load { file: String },
    /// Apply the candidate. --confirm N: roll back after N seconds unless confirmed.
    Commit {
        #[arg(long)]
        confirm: Option<u64>,
    },
    /// Keep a "commit --confirm" change.
    Confirm,
    /// Throw away the staged candidate.
    Discard,
    /// Restore an earlier version (1 = the previous one).
    Rollback {
        #[arg(default_value_t = 1)]
        to: usize,
    },
    /// List saved versions.
    History,
}

struct Client {
    base: String,
    token: String,
}

impl Client {
    fn call(&self, method: &str, path: &str, body: Option<(&str, &str)>) -> Result<Value> {
        let url = format!("{}/api/v1{path}", self.base.trim_end_matches('/'));
        let req =
            ureq::request(method, &url).set("Authorization", &format!("Bearer {}", self.token));
        let res = match body {
            Some((ctype, b)) => req.set("Content-Type", ctype).send_string(b),
            None => req.call(),
        };
        let (code, text) = match res {
            Ok(r) => (r.status(), r.into_string()?),
            Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap_or_default()),
            Err(e) => return Err(anyhow!("cannot reach {url}: {e}")),
        };
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        if code >= 400 {
            let msg = v["error"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string());
            bail!("{msg} (HTTP {code})");
        }
        Ok(v)
    }
    fn get(&self, path: &str) -> Result<Value> {
        self.call("GET", path, None)
    }
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("ephctl: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let token = match cli.token {
        Some(t) => t,
        None => std::fs::read_to_string("/var/lib/ephemeris/api-token")
            .map(|t| t.trim().to_string())
            .context(
                "no API token: pass --token, set EPHCTL_TOKEN, or run on the router as root",
            )?,
    };
    let c = Client {
        base: cli.url,
        token,
    };
    let json = cli.json;
    let print = |v: &Value| println!("{}", serde_json::to_string_pretty(v).unwrap());

    match cli.cmd {
        Cmd::Status => {
            let s = c.get("/status")?;
            if json {
                print(&s);
                return Ok(());
            }
            println!(
                "Ephemeris {}, build {}, up {}, {} worker(s)",
                s["version"].as_str().unwrap_or("?"),
                s["build"].as_str().unwrap_or("?"),
                dur(s["uptime_secs"].as_u64().unwrap_or(0)),
                s["workers"]
            );
            // The same four numbers as the portal's Reporting tab.
            let r = &s["rates"];
            let f = |k: &str| r[k].as_f64().unwrap_or(0.0);
            println!(
                "Open sessions {} · {} pps (in {} / out {}) · {} (in {} / out {}) · dropped {}",
                s["sessions"]["active"],
                if r.is_null() {
                    "-".into()
                } else {
                    format!("{:.0}", f("rx_pps") + f("tx_pps"))
                },
                f("rx_pps").round(),
                f("tx_pps").round(),
                bits(f("rx_bps") + f("tx_bps")),
                bits(f("rx_bps")),
                bits(f("tx_bps")),
                s["drops_total"],
            );
            if let Some(secs) = s["pending_confirm_secs"].as_u64() {
                println!("!! unconfirmed commit: rolls back in {secs}s (ephctl config confirm)");
            }
            if let Some(e) = s["dataplane_error"].as_str() {
                println!("!! data plane NOT running: {e}");
                println!("   fix the config (ephctl config edit / rollback), then: ephctl restart");
            }
            if let Some(f) = s["fallback"].as_object() {
                println!(
                    "!! a newer config failed to start ({}); running the last one that worked. Failed config kept as {}",
                    str(&f["error"]),
                    str(&f["failed_file"])
                );
            }
            println!();
            table(
                &[
                    "INTERFACE",
                    "DEVICE",
                    "ADDRESS",
                    "MAC",
                    "XDP",
                    "ZC",
                    "NEW SESSIONS",
                    "ACCESS",
                ],
                rows(&s["ports"], |p| {
                    vec![
                        str(&p["name"]),
                        match p["vlan"].as_u64() {
                            Some(v) => format!("{}.{v}", str(&p["device"])),
                            None => str(&p["device"]),
                        },
                        str(&p["address"]),
                        str(&p["mac"]),
                        str(&p["xdp_mode"]),
                        yesno(&p["zero_copy"]),
                        if p["allow_new_sessions"].as_bool() == Some(true) {
                            "allowed".into()
                        } else {
                            "replies only".into()
                        },
                        p["management"]
                            .as_array()
                            .map(|m| m.iter().map(str).collect::<Vec<_>>().join(","))
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| "-".into()),
                    ]
                }),
            );
            let k = &s["counters"];
            println!(
                "\nrx {}  forwarded {}  originated {}  kernel-drops {}  fill-empty {}",
                k["rx"], k["forwarded"], k["originated"], k["kernel_drops"], k["fill_empty"]
            );
            let ss = &s["sessions"];
            println!(
                "sessions: {} active, {} created, {} expired ({} never answered, {} dropped early)   routes: {}   neighbours: {}",
                ss["active"], ss["created"], ss["expired"], ss["unanswered"], ss["early_dropped"], s["routes"], s["neighbors"]
            );
            if let Some(d) = s["drops"].as_object().filter(|d| !d.is_empty()) {
                println!(
                    "drops: {}",
                    d.iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join("  ")
                );
            }
        }
        Cmd::Sessions { limit } => {
            let v = c.get(&format!("/sessions?limit={limit}"))?;
            if json {
                print(&v);
                return Ok(());
            }
            table(
                &[
                    "PROTO",
                    "INITIATOR",
                    "RESPONDER",
                    "STATE",
                    "PKTS ->/<-",
                    "BYTES ->/<-",
                    "AGE",
                    "IDLE",
                ],
                rows(&v, |x| {
                    vec![
                        str(&x["proto"]),
                        str(&x["initiator"]),
                        str(&x["responder"]),
                        str(&x["state"]),
                        format!("{}/{}", x["packets"][0], x["packets"][1]),
                        format!("{}/{}", bytes(&x["bytes"][0]), bytes(&x["bytes"][1])),
                        dur(x["age_secs"].as_u64().unwrap_or(0)),
                        dur(x["idle_secs"].as_u64().unwrap_or(0)),
                    ]
                }),
            );
        }
        Cmd::Neighbors => {
            let v = c.get("/neighbors")?;
            if json {
                print(&v);
                return Ok(());
            }
            table(
                &["IP", "MAC", "INTERFACE"],
                rows(&v, |x| vec![str(&x["ip"]), str(&x["mac"]), str(&x["port"])]),
            );
        }
        Cmd::Wan => {
            let v = c.get("/wan")?;
            if json {
                print(&v);
                return Ok(());
            }
            let o = |x: &Value| if x.is_null() { "-".into() } else { str(x) };
            table(
                &[
                    "INTERFACE",
                    "MODE",
                    "STATE",
                    "ADDRESS",
                    "GATEWAY",
                    "DNS",
                    "DETAIL",
                ],
                rows(&v, |x| {
                    let dns: Vec<String> = x["dns"]
                        .as_array()
                        .map(|a| a.iter().map(str).collect())
                        .unwrap_or_default();
                    let p = &x["pppoe"];
                    let detail = match x["mode"].as_str() {
                        Some("pppoe") => match (p["last_error"].as_str(), p["session"].as_u64()) {
                            (_, Some(sid)) => format!(
                                "{} session {sid:#06x}, MTU {}, up {}",
                                o(&p["concentrator"]),
                                o(&p["mtu"]),
                                p["up_for_secs"].as_u64().map_or("-".into(), dur)
                            ),
                            (Some(e), None) => format!("last error: {e}"),
                            _ => format!("user {}", o(&p["username"])),
                        },
                        Some("dhcp") => format!(
                            "server {}, lease ends in {}",
                            o(&x["dhcp"]["server"]),
                            x["dhcp"]["expires_in_secs"]
                                .as_u64()
                                .map_or("-".into(), dur)
                        ),
                        _ => String::new(),
                    };
                    let detail = match x["apply_error"].as_str() {
                        Some(e) => format!("NOT APPLIED: {e}; {detail}"),
                        None => detail,
                    };
                    vec![
                        str(&x["interface"]),
                        str(&x["mode"]),
                        str(&x["state"]),
                        o(&x["address"]),
                        o(&x["gateway"]),
                        if dns.is_empty() {
                            "-".into()
                        } else {
                            dns.join(",")
                        },
                        detail,
                    ]
                }),
            );
        }
        Cmd::Dhcp => {
            let v = c.get("/dhcp")?;
            if json {
                print(&v);
                return Ok(());
            }
            let secs = |x: &Value| x.as_u64().map_or("-".into(), dur);
            let o = |x: &Value| if x.is_null() { "-".into() } else { str(x) };
            let clients = v["clients"].as_array().cloned().unwrap_or_default();
            if !clients.is_empty() {
                println!("Addresses the router got:");
                table(
                    &[
                        "INTERFACE",
                        "STATE",
                        "ADDRESS",
                        "GATEWAY",
                        "DNS",
                        "EXPIRES IN",
                    ],
                    clients
                        .iter()
                        .map(|x| {
                            let dns: Vec<String> = x["dns"]
                                .as_array()
                                .map(|a| a.iter().map(str).collect())
                                .unwrap_or_default();
                            vec![
                                str(&x["interface"]),
                                str(&x["state"]),
                                o(&x["address"]),
                                o(&x["gateway"]),
                                if dns.is_empty() {
                                    "-".into()
                                } else {
                                    dns.join(",")
                                },
                                secs(&x["expires_in_secs"]),
                            ]
                        })
                        .collect(),
                );
                println!();
            }
            let servers = v["servers"].as_array().cloned().unwrap_or_default();
            if servers.is_empty() && clients.is_empty() {
                println!("DHCP isn't used on any interface.");
            }
            for srv in servers {
                println!("Leases on {}:", str(&srv["interface"]));
                table(
                    &["IP", "MAC", "HOST NAME", "STATE", "EXPIRES IN"],
                    rows(&srv["leases"], |x| {
                        vec![
                            str(&x["ip"]),
                            str(&x["mac"]),
                            o(&x["hostname"]),
                            str(&x["state"]),
                            secs(&x["expires_in_secs"]),
                        ]
                    }),
                );
                println!();
            }
        }
        Cmd::Routes => {
            let v = c.get("/routes")?;
            if json {
                print(&v);
                return Ok(());
            }
            table(
                &["PREFIX", "VIA", "INTERFACE", "KIND"],
                rows(&v, |x| {
                    vec![
                        str(&x["prefix"]),
                        x["via"].as_str().unwrap_or("-").into(),
                        str(&x["port"]),
                        str(&x["kind"]),
                    ]
                }),
            );
        }
        Cmd::Overlay => {
            let v = c.get("/overlay")?;
            if json {
                print(&v);
                return Ok(());
            }
            if v["enabled"].as_bool() != Some(true) {
                println!("SD-WAN overlay not configured.");
                return Ok(());
            }
            println!(
                "Site {}  (overlay MTU {}, path generation {})\n",
                v["site_id"], v["mtu"], v["path_generation"]
            );
            table(
                &[
                    "TETHER", "VIA", "REMOTE", "SITE", "STATE", "RTT", "JITTER", "LOSS", "TX PKTS",
                    "RX PKTS",
                ],
                rows(&v["tethers"], |t| {
                    vec![
                        str(&t["name"]),
                        str(&t["interface"]),
                        str(&t["remote"]),
                        t["site"].to_string(),
                        if t["up"].as_bool() == Some(true) {
                            "up".into()
                        } else {
                            "DOWN".into()
                        },
                        format!("{:.1} ms", t["rtt_ms"].as_f64().unwrap_or(0.0)),
                        format!("{:.1} ms", t["jitter_ms"].as_f64().unwrap_or(0.0)),
                        format!("{:.1}%", t["loss_pct"].as_f64().unwrap_or(0.0)),
                        t["tx_packets"].to_string(),
                        t["rx_packets"].to_string(),
                    ]
                }),
            );
            println!();
            table(
                &["SITE", "CLASS", "USING"],
                rows(&v["paths"], |p| {
                    vec![
                        p["site"].to_string(),
                        str(&p["class"]),
                        p["tether"].as_str().unwrap_or("(no path)").into(),
                    ]
                }),
            );
        }
        Cmd::Sdwan { cmd } => match cmd {
            SdwanCmd::Sites => {
                let v = c.get("/overlay/sites")?;
                if json {
                    print(&v);
                    return Ok(());
                }
                if let Some(me) = v["this"].as_object() {
                    println!(
                        "This router: {} (site {}, {})\n",
                        str(&me["name"]),
                        str(&me["id"]),
                        str(&me["role"])
                    );
                }
                table(
                    &[
                        "SITE",
                        "ID",
                        "ROLE",
                        "CONNECTION",
                        "ENCRYPTION",
                        "ADDRESSES",
                        "TETHERS",
                    ],
                    rows(&v["sites"], |x| {
                        let list = |k: &str| {
                            x[k].as_array()
                                .map(|a| a.iter().map(str).collect::<Vec<_>>().join(","))
                                .filter(|s| !s.is_empty())
                                .unwrap_or_else(|| "-".into())
                        };
                        vec![
                            str(&x["name"]),
                            str(&x["id"]),
                            str(&x["role"]),
                            if x["connected"] == true {
                                "direct"
                            } else {
                                "via hub"
                            }
                            .into(),
                            encryption(x),
                            if x["addresses"].as_array().is_some_and(|a| a.is_empty()) {
                                "learned".into()
                            } else {
                                list("addresses")
                            },
                            list("tethers"),
                        ]
                    }),
                );
            }
            SdwanCmd::Identity => {
                let v = c.get("/overlay/identity")?;
                if json {
                    print(&v);
                    return Ok(());
                }
                match v["public_key"].as_str() {
                    Some(k) => println!("{k}"),
                    None => bail!("no SD-WAN key pair: see `ephctl log show -c sdwan`"),
                }
            }
            SdwanCmd::PublicKey { site, set, clear } => {
                if set.is_none() && !clear {
                    let v = c.get("/overlay/sites")?;
                    let x = v["sites"]
                        .as_array()
                        .and_then(|a| a.iter().find(|x| x["name"] == site.as_str()))
                        .with_context(|| format!("no site named {site:?}"))?;
                    match x["public_key"].as_str() {
                        Some(k) => println!("{k}"),
                        None => bail!("site {site} has no public key (it uses the pre-shared key)"),
                    }
                    return Ok(());
                }
                let body = serde_json::json!({ "site": site, "public_key": set });
                let v = c.call(
                    "POST",
                    "/overlay/public-key",
                    Some(("application/json", &body.to_string())),
                )?;
                if json {
                    print(&v);
                    return Ok(());
                }
                println!("Committed: {}.", describe(&v["applied"]));
                if set.is_some() {
                    println!("{site} needs this router's public key in its entry for this one:");
                    println!("`ephctl sdwan entry {site}` prints that entry.");
                } else {
                    println!("Tethers to {site} use the pre-shared key again: so must {site}.");
                }
            }
            SdwanCmd::Key {
                site,
                generate,
                set,
            } => {
                if !generate && set.is_none() {
                    let v = c.get(&format!("/overlay/key?site={}", encode(&site)))?;
                    match v["key"].as_str() {
                        Some(k) => println!("{k}"),
                        None => {
                            bail!("site {site} has no key yet: ephctl sdwan key {site} --generate")
                        }
                    }
                    return Ok(());
                }
                let mut body = serde_json::json!({ "site": site });
                if let Some(k) = set {
                    body["key"] = k.into();
                }
                let v = c.call(
                    "POST",
                    "/overlay/key",
                    Some(("application/json", &body.to_string())),
                )?;
                if json {
                    print(&v);
                    return Ok(());
                }
                println!("Key shared with {site}:\n{}\n", str(&v["key"]));
                println!("Committed: {}.", describe(&v["applied"]));
                println!("{site} needs the same key in its entry for this router: `ephctl sdwan entry {site}` prints that entry.");
            }
            SdwanCmd::Entry { site } => {
                let v = c.get(&format!("/overlay/entry?site={}", encode(&site)))?;
                if json {
                    print(&v);
                    return Ok(());
                }
                println!("# Paste into {site}'s configuration (ephctl config edit on {site}):");
                print!("{}", str(&v["toml"]));
                if v["dynamic"] == true {
                    println!("# This router has no fixed WAN address: {site} learns it, so {site} needs a fixed one.");
                }
            }
        },
        Cmd::Controller { cmd } => match cmd {
            ControllerCmd::Identity => {
                let v = c.get("/controller/identity")?;
                if json {
                    print(&v);
                    return Ok(());
                }
                match v["public_key"].as_str() {
                    Some(k) => println!("{k}"),
                    None => bail!("no controller key pair: see `ephctl log show -c mgmt`"),
                }
            }
        },
        Cmd::Route { cmd } => {
            let v = match cmd {
                RouteCmd::Add { prefix, via } => {
                    let body = serde_json::json!({ "prefix": prefix, "via": via }).to_string();
                    c.call("POST", "/routes", Some(("application/json", &body)))?
                }
                RouteCmd::Del { prefix } => c.call(
                    "DELETE",
                    &format!("/routes?prefix={}", encode(&prefix)),
                    None,
                )?,
            };
            report_commit(&v, json);
        }
        Cmd::Config { cmd } => config(&c, cmd, json)?,
        Cmd::Log { cmd } => log(&c, cmd, json)?,
        Cmd::System { cmd } => system(&c, cmd, json)?,
        Cmd::Restart => {
            let v = c.call("POST", "/restart", None)?;
            println!("{}", v["note"].as_str().unwrap_or("restarting"));
        }
    }
    Ok(())
}

fn log(c: &Client, cmd: LogCmd, json: bool) -> Result<()> {
    let print = |v: &Value| println!("{}", serde_json::to_string_pretty(v).unwrap());
    match cmd {
        LogCmd::Show {
            category,
            level,
            lines,
            follow,
        } => {
            let query = |after: u64, limit: usize| {
                let mut q = format!("/logs?after={after}&limit={limit}");
                if let Some(c) = &category {
                    q += &format!("&category={c}");
                }
                if let Some(l) = &level {
                    q += &format!("&level={l}");
                }
                q
            };
            let mut after = 0;
            let mut limit = lines;
            loop {
                let v = c.get(&query(after, limit))?;
                for r in v.as_array().into_iter().flatten() {
                    if json {
                        println!("{r}");
                    } else {
                        println!(
                            "{} {:<5} {:<11} {}",
                            str(&r["time"]),
                            str(&r["level"]).to_uppercase(),
                            str(&r["category"]),
                            str(&r["message"])
                        );
                    }
                    after = after.max(r["seq"].as_u64().unwrap_or(0));
                }
                if !follow {
                    break;
                }
                std::io::stdout().flush()?;
                limit = 5000;
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
        LogCmd::Levels => {
            let v = c.get("/logging")?;
            if json {
                print(&v);
                return Ok(());
            }
            table(
                &["CATEGORY", "GROUP", "LEVEL", "CONFIGURED", "FOR", "COVERS"],
                rows(&v["categories"], |k| {
                    let level = str(&k["level"]);
                    vec![
                        str(&k["name"]),
                        str(&k["group"]),
                        if k["packets"] == true && matches!(level.as_str(), "debug" | "trace") {
                            format!("{level} (tracing packets)")
                        } else {
                            level
                        },
                        str(&k["configured"]),
                        match (k["overridden"].as_bool(), k["expires_in_secs"].as_u64()) {
                            (Some(true), Some(s)) => dur(s),
                            (Some(true), None) => "until reset".into(),
                            _ => "".into(),
                        },
                        str(&k["about"]),
                    ]
                }),
            );
            if let Some(h) = v["host"].as_str() {
                println!("\nPacket tracing only for {h}");
            }
            let f = &v["files"];
            println!(
                "\nFiles in {}: debug.log {} of {}, audit.log {} of {}",
                str(&f["dir"]),
                bytes(&f["debug"]["bytes"]),
                bytes(&f["debug"]["limit"]),
                bytes(&f["audit"]["bytes"]),
                bytes(&f["audit"]["limit"]),
            );
            if let Some(e) = f["error"].as_str() {
                println!("!! log files: {e}");
            }
            if v["dropped"].as_u64().unwrap_or(0) > 0 {
                println!(
                    "!! {} log line(s) dropped (logging fell behind)",
                    v["dropped"]
                );
            }
        }
        LogCmd::Set {
            category,
            level,
            for_,
        } => {
            let mut body = serde_json::json!({ "category": category, "level": level });
            if let Some(f) = for_ {
                body["for"] = f.into();
            }
            let v = c.call(
                "PUT",
                "/logging",
                Some(("application/json", &body.to_string())),
            )?;
            if json {
                print(&v);
            } else {
                match v["expires_in_secs"].as_u64() {
                    Some(s) => println!("{category}: {} for {}", str(&v["level"]), dur_exact(s)),
                    None => println!("{category}: {} until `ephctl log reset`", str(&v["level"])),
                }
            }
        }
        LogCmd::Host { host } => {
            let body = serde_json::json!({ "host": host });
            let v = c.call(
                "PUT",
                "/logging/host",
                Some(("application/json", &body.to_string())),
            )?;
            match v["host"].as_str() {
                Some(h) => println!("packet tracing only for {h}"),
                None => println!("packet tracing for all hosts"),
            }
        }
        LogCmd::Reset => {
            c.call("DELETE", "/logging", None)?;
            println!("log levels back to the configuration");
        }
        LogCmd::Audit { lines } => {
            let v = c.get(&format!("/logs/audit?limit={lines}"))?;
            for l in v.as_array().into_iter().flatten() {
                println!("{}", str(l));
            }
        }
    }
    Ok(())
}

fn config(c: &Client, cmd: ConfigCmd, json: bool) -> Result<()> {
    let stage = |text: String| -> Result<()> {
        let p = c.call("PUT", "/config/candidate", Some(("text/plain", &text)))?;
        if json {
            println!("{}", serde_json::to_string_pretty(&p)?);
            return Ok(());
        }
        let diff = p["diff"].as_str().unwrap_or("");
        if diff.is_empty() {
            println!("No changes.");
        } else {
            print_diff(diff);
            println!(
                "\nCandidate staged ({}). Apply with: ephctl config commit",
                describe(&p["apply"])
            );
        }
        Ok(())
    };
    match cmd {
        ConfigCmd::Show => {
            let v = c.get("/config")?;
            print!("{}", v["running"].as_str().unwrap_or(""));
        }
        ConfigCmd::Load { file } => {
            stage(std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?)?
        }
        ConfigCmd::Edit => {
            let v = c.get("/config")?;
            let start = v["candidate"]
                .as_str()
                .or(v["running"].as_str())
                .unwrap_or("")
                .to_string();
            let path = std::env::temp_dir().join(format!("ephctl-{}.toml", std::process::id()));
            std::fs::write(&path, &start)?;
            let editor = std::env::var("VISUAL")
                .or_else(|_| std::env::var("EDITOR"))
                .unwrap_or_else(|_| "vi".into());
            let ok = std::process::Command::new(&editor)
                .arg(&path)
                .status()
                .with_context(|| format!("running {editor}"))?;
            let text = std::fs::read_to_string(&path)?;
            let _ = std::fs::remove_file(&path);
            if !ok.success() {
                bail!("{editor} exited with {ok}; nothing staged");
            }
            if text == start {
                println!("No changes.");
                return Ok(());
            }
            stage(text)?;
            if std::io::stdin().is_terminal() && ask("Commit now?")? {
                report_commit(&c.call("POST", "/config/commit", None)?, json);
            }
        }
        ConfigCmd::Commit { confirm } => {
            let q = confirm.map(|s| format!("?confirm={s}")).unwrap_or_default();
            report_commit(&c.call("POST", &format!("/config/commit{q}"), None)?, json);
        }
        ConfigCmd::Confirm => {
            c.call("POST", "/config/confirm", None)?;
            println!("Confirmed.");
        }
        ConfigCmd::Discard => {
            c.call("DELETE", "/config/candidate", None)?;
            println!("Candidate discarded.");
        }
        ConfigCmd::Rollback { to } => report_commit(
            &c.call("POST", &format!("/config/rollback?to={to}"), None)?,
            json,
        ),
        ConfigCmd::History => {
            let v = c.get("/config/history")?;
            if json {
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(());
            }
            table(
                &["#", "SAVED (unix)", "FILE"],
                rows(&v, |e| {
                    vec![
                        e["index"].to_string(),
                        e["saved_unix"].to_string(),
                        str(&e["file"]),
                    ]
                }),
            );
        }
    }
    Ok(())
}

fn system(c: &Client, cmd: SystemCmd, json: bool) -> Result<()> {
    let v = match cmd {
        SystemCmd::Status => c.get("/system")?,
        SystemCmd::Resources => {
            let v = c.get("/stats/resources")?;
            if json {
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(());
            }
            let f = |x: &Value| x.as_f64().unwrap_or(0.0);
            let u = |x: &Value| x.as_u64().unwrap_or(0);
            let sys = &v["system"];
            let m = &sys["memory"];
            println!(
                "CPU {:.1}% ({} cores) · load {} · up {}",
                f(&sys["cpu_pct"]),
                sys["cpu_each_pct"].as_array().map_or(0, |a| a.len()),
                sys["load"].as_array().map_or("-".into(), |a| a
                    .iter()
                    .map(|x| format!("{:.2}", f(x)))
                    .collect::<Vec<_>>()
                    .join(" ")),
                dur(u(&sys["uptime_secs"]))
            );
            println!(
                "Memory {} of {} used · huge pages {}/{}",
                size(u(&m["used"])),
                size(u(&m["total"])),
                u(&m["hugepages_total"]).saturating_sub(u(&m["hugepages_free"])),
                u(&m["hugepages_total"])
            );
            for d in sys["disks"].as_array().cloned().unwrap_or_default() {
                println!(
                    "Disk {}: {} free of {}",
                    str(&d["path"]),
                    size(u(&d["free"])),
                    size(u(&d["total"]))
                );
            }
            let p = &v["process"];
            println!(
                "ephemerisd: {:.1}% of one core, {} resident (packet buffers {}, session tables {}, forwarding table {})\n",
                f(&p["cpu_pct"]),
                size(u(&p["rss"])),
                size(u(&p["memory"]["packet_buffers"])),
                size(u(&p["memory"]["session_tables"])),
                size(u(&p["memory"]["forwarding_table"]))
            );
            table(
                &["WORKER", "BUSY", "SESSIONS", "NEIGHBOURS", "NAT"],
                rows(&v["workers"], |w| {
                    vec![
                        str(&w["id"]),
                        format!("{:.1}%", f(&w["busy_pct"])),
                        format!("{}/{}", u(&w["sessions"]), u(&w["sessions_max"])),
                        format!("{}/{}", u(&w["neighbors"]), u(&w["neighbors_max"])),
                        u(&w["nat"]).to_string(),
                    ]
                }),
            );
            println!();
            table(
                &["TABLE", "USED", "LIMIT", "%", "NOTE"],
                rows(&v["capacity"], |c| {
                    let (used, max) = (u(&c["used"]), c["max"].as_u64());
                    vec![
                        str(&c["name"]),
                        used.to_string(),
                        max.map_or("-".into(), |m| m.to_string()),
                        max.filter(|&m| m > 0).map_or("-".into(), |m| {
                            format!("{:.0}%", 100.0 * used as f64 / m as f64)
                        }),
                        str(&c["note"]),
                    ]
                }),
            );
            return Ok(());
        }
        SystemCmd::Check => c.call("POST", "/system/update/check", None)?,
        SystemCmd::Update => c.call("POST", "/system/update", None)?,
        SystemCmd::Reboot { force } => {
            let st = c.get("/system")?;
            let u = &st["update"];
            match u["phase"].as_str() {
                Some("installing") if !force => bail!(
                    "an update is still installing ({}): wait until `ephctl system status` says it's installed, or reboot anyway with --force",
                    u["version"].as_str().unwrap_or("the newest version")
                ),
                Some("installed") => println!("Rebooting into {}…", str(&u["version"])),
                _ => println!("Rebooting…"),
            }
            c.call("POST", "/system/reboot", None)?
        }
        SystemCmd::Password { reset } => {
            let current = if reset {
                None
            } else {
                Some(read_secret("Current password: ")?)
            };
            let new = read_secret("New password: ")?;
            if read_secret("Repeat new password: ")? != new {
                bail!("the passwords don't match");
            }
            let mut body = serde_json::json!({ "new": new });
            if let Some(c) = current {
                body["current"] = c.into();
            }
            let body = body.to_string();
            c.call(
                "POST",
                "/system/password",
                Some(("application/json", &body)),
            )
            .map_err(|e| {
                match e.to_string().contains("current password is wrong") {
                    true => {
                        anyhow::anyhow!(
                            "{e}\nForgotten it? As root: ephctl system password --reset"
                        )
                    }
                    false => e,
                }
            })?;
            println!("Password changed.");
            return Ok(());
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    if let Some(build) = v["build"].as_str() {
        println!(
            "Ephemeris {}, build {build}",
            v["version"].as_str().unwrap_or("?")
        );
        let u = &v["update"];
        let ver = u["version"].as_str().unwrap_or("the newest version");
        match u["phase"].as_str() {
            Some("installing") => println!(
                "update: installing {ver} into the idle slot (the router keeps forwarding)"
            ),
            Some("installed") => {
                println!("update: {ver} is installed: `ephctl system reboot` switches to it")
            }
            Some("failed") => println!("update: failed: {}", str(&u["detail"])),
            _ => println!("update: nothing pending (`ephctl system check` looks for one)"),
        }
    }
    if let Some(list) = v["versions"].as_str() {
        print!("{list}");
        match v["available"].as_str() {
            Some(n) => {
                println!("\nNewer version available: {n}. Install with: ephctl system update")
            }
            None => println!("\nUp to date."),
        }
    }
    if let Some(note) = v["note"].as_str() {
        println!("{note}");
        if v["version"].is_string() || v["ok"] == true {
            println!("Follow it with `ephctl system status`.");
        }
    } else if v["ok"].as_bool() == Some(true) {
        println!("OK.");
    }
    Ok(())
}

fn report_commit(v: &Value, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(v).unwrap());
        return;
    }
    if let Some(d) = v["diff"].as_str().filter(|d| !d.is_empty()) {
        print_diff(d);
        println!();
    }
    println!("Committed: {}.", describe(&v["applied"]));
    if let Some(s) = v["confirm_within_secs"].as_u64() {
        println!("Run `ephctl config confirm` within {s}s, or the change rolls back.");
    }
}

fn describe(apply: &Value) -> &'static str {
    match apply.as_str() {
        Some("live") => "applied live",
        Some("restart-required") => "saved; takes effect after `ephctl restart`",
        _ => "no effect on the data plane",
    }
}

fn print_diff(d: &str) {
    let color = std::io::stdout().is_terminal();
    for line in d.lines() {
        match (color, line.chars().next()) {
            (true, Some('+')) => println!("\x1b[32m{line}\x1b[0m"),
            (true, Some('-')) => println!("\x1b[31m{line}\x1b[0m"),
            _ => println!("{line}"),
        }
    }
}

/// Read a line from the terminal without echoing it.
fn read_secret(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let tty = std::io::stdin().is_terminal();
    let stty = |arg: &str| {
        let _ = std::process::Command::new("stty")
            .arg(arg)
            .stdin(std::process::Stdio::inherit())
            .status();
    };
    if tty {
        stty("-echo");
    }
    let mut line = String::new();
    let r = std::io::stdin().read_line(&mut line);
    if tty {
        stty("echo");
        println!();
    }
    r?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn ask(q: &str) -> Result<bool> {
    print!("{q} [y/N] ");
    std::io::stdout().flush()?;
    let mut a = String::new();
    std::io::stdin().read_line(&mut a)?;
    Ok(matches!(a.trim(), "y" | "Y" | "yes"))
}

// ---- formatting helpers

fn str(v: &Value) -> String {
    v.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| v.to_string())
}

fn yesno(v: &Value) -> String {
    if v.as_bool() == Some(true) {
        "yes".into()
    } else {
        "no".into()
    }
}

fn rows(v: &Value, f: impl Fn(&Value) -> Vec<String>) -> Vec<Vec<String>> {
    v.as_array()
        .map(|a| a.iter().map(f).collect())
        .unwrap_or_default()
}

fn table(head: &[&str], rows: Vec<Vec<String>>) {
    let mut w: Vec<usize> = head.iter().map(|h| h.len()).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let s: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<width$}", width = w[i]))
            .collect();
        println!("{}", s.join("  ").trim_end());
    };
    line(head.iter().map(|h| h.to_string()).collect());
    if rows.is_empty() {
        println!("(none)");
    }
    for r in rows {
        line(r);
    }
}

/// Bytes, scaled: "512 B", "3.4 MB", "1.9 GB".
fn size(b: u64) -> String {
    let (v, u) = match b {
        b if b >= 1 << 30 => (b as f64 / (1u64 << 30) as f64, "GB"),
        b if b >= 1 << 20 => (b as f64 / (1u64 << 20) as f64, "MB"),
        b if b >= 1 << 10 => (b as f64 / 1024.0, "kB"),
        b => return format!("{b} B"),
    };
    format!("{v:.1} {u}")
}

/// Bits per second, scaled: "950 bps", "12.5 kbps", "3.20 Mbps".
fn bits(x: f64) -> String {
    let (v, u) = match x {
        x if x >= 1e9 => (x / 1e9, "Gbps"),
        x if x >= 1e6 => (x / 1e6, "Mbps"),
        x if x >= 1e3 => (x / 1e3, "kbps"),
        x => return format!("{x:.0} bps"),
    };
    match v {
        v if v >= 100.0 => format!("{v:.0} {u}"),
        v if v >= 10.0 => format!("{v:.1} {u}"),
        v => format!("{v:.2} {u}"),
    }
}

fn dur(s: u64) -> String {
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86399 => format!("{}h{}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d", s / 86400),
    }
}

/// 90 -> "1m30s": exact, for what was just set.
fn dur_exact(s: u64) -> String {
    let mut out = String::new();
    for (v, unit) in [(s / 3600, "h"), (s % 3600 / 60, "m"), (s % 60, "s")] {
        if v > 0 {
            out += &format!("{v}{unit}");
        }
    }
    if out.is_empty() {
        out = "0s".into();
    }
    out
}

fn bytes(v: &Value) -> String {
    let mut b = v.as_f64().unwrap_or(0.0);
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut i = 0;
    while b >= 1000.0 && i < units.len() - 1 {
        b /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{b}B")
    } else {
        format!("{b:.1}{}", units[i])
    }
}

/// Percent-encode a query value (prefixes contain '/').
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
