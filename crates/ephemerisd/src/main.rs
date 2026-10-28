//! `ephemerisd`: the Ephemeris router daemon.
//!
//! Reads a TOML config, takes over the data-plane interfaces with AF_XDP,
//! routes IPv4 between them statefully, and serves a management API and
//! web portal.

// The management code is only wired up by the Linux-only `run` module.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod config;
mod dhcp;
mod files;
#[cfg(target_os = "linux")]
mod host;
mod logging;
mod memory;
mod mgmt;
mod overlay_state;
mod pppoe;
mod report;
#[cfg(target_os = "linux")]
mod run;
mod sdwan;
mod startup;
#[cfg(target_os = "linux")]
mod worker;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Ephemeris router daemon")]
struct Args {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "/etc/ephemeris/ephemeris.toml")]
    config: PathBuf,
    /// Validate the configuration, print the resulting forwarding table, and exit.
    #[arg(long)]
    check: bool,
    /// Read a password on stdin and print its hash, the way the admin
    /// password is stored (yescrypt); first boot uses it.
    #[arg(long)]
    hash_password: bool,
    /// Print this router's SD-WAN public key (what other routers put in
    /// their `[[site]]` entry for it), making its key pair first if there
    /// isn't one. The key pair lives next to the config file.
    #[arg(long)]
    sdwan_identity: bool,
    /// Development only (not in Linux builds): serve the web portal on
    /// 127.0.0.1:8080 against the config file, without a data plane.
    /// Sign in as admin / dev.
    #[cfg(not(target_os = "linux"))]
    #[arg(long)]
    dev_portal: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.hash_password {
        let mut pw = String::new();
        std::io::stdin().read_line(&mut pw)?;
        let pw = pw.strip_suffix('\n').unwrap_or(&pw);
        println!("{}", mgmt::auth::hash_password(pw)?);
        return Ok(());
    }
    if args.sdwan_identity {
        let dir = args.config.parent().unwrap_or(std::path::Path::new("."));
        println!(
            "{}",
            sdwan::hex(&sdwan::Identity::load_or_create(dir)?.public)
        );
        return Ok(());
    }
    logging::sink::init();
    #[cfg(not(target_os = "linux"))]
    if args.dev_portal {
        return mgmt::dev::serve(&args.config);
    }
    if args.check {
        config::print_summary(&config::Config::load(&args.config)?)?;
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    return run::run(&args.config);

    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("the data plane needs Linux (AF_XDP); use --check to validate a config here")
}
