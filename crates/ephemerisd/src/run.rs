//! Bring-up: resolve interfaces, build per-worker UMEMs and sockets, attach
//! the XDP programs, start the workers, and print stats until told to stop.

use crate::config::Config;
use crate::memory::FRAME_SIZE;
use crate::mgmt::configmgr::ConfigManager;
use crate::mgmt::paths::{PathSelector, TICK_MS};
use crate::mgmt::{api, load_or_create_token, PortRuntime, Shared, Summary};
use crate::overlay_state;
use crate::report::{Control, Report};
use crate::sdwan::{Action, Handshakes, Identity};
use crate::startup::{self, StartupState};
use crate::worker::{Wake, Worker};
use anyhow::{bail, Context, Result};
use eph_dataplane::overlay::{ReplayGuard, DEFAULT_MTU};
use eph_dataplane::{Pipeline, Port};
use eph_packet::eth;
use eph_xdp::{iface, BindMode, Promisc, Umem, XdpMode, XdpRedirect, Xsk, XskConfig, XskMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

pub fn run(config_path: &Path) -> Result<()> {
    // SAFETY: `on_signal` only stores to an atomic, which is
    // async-signal-safe; it lives for the whole program.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
    // Older kernels charge UMEM and BPF maps against RLIMIT_MEMLOCK.
    let unlimited = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `unlimited` is a live rlimit, read by the kernel during the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &unlimited) } != 0 {
        warn!(target: crate::logging::cat::SYSTEM,
            "could not lift the locked-memory limit ({}): packet buffers may fail to allocate",
            std::io::Error::last_os_error()
        );
    }
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let mut startup = StartupState {
        fallback: startup::take_note(config_path),
        ..Default::default()
    };
    if let Some(f) = &startup.fallback {
        warn!(target: crate::logging::cat::CONFIG,
            "started with the last configuration that worked: the newer one failed ({}); it was kept as {}",
            f.error, f.failed_file
        );
    }
    // Anything that stops the data plane from starting: go back to the last
    // config that worked (and restart with it), or run management only.
    let dhcp_state = Arc::new(Mutex::new(crate::dhcp::DhcpState::default()));
    let manager = match ConfigManager::open(config_path) {
        Ok(m) => m
            .check_nics(crate::mgmt::nics::list)
            .check_with_leases(dhcp_state.clone()),
        Err(e) => return Err(fall_back(config_path, &text, e)),
    };
    let cfg = manager.running().clone();
    crate::logging::control().apply_config(&cfg.logging);
    crate::mgmt::ssh::apply(&cfg.ssh);
    let state_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    // This router's SD-WAN key pair: made on first start, so its public key
    // can be given to other routers before any site uses it.
    let identity = match Identity::load_or_create(&state_dir) {
        Ok(i) => Some(i),
        Err(e) => {
            error!(target: crate::logging::cat::SDWAN,
                "SD-WAN key pair unavailable ({e:#}): tethers to sites with a public_key stay down");
            None
        }
    };
    let dp = match start_dataplane(&cfg, &state_dir) {
        Ok(dp) => {
            if let Err(e) = startup::mark_good(config_path, &text) {
                warn!(target: crate::logging::cat::CONFIG, "could not save this config as the last good one: {e:#}");
            }
            dp
        }
        Err(e) => {
            let e = fall_back(config_path, &text, e);
            if e.to_string().starts_with(RESTARTING) {
                return Err(e);
            }
            error!(target: crate::logging::cat::CONFIG, "data plane not started: {e:#}. Running the management plane only: fix the configuration, then restart.");
            startup.dataplane_error = Some(format!("{e:#}"));
            Dataplane::none(&cfg)?
        }
    };
    let Dataplane {
        workers,
        ports,
        fib,
        overlay,
        reports,
        txs,
        runtime,
        handles,
        links,
        promisc,
        epoch,
        replay,
        punts,
        handshakes,
        endpoints,
        umem_bytes,
        detail,
    } = dp;
    let d = &cfg.dataplane;

    // ---- management plane on its own thread and async runtime
    let m = cfg.management.clone();
    let shared = Arc::new(Shared {
        build: build_string(),
        started: Instant::now(),
        runtime,
        workers: workers as usize,
        ports: RwLock::new(ports.clone()),
        fib: RwLock::new(fib.clone()),
        paths: RwLock::new(Arc::new(eph_dataplane::overlay::PathTable::empty(&overlay))),
        health: RwLock::new(vec![Default::default(); overlay.tethers.len()]),
        overlay: overlay.clone(),
        reports: reports.clone(),
        control: Mutex::new(txs),
        config: Mutex::new(manager),
        // A management-plane problem must never stop the data plane: log it
        // and run without API token auth (logins still work).
        token: if m.enabled {
            load_or_create_token(&m.token_file).unwrap_or_else(|e| {
                error!(target: crate::logging::cat::MGMT, "API token unavailable ({e:#}); token authentication disabled");
                String::new()
            })
        } else {
            String::new()
        },
        auth: crate::mgmt::auth::Auth::new(
            std::path::Path::new(&m.token_file)
                .parent()
                .unwrap_or(std::path::Path::new("/var/lib/ephemeris")),
        ),
        startup,
        dhcp: dhcp_state,
        endpoints,
        sdwan: crate::sdwan::SdwanState {
            public_key: identity.as_ref().map(|i| i.public),
            ..Default::default()
        },
        history: Default::default(),
        update: Default::default(),
        system: Default::default(),
        umem_bytes,
        detail,
        stop: &STOP,
    });
    let mgmt = m.enabled.then(|| {
        let shared = shared.clone();
        let (listen, moved) = m.bind_addr();
        if moved {
            warn!(target: crate::logging::cat::MGMT,
                "management.listen {} is not a loopback address: plain HTTP stays on {listen}, \
                 and the portal is served over HTTPS by nginx (https://<router>:8443/). \
                 Set management.insecure_remote_http = true to serve plain HTTP on the network.",
                m.listen
            );
        } else if !listen.ip().is_loopback() {
            warn!(target: crate::logging::cat::MGMT, "management API on {listen} over plain HTTP: passwords cross the network unencrypted");
        }
        std::thread::Builder::new()
            .name("eph-mgmt".into())
            .spawn(move || {
                // The portal and API give way to the data plane under load.
                lower_priority(10);
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                // A broken management plane must never take the data plane down.
                if let Err(e) = rt.block_on(api::serve(shared, listen)) {
                    error!(target: crate::logging::cat::MGMT, "management API stopped: {e:#}");
                }
            })
            .expect("spawning management thread")
    });

    // ---- DHCP server and client (only with a running data plane: they
    // send and receive through it)
    let dhcp = punts.map(|rx| {
        let shared = shared.clone();
        let dir = state_dir.clone();
        std::thread::Builder::new()
            .name("eph-dhcp".into())
            .spawn(move || {
                lower_priority(5);
                crate::dhcp::service::run(&shared, rx, &STOP, &dir)
            })
            .expect("spawning DHCP service")
    });

    // ---- SD-WAN control loop
    let selector = (overlay.enabled() && workers > 0).then(|| {
        let shared = shared.clone();
        info!(target: crate::logging::cat::SDWAN,
            "SD-WAN: site {}, {} tether(s) to {} site(s)",
            overlay.site_id,
            overlay.tethers.len(),
            overlay.sites.len()
        );
        std::thread::Builder::new()
            .name("eph-paths".into())
            .spawn(move || path_loop(&shared, epoch, &replay, &state_dir))
            .expect("spawning path selector")
    });

    // ---- SD-WAN handshakes, for sites configured with a public key
    let names: Vec<(u16, String)> = cfg.sites.iter().map(|s| (s.id, s.name.clone())).collect();
    let handshaker = match (identity, handshakes) {
        (Some(me), Some(rx)) if workers > 0 => {
            let pref = cfg.overlay.as_ref().map(|o| o.cipher).unwrap_or_default();
            let aes_hw = eph_dataplane::overlay::Cipher::aes_in_hardware();
            let hs = Handshakes::new(me, overlay.clone(), &names).with_ciphers(pref, aes_hw);
            if hs.active() {
                info!(target: crate::logging::cat::SDWAN,
                    "SD-WAN ciphers: {pref:?}; AES in hardware: {}", if aes_hw { "yes" } else { "no" });
            }
            hs.active().then(|| {
                let shared = shared.clone();
                std::thread::Builder::new()
                    .name("eph-sdwan".into())
                    .spawn(move || handshake_loop(&shared, epoch, hs, rx))
                    .expect("spawning SD-WAN handshakes")
            })
        }
        _ => None,
    };

    let log_stats = d.stats_interval_secs > 0;
    let interval = Duration::from_secs(d.stats_interval_secs.max(1));
    let mut next = Instant::now() + interval;
    let sample_every = Duration::from_secs(crate::mgmt::history::INTERVAL_SECS);
    let mut next_sample = Instant::now();
    let started = Instant::now();
    let mut sysinfo = crate::mgmt::sysinfo::Sampler::default();
    let mut trace_seen = crate::logging::control().trace_version();
    while !STOP.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        // Temporary log levels that ran out; the workers follow any change
        // to what's traced.
        let log = crate::logging::control();
        for c in log.expire(Instant::now()) {
            info!(target: "system", "log category {c}: back to its configured level");
        }
        if log.trace_version() != trace_seen {
            trace_seen = log.trace_version();
            let t = log.trace_config();
            for tx in shared.control.lock().unwrap().iter() {
                let _ = tx.send(Control::SetTrace(t));
            }
        }
        if Instant::now() >= next_sample {
            next_sample += sample_every;
            let unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let sum = shared.summary();
            let at = started.elapsed().as_secs_f64();
            // The data partition is the one that can fill up (config
            // history, leases, logs); the root is read-only.
            let sys = sysinfo.sample(at, &["/var"]);
            shared
                .history
                .lock()
                .unwrap()
                .record(at, unix, &sum, Some(&sys));
            *shared.system.lock().unwrap() = Some(sys);
        }
        if log_stats && Instant::now() >= next && workers > 0 {
            next += interval;
            if d.show_sessions > 0 {
                // Have the workers gather their newest sessions for next time.
                shared.detail.store(
                    crate::report::unix_ms() + 2 * interval.as_millis() as u64 + 2_000,
                    Ordering::Relaxed,
                );
            }
            print_stats(&shared, d.show_sessions);
        }
    }
    info!(target: crate::logging::cat::SYSTEM, "stopping");
    for h in handles {
        let _ = h.join();
    }
    if let Some(m) = mgmt {
        let _ = m.join();
    }
    if let Some(p) = selector {
        let _ = p.join();
    }
    if let Some(h) = dhcp {
        let _ = h.join();
    }
    if let Some(h) = handshaker {
        let _ = h.join();
    }
    print_stats(&shared, d.show_sessions);
    drop(links); // detaches XDP; the kernel would also do this when we exit
    drop(promisc);
    Ok(())
}

/// The image build this is, e.g. "0.7.1-9003193": the release and the
/// commit it was built from (added if the version doesn't already say it).
fn build_string() -> String {
    let read = |f: &str| {
        std::fs::read_to_string(format!("/usr/lib/ephemeris/{f}"))
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
    };
    match (read("version"), read("commit")) {
        (Some(v), Some(c)) if v.ends_with(&format!("-{c}")) => v,
        (Some(v), Some(c)) => format!("{v} (commit {c})"),
        (Some(v), None) => v,
        (None, _) => format!("{} (dev)", env!("CARGO_PKG_VERSION")),
    }
}

const RESTARTING: &str = "restarting with the last configuration that worked";

/// The data plane can't start with `text`: restore the last good config if
/// there is a different one (the returned error then starts with
/// [`RESTARTING`], and ephemerisd should exit so systemd restarts it).
fn fall_back(config_path: &Path, text: &str, e: anyhow::Error) -> anyhow::Error {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match startup::fall_back(config_path, text, &format!("{e:#}"), now) {
        Ok(true) => {
            error!(target: crate::logging::cat::CONFIG, "configuration failed: {e:#}");
            anyhow::anyhow!("{RESTARTING} (the failed one was kept next to it)")
        }
        Ok(false) => e,
        Err(io) => e.context(format!(
            "and the last good config couldn't be restored: {io:#}"
        )),
    }
}

/// A running data plane (or none, when only management runs).
struct Dataplane {
    workers: u32,
    ports: Arc<[Port]>,
    fib: Arc<eph_fib::Fib<eph_dataplane::NextHop>>,
    overlay: Arc<eph_dataplane::overlay::Overlay>,
    reports: Vec<Arc<Mutex<Report>>>,
    txs: Vec<mpsc::Sender<Control>>,
    runtime: Vec<PortRuntime>,
    handles: Vec<std::thread::JoinHandle<()>>,
    links: Vec<XdpRedirect>,
    /// Promiscuous mode on cards carrying VLANs, released when dropped.
    promisc: Vec<Promisc>,
    epoch: Instant,
    /// Received overlay counters, shared by the workers (persisted by the
    /// path loop).
    replay: Arc<ReplayGuard>,
    /// DHCP packets the workers hand to the control plane.
    punts: Option<mpsc::Receiver<eph_dataplane::Punt>>,
    /// SD-WAN handshake messages, likewise.
    handshakes: Option<mpsc::Receiver<eph_dataplane::HandshakeIn>>,
    /// Learned addresses of SD-WAN peers without a fixed one.
    endpoints: Arc<eph_dataplane::overlay::Endpoints>,
    /// Packet buffer memory reserved, all workers.
    umem_bytes: u64,
    /// Shared with the workers: until when the API wants session lists.
    detail: crate::report::DetailWanted,
}

impl Dataplane {
    /// No workers: the configured ports are still shown, as not running.
    fn none(cfg: &Config) -> Result<Self> {
        let ports: Arc<[Port]> = cfg.ports(|_| Ok([0; 6]))?.into();
        let overlay = Arc::new(cfg.overlay()?);
        Ok(Dataplane {
            workers: 0,
            fib: Arc::new(cfg.fib(&ports)?),
            replay: Arc::new(ReplayGuard::new(overlay.sites.len())),
            endpoints: Arc::new(eph_dataplane::overlay::Endpoints::new(
                overlay.tethers.len(),
            )),
            umem_bytes: 0,
            detail: Default::default(),
            overlay,
            runtime: cfg
                .interfaces
                .iter()
                .map(|i| PortRuntime {
                    device: i.device.clone(),
                    xdp_mode: "not running".into(),
                    zero_copy: false,
                })
                .collect(),
            ports,
            reports: vec![],
            txs: vec![],
            handles: vec![],
            punts: None,
            handshakes: None,
            links: vec![],
            promisc: vec![],
            epoch: Instant::now(),
        })
    }
}

/// Resolve interfaces, build UMEMs and sockets, attach XDP, start the
/// workers. On error nothing is left running: sockets and XDP links close
/// when dropped, and workers only start once everything else worked.
fn start_dataplane(cfg: &Config, state_dir: &Path) -> Result<Dataplane> {
    let d = &cfg.dataplane;
    let workers = d.workers;
    let xdp_mode = match d.xdp_mode.as_str() {
        "auto" => XdpMode::Auto,
        "native" => XdpMode::Native,
        "generic" => XdpMode::Generic,
        m => bail!("dataplane.xdp_mode: unknown mode {m:?}"),
    };
    let bind_mode = match d.bind_mode.as_str() {
        "auto" => BindMode::Auto,
        "copy" => BindMode::Copy,
        "zerocopy" => BindMode::ZeroCopy,
        m => bail!("dataplane.bind_mode: unknown mode {m:?}"),
    };

    // ---- network cards: one socket per card and worker, however many
    // (VLAN) interfaces share it
    let cards = cfg.cards();
    let mut ifindexes = Vec::new();
    let mut promisc = Vec::new();
    for &dev in &cards {
        let users = || {
            cfg.interfaces
                .iter()
                .filter(|i| i.device == dev)
                .map(|i| i.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let idx = iface::ifindex(dev).with_context(|| format!("interface {}", users()))?;
        if !iface::is_up(dev) {
            bail!("device {dev} is down; run: ip link set dev {dev} up");
        }
        let queues = iface::rx_queues(dev)?;
        if queues < workers {
            bail!(
                "device {dev} has {queues} RX queue(s) but {workers} workers are configured \
                 (try: ethtool -L {dev} combined {workers})"
            );
        }
        if queues > workers {
            warn!(target: crate::logging::cat::INTERFACE,
                "device {dev} has {queues} RX queues but only {workers} worker(s): traffic hashed to \
                 queues {workers}..{} will be dropped. Fix: ethtool -L {dev} combined {workers}",
                queues - 1
            );
        }
        // Tags must reach the data plane as they are on the wire: a card
        // that strips them would make every VLAN look untagged.
        match iface::disable_vlan_stripping(dev) {
            Ok(true) => {
                info!(target: crate::logging::cat::INTERFACE, "{dev}: VLAN stripping turned off")
            }
            Ok(false) => {}
            Err(e) => warn!(target: crate::logging::cat::INTERFACE,
                "{dev}: could not turn VLAN stripping off ({e}); tagged frames may arrive \
                 untagged. Try: ethtool -K {dev} rxvlan off"
            ),
        }
        if cfg
            .interfaces
            .iter()
            .any(|i| i.device == dev && i.vlan.is_some())
        {
            promisc.push(
                Promisc::enable(idx)
                    .with_context(|| format!("{dev}: promiscuous mode (needed for its VLANs)"))?,
            );
            info!(target: crate::logging::cat::INTERFACE, "{dev}: carries VLANs ({}); promiscuous mode on", users());
        }
        ifindexes.push(idx);
    }
    // How the cards spread packets over the workers, so NAT replies (and
    // tether traffic) reach the worker that holds their session.
    let steering = Arc::new(if workers > 1 {
        read_steering(cfg, &cards)
    } else {
        eph_dataplane::steer::Steering::default()
    });
    let ports: Arc<[Port]> = cfg
        .ports(|i| {
            let s = iface::mac(&i.device)?;
            eth::parse_mac(&s).with_context(|| format!("device {}: bad MAC {s:?}", i.device))
        })?
        .into();
    let fib = Arc::new(cfg.fib(&ports)?);
    let mut overlay = cfg.overlay()?;
    // Overlay crypto: claim this start's run number before anything is
    // sealed with a pre-shared key. Without one those tethers stay down
    // rather than risk reusing a nonce; the rest of the router (and tethers
    // with session keys, which don't use runs) runs normally.
    let pre_shared = |o: &eph_dataplane::overlay::Overlay, t: &eph_dataplane::overlay::Tether| {
        o.crypto(t.site_idx) == eph_dataplane::overlay::PeerCrypto::PreShared
    };
    let run = if overlay.enabled() {
        match overlay_state::claim_run(state_dir) {
            Ok(run) => run,
            Err(e) => {
                error!(target: crate::logging::cat::SDWAN, "SD-WAN tethers with a pre-shared key disabled: {e:#}");
                let o = overlay.clone();
                for t in overlay.tethers.iter_mut().filter(|t| pre_shared(&o, t)) {
                    t.key = None;
                }
                0
            }
        }
    } else {
        0
    };
    for t in overlay
        .tethers
        .iter()
        .filter(|t| t.key.is_none() && pre_shared(&overlay, t))
    {
        warn!(target: crate::logging::cat::SDWAN, "tether {} has no key or public_key: it stays down", t.name);
    }
    if overlay.enabled() && overlay.mtu > DEFAULT_MTU {
        warn!(target: crate::logging::cat::SDWAN,
            "overlay MTU {} needs an underlay MTU of at least {} on every WAN path",
            overlay.mtu,
            overlay.mtu as usize + 60
        );
    }
    let replay = Arc::new(ReplayGuard::new(overlay.sites.len()));
    let endpoints = Arc::new(eph_dataplane::overlay::Endpoints::new(
        overlay.tethers.len(),
    ));
    for (site, worker, seen) in overlay_state::load_peers(state_dir) {
        if let Some(idx) = overlay.sites.iter().position(|&s| s == site) {
            replay.restore(idx, worker, seen);
        }
    }
    // Peers found elsewhere before the restart: start there (unless the
    // config was changed since: then the configured address wins).
    for (name, configured, ip, port) in overlay_state::load_moved(state_dir) {
        if let Some(t) = overlay
            .tethers
            .iter()
            .find(|t| t.name == name && t.remote == configured)
        {
            endpoints.learn(t.id, ip, port);
            info!(target: crate::logging::cat::SDWAN,
                "tether {name}: its peer was last at {ip}, not the configured {configured}: starting there");
        }
    }
    let overlay = Arc::new(overlay);
    let nat = Arc::new(cfg.nat()?);
    for p in ports.iter() {
        info!(target: crate::logging::cat::INTERFACE,
            "port {} {} dev {} mac {} addr {}/{}",
            p.id,
            p.name,
            cfg.interfaces[p.id as usize].link_name(),
            eth::fmt_mac(&p.mac),
            p.addr,
            p.subnet.len()
        );
    }
    info!(target: crate::logging::cat::ROUTE, "forwarding table: {} route(s)", fib.routes().len());

    // ---- memory: size "auto" session tables, and refuse what can't fit
    // (that falls back to the last config that worked) before allocating.
    let mem = crate::memory::machine();
    let plan = crate::memory::plan(cfg, fib.memory_bytes() as u64, mem.as_ref())?;
    info!(target: crate::logging::cat::SYSTEM,
        "memory: {} session(s) per worker{}; reserving {} MiB (packet buffers {} MiB, session \
         tables {} MiB, forwarding table {} MiB) of {} MiB available",
        plan.sessions_per_worker,
        if plan.auto { " (auto)" } else { "" },
        plan.ordinary_memory() >> 20,
        plan.packet_buffers >> 20,
        plan.session_tables >> 20,
        plan.forwarding_table >> 20,
        plan.available.map_or("?".into(), |a| (a >> 20).to_string()),
    );
    if let Some(w) = &plan.warning {
        warn!(target: crate::logging::cat::SYSTEM, "memory: {w}");
    }

    // ---- per-worker UMEM + one socket per card on queue `w`
    let ring = d.ring_size;
    let xcfg = XskConfig {
        rx_size: ring,
        tx_size: ring,
        fill_size: ring,
        comp_size: ring,
        bind_mode,
    };
    let frames = crate::memory::umem_frames(cards.len(), ring);

    let maps: Vec<XskMap> = cards
        .iter()
        .map(|_| XskMap::new(workers))
        .collect::<Result<_, _>>()?;
    // One control channel per worker: neighbour updates from siblings, and
    // FIB/port changes from the management plane.
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..workers).map(|_| mpsc::channel()).unzip();
    // Bounded: if the control plane falls behind (a DHCP flood), packets
    // for it are dropped and counted, never queued without end.
    let (punt_tx, punt_rx) = mpsc::sync_channel(1024);
    let (handshake_tx, handshake_rx) = mpsc::sync_channel(256);
    // Packets for the worker that owns their session, and a wake-up for
    // each worker sleeping in poll().
    let (handoff_txs, handoff_rxs): (Vec<_>, Vec<_>) =
        (0..workers).map(|_| mpsc::sync_channel(4096)).unzip();
    let mut handoff_rxs = handoff_rxs.into_iter();
    let wakes: Arc<[Wake]> = (0..workers)
        .map(|_| Wake::new())
        .collect::<std::io::Result<Vec<_>>>()
        .context("creating the workers' wake-ups")?
        .into();
    let detail: crate::report::DetailWanted = Default::default();
    // The host path: SSH and the portal on inside interfaces that offer
    // them. Replies go to worker 0, which sends them like its own packets.
    let (host_tx, host_threads) = match crate::host::start(txs[0].clone(), &STOP) {
        Ok((tx, threads)) => (Some(tx), threads),
        Err(e) => {
            if cfg.interfaces.iter().any(|i| !i.management.is_empty()) {
                warn!(target: crate::logging::cat::MGMT,
                    "SSH and the portal can't be reached on data-plane interfaces: {e}");
            }
            (None, vec![])
        }
    };
    let mut zero_copy = vec![false; cards.len()];
    let reports: Vec<Arc<Mutex<Report>>> = (0..workers).map(|_| Default::default()).collect();
    let mut pool = Vec::new();

    for (w, control) in rxs.into_iter().enumerate() {
        let umem = Umem::new(frames, FRAME_SIZE).context("allocating UMEM")?;
        let first = Xsk::new(&umem, ifindexes[0], w as u32, &xcfg, None)
            .with_context(|| format!("AF_XDP socket on {} queue {w}", cards[0]))?;
        let mut socks = Vec::new();
        for (c, &idx) in ifindexes.iter().enumerate().skip(1) {
            socks.push(
                Xsk::new(&umem, idx, w as u32, &xcfg, Some(&first))
                    .with_context(|| format!("AF_XDP socket on {} queue {w}", cards[c]))?,
            );
        }
        socks.insert(0, first);
        for (c, s) in socks.iter().enumerate() {
            maps[c].insert(w as u32, s.fd())?;
            zero_copy[c] |= s.zero_copy;
        }
        info!(target: crate::logging::cat::DATAPLANE,
            "worker {w}: {frames} frames ({} MiB, huge pages: {}), zero-copy: {}",
            (frames as usize * FRAME_SIZE as usize) >> 20,
            umem.huge_pages,
            socks
                .iter()
                .map(|s| s.zero_copy.to_string())
                .collect::<Vec<_>>()
                .join("/")
        );
        let siblings = txs
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != w)
            .map(|(_, t)| t.clone())
            .collect();
        let mut pipeline = Pipeline::new(
            ports.clone(),
            fib.clone(),
            cfg.sessions
                .to_config(plan.sessions_per_worker, plan.workers),
            overlay.clone(),
        );
        // One worker sends the SD-WAN probes; replies may land on any worker.
        pipeline.set_prober(w == 0);
        pipeline.set_worker(w as u16, workers as u16);
        pipeline.set_nat(nat.clone());
        pipeline.set_overlay_run(run, replay.clone());
        pipeline.set_endpoints(endpoints.clone());
        pipeline.set_steering(steering.clone());
        pipeline.set_trace(crate::logging::control().trace_config());
        pool.push(Worker {
            id: w,
            socks,
            umem,
            pipeline,
            control,
            siblings,
            report: reports[w].clone(),
            punt: punt_tx.clone(),
            handshake: handshake_tx.clone(),
            handoff_to: handoff_txs.clone(),
            handoff_in: handoff_rxs.next().expect("one per worker"),
            wakes: wakes.clone(),
            detail: detail.clone(),
            host: host_tx.clone(),
            busy_poll: d.busy_poll,
            cpu: d.cpus.get(w).copied(),
        });
    }

    // ---- attach XDP last, once every queue has a socket to redirect to.
    let mut links = Vec::new();
    for (c, &idx) in ifindexes.iter().enumerate() {
        let link = XdpRedirect::attach(idx, &maps[c], xdp_mode)
            .with_context(|| format!("attaching XDP to {}", cards[c]))?;
        info!(target: crate::logging::cat::DATAPLANE, "XDP attached to {} in {:?} mode", cards[c], link.mode);
        links.push(link);
    }
    // What each interface ended up with is its card's.
    let runtime = ports
        .iter()
        .map(|p| PortRuntime {
            device: cards[p.card as usize].to_string(),
            xdp_mode: format!("{:?}", links[p.card as usize].mode),
            zero_copy: zero_copy[p.card as usize],
        })
        .collect();

    // ---- run
    let epoch = Instant::now();
    let mut handles: Vec<_> = pool
        .into_iter()
        .map(|w| {
            std::thread::Builder::new()
                .name(format!("eph-worker-{}", w.id))
                .spawn(move || w.run(&STOP, epoch))
                .expect("spawning worker")
        })
        .collect();
    handles.extend(host_threads);
    info!(target: crate::logging::cat::SYSTEM, "ephemerisd running with {workers} worker(s); Ctrl-C to stop");
    Ok(Dataplane {
        workers,
        ports,
        fib,
        overlay,
        reports,
        txs,
        runtime,
        handles,
        links,
        promisc,
        epoch,
        replay,
        punts: Some(punt_rx),
        handshakes: Some(handshake_rx),
        endpoints,
        umem_bytes: frames as u64 * FRAME_SIZE as u64 * workers as u64,
        detail,
    })
}

/// How long an outside address change keeps being announced.
const ANNOUNCE_FOR: Duration = Duration::from_secs(3600);

/// Our outside addresses, to notice when one changes (a PPPoE redial, a new
/// DHCP lease) and announce it to the other sites: (old, new, when).
struct AddressWatch {
    last: Vec<Option<std::net::Ipv4Addr>>,
    changes: Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr, Instant)>,
}

impl AddressWatch {
    /// Whether the list to announce changed.
    fn check(&mut self, ports: &[eph_dataplane::Port]) -> bool {
        let mut changed = false;
        self.last.resize(ports.len(), None);
        for (p, last) in ports.iter().zip(self.last.iter_mut()) {
            if p.role != eph_dataplane::Role::Outside || p.addr.is_unspecified() {
                continue; // a PPPoE link that's down: wait for its new address
            }
            match *last {
                Some(old) if old != p.addr => {
                    info!(target: crate::logging::cat::SDWAN,
                        "{}: address changed from {old} to {}: telling the other sites", p.name, p.addr);
                    self.changes.push((old, p.addr, Instant::now()));
                    changed = true;
                }
                _ => {}
            }
            *last = Some(p.addr);
        }
        let before = self.changes.len();
        self.changes.retain(|c| c.2.elapsed() < ANNOUNCE_FOR);
        let keep = eph_dataplane::overlay::ANNOUNCE_MAX;
        if self.changes.len() > keep {
            self.changes.drain(..self.changes.len() - keep);
        }
        changed || self.changes.len() != before
    }

    fn list(&self) -> Arc<[(std::net::Ipv4Addr, std::net::Ipv4Addr)]> {
        self.changes.iter().map(|&(a, b, _)| (a, b)).collect()
    }
}

/// Twice a second: tether health from probe results, then path decisions.
/// Every few seconds, also the peers' newest runs, peers that moved (see
/// `overlay_state`), and changes of our own outside addresses.
fn path_loop(shared: &Shared, epoch: Instant, replay: &ReplayGuard, state_dir: &Path) {
    let mut sel = PathSelector::new(shared.overlay.clone());
    let mut saved = overlay_state::load_peers(state_dir);
    let mut moved_saved = overlay_state::load_moved(state_dir);
    let mut watch = AddressWatch {
        last: vec![],
        changes: vec![],
    };
    let mut tick = 0u32;
    while !STOP.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(TICK_MS));
        tick = tick.wrapping_add(1);
        if tick.is_multiple_of(4) {
            let ports = shared.ports.read().unwrap().clone();
            if watch.check(&ports) {
                let list = watch.list();
                for tx in shared.control.lock().unwrap().iter() {
                    let _ = tx.send(Control::SetAnnounce(list.clone()));
                }
            }
        }
        if tick.is_multiple_of(10) {
            let moved: Vec<overlay_state::Moved> = shared
                .overlay
                .tethers
                .iter()
                .filter(|t| !t.remote.is_unspecified())
                .filter_map(|t| {
                    let (ip, port) = shared.endpoints.get(t.id)?;
                    (ip != t.remote).then(|| (t.name.clone(), t.remote, ip, port))
                })
                .collect();
            if moved != moved_saved {
                for m in moved.iter().filter(|m| !moved_saved.contains(m)) {
                    info!(target: crate::logging::cat::SDWAN,
                        "tether {}: its peer is now at {} (configured: {})", m.0, m.2, m.1);
                }
                match overlay_state::save_moved(state_dir, &moved) {
                    Ok(()) => moved_saved = moved,
                    Err(e) => {
                        warn!(target: crate::logging::cat::SDWAN, "saving where SD-WAN peers moved: {e:#}")
                    }
                }
            }
            let sites = &shared.overlay.sites;
            let mut peers: Vec<(u16, u8, u16)> = replay
                .runs()
                .into_iter()
                .map(|(idx, worker, run)| (sites[idx], worker, run))
                .collect();
            // Keep what was saved for senders not heard from since.
            for &(s, w, r) in &saved {
                if !peers.iter().any(|&(s2, w2, _)| (s2, w2) == (s, w)) {
                    peers.push((s, w, r));
                }
            }
            peers.sort_unstable();
            if peers != saved {
                match overlay_state::save_peers(state_dir, &peers) {
                    Ok(()) => saved = peers,
                    Err(e) => {
                        warn!(target: crate::logging::cat::SDWAN, "saving overlay peer state: {e:#}")
                    }
                }
            }
        }
        let merged = Summary::collect(&shared.reports).tethers;
        let health = sel.health(&merged, epoch.elapsed().as_nanos() as u64);
        *shared.health.write().unwrap() = health.clone();
        if let Some((table, changes)) = sel.decide(&health) {
            for c in changes {
                info!(target: crate::logging::cat::SDWAN, "SD-WAN path change: {c}");
            }
            let table = Arc::new(table);
            for tx in shared.control.lock().unwrap().iter() {
                let _ = tx.send(Control::SetPaths(table.clone()));
            }
            *shared.paths.write().unwrap() = table;
        }
    }
}

/// SD-WAN handshakes: answer the ones the workers hand over, and every
/// 100 ms start the ones that are due. New keys go to every worker; the
/// messages to send go to worker 0, which sends them like its probes.
fn handshake_loop(
    shared: &Shared,
    epoch: Instant,
    mut hs: Handshakes,
    rx: mpsc::Receiver<eph_dataplane::HandshakeIn>,
) {
    const TICK: Duration = Duration::from_millis(100);
    let overlay = shared.overlay.clone();
    // An initiation can go on a tether whose peer we know where to find,
    // working ones first, fastest first.
    let candidates = |idx: usize| {
        let health = shared.health.read().unwrap();
        let mut c: Vec<_> = overlay
            .tethers
            .iter()
            .filter(|t| {
                t.site_idx == idx
                    && (!t.remote.is_unspecified() || shared.endpoints.get(t.id).is_some())
            })
            .map(|t| {
                let h = health.get(t.id as usize).copied().unwrap_or_default();
                (!h.up, h.rtt_ns, t.id)
            })
            .collect();
        c.sort_unstable();
        c.into_iter().map(|(_, _, id)| id).collect()
    };
    let mut next_tick = Instant::now();
    while !STOP.load(Ordering::Relaxed) {
        let out = match rx.recv_timeout(next_tick.saturating_duration_since(Instant::now())) {
            Ok(m) => hs.receive(&m, epoch.elapsed().as_nanos() as u64),
            Err(mpsc::RecvTimeoutError::Timeout) => Default::default(),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        apply_handshakes(shared, out);
        if Instant::now() >= next_tick {
            next_tick += TICK;
            let now = epoch.elapsed().as_nanos() as u64;
            apply_handshakes(shared, hs.tick(now, &candidates));
            *shared.sdwan.peers.lock().unwrap() = hs.status(now);
        }
    }
}

fn apply_handshakes(shared: &Shared, out: crate::sdwan::Output) {
    for (routine, e) in out.events {
        if routine {
            debug!(target: crate::logging::cat::SDWAN, "{e}");
        } else {
            info!(target: crate::logging::cat::SDWAN, "{e}");
        }
    }
    let control = shared.control.lock().unwrap();
    for a in out.actions {
        let Action::Send {
            tether,
            to,
            payload,
        } = a;
        if let Some(tx) = control.first() {
            let _ = tx.send(Control::Handshake {
                tether,
                to,
                payload,
            });
        }
    }
    if let Some(keys) = out.keys {
        for tx in control.iter() {
            let _ = tx.send(Control::SetKeys(keys.clone()));
        }
    }
}

/// Each card's spreading (see `eph_dataplane::steer`). Outside cards are
/// first told to hash TCP and UDP on ports too, so a NAT port decides where
/// replies land. A card that can't say is left to hand-offs.
fn read_steering(cfg: &Config, cards: &[&str]) -> eph_dataplane::steer::Steering {
    let card_rss: Vec<_> = cards
        .iter()
        .map(|&dev| {
            let outside = cfg
                .interfaces
                .iter()
                .any(|i| i.device == dev && i.role == crate::config::RoleCfg::Outside);
            if outside {
                let (tcp, udp) = iface::hash_ports(dev);
                if !(tcp && udp) {
                    info!(target: crate::logging::cat::DATAPLANE,
                        "{dev}: can't hash {} on ports: NAT replies handed between workers as needed",
                        if tcp { "UDP" } else if udp { "TCP" } else { "TCP or UDP" });
                }
            }
            match iface::rss(dev) {
                Ok(r) => {
                    let workers = cfg.dataplane.workers;
                    let idle: Vec<u32> = (0..workers).filter(|q| !r.indir.contains(q)).collect();
                    if !idle.is_empty() {
                        warn!(target: crate::logging::cat::DATAPLANE,
                            "{dev}: the card's RSS table sends nothing to queue(s) {idle:?}, so \
                             those workers get no traffic from it. Fix: ethtool -X {dev} equal {workers}");
                    }
                    info!(target: crate::logging::cat::DATAPLANE,
                        "{dev}: Toeplitz RSS over {} entries{}; ports hashed: TCP {}, UDP {}",
                        r.indir.len(),
                        if r.symmetric { " (symmetric)" } else { "" },
                        if r.tcp_ports { "yes" } else { "no" },
                        if r.udp_ports { "yes" } else { "no" });
                    Some(eph_dataplane::steer::CardRss {
                        key: r.key,
                        indir: r.indir.iter().map(|&q| q.min(u16::MAX as u32) as u16).collect(),
                        symmetric: r.symmetric,
                        tcp_ports: r.tcp_ports,
                        udp_ports: r.udp_ports,
                    })
                }
                Err(e) => {
                    info!(target: crate::logging::cat::DATAPLANE,
                        "{dev}: queue spreading unknown ({e}): replies handed between workers as needed");
                    None
                }
            }
        })
        .collect();
    eph_dataplane::steer::Steering::new(&card_rss)
}

/// Make the calling thread nicer (0 = normal, 19 = lowest), so that on a
/// busy router the workers get the CPU first. Linux sets this per thread.
fn lower_priority(nice: i32) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: plain syscalls on this thread, no pointers.
        let r =
            unsafe { libc::setpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t, nice) };
        if r != 0 {
            warn!(target: crate::logging::cat::SYSTEM,
                "could not lower thread priority: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = nice;
}

fn print_stats(shared: &Shared, show_sessions: usize) {
    let s = Summary::collect(&shared.reports);
    let drops: Vec<String> = s.drops.iter().map(|(k, v)| format!("{k}={v}")).collect();
    info!(target: crate::logging::cat::DATAPLANE,
        "rx={} forwarded={} originated={} kernel-drops={} fill-empty={} sessions={} (created {}, expired {}) neighbors={} drops[{}]",
        s.rx,
        s.forwarded,
        s.originated,
        s.kernel_drops,
        s.fill_empty,
        s.sessions_active,
        s.sessions_created,
        s.sessions_expired,
        s.neighbor_count,
        drops.join(" ")
    );
    let health = shared.health.read().unwrap().clone();
    for (t, (st, h)) in shared
        .overlay
        .tethers
        .iter()
        .zip(s.tethers.iter().zip(&health))
    {
        info!(target: crate::logging::cat::DATAPLANE,
            "  tether {:<10} {:<4} rtt {:>6.1} ms  jitter {:>5.1} ms  loss {:>5.1}%  tx {} rx {}",
            t.name,
            if h.up { "up" } else { "DOWN" },
            h.rtt_ns as f64 / 1e6,
            h.jitter_ns as f64 / 1e6,
            h.loss_pct,
            st.tx_packets,
            st.rx_packets
        );
    }
    let mut newest: Vec<_> = s.sessions.iter().collect();
    newest.sort_by_key(|v| std::cmp::Reverse(v.session.created_ns));
    for v in newest.into_iter().take(show_sessions) {
        info!(target: crate::logging::cat::DATAPLANE, "  {v}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wan(addr: &str) -> eph_dataplane::Port {
        let addr = addr.parse().unwrap();
        eph_dataplane::Port {
            id: 0,
            name: "wan".into(),
            mac: [2, 0, 0, 0, 0, 1],
            addr,
            subnet: eph_fib::Prefix::new(addr, 32).unwrap(),
            allow_new_sessions: false,
            role: eph_dataplane::Role::Outside,
            mss_adjust: None,
            dhcp: eph_dataplane::Dhcp::Off,
            gateway: None,
            pppoe: eph_dataplane::Pppoe::Off,
            onlink: vec![],
            mtu: 1492,
            card: 0,
            vlan: None,
            host: Default::default(),
        }
    }

    #[test]
    fn outside_address_changes_are_announced_for_a_while() {
        let mut w = AddressWatch {
            last: vec![],
            changes: vec![],
        };
        assert!(
            !w.check(&[wan("192.0.2.1")]),
            "the first one isn't a change"
        );
        assert!(!w.check(&[wan("0.0.0.0")]), "PPPoE down: wait");
        assert!(w.check(&[wan("203.0.113.9")]));
        assert_eq!(
            &w.list()[..],
            [("192.0.2.1".parse().unwrap(), "203.0.113.9".parse().unwrap())]
        );
        assert!(!w.check(&[wan("203.0.113.9")]));
        w.changes[0].2 -= ANNOUNCE_FOR;
        assert!(w.check(&[wan("203.0.113.9")]), "expired: dropped");
        assert!(w.list().is_empty());
    }
}
