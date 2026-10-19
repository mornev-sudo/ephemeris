//! Bring-up: resolve interfaces, build per-worker UMEMs and sockets, attach
//! the XDP programs, start the workers, and print stats until told to stop.

use crate::config::Config;
use crate::mgmt::configmgr::ConfigManager;
use crate::mgmt::paths::{PathSelector, TICK_MS};
use crate::mgmt::{api, load_or_create_token, PortRuntime, Shared, Summary};
use crate::overlay_state;
use crate::report::{Control, Report};
use crate::startup::{self, StartupState};
use crate::worker::Worker;
use anyhow::{bail, Context, Result};
use eph_dataplane::overlay::{ReplayGuard, DEFAULT_MTU};
use eph_dataplane::{Pipeline, Port};
use eph_packet::eth;
use eph_xdp::{iface, BindMode, Umem, XdpMode, XdpRedirect, Xsk, XskConfig, XskMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

const FRAME_SIZE: u32 = 4096;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

pub fn run(config_path: &Path) -> Result<()> {
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        // Older kernels charge UMEM and BPF maps against RLIMIT_MEMLOCK.
        let unlimited = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &unlimited);
    }
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let mut startup = StartupState {
        fallback: startup::take_note(config_path),
        ..Default::default()
    };
    if let Some(f) = &startup.fallback {
        warn!(
            "started with the last configuration that worked: the newer one failed ({}); it was kept as {}",
            f.error, f.failed_file
        );
    }
    // Anything that stops the data plane from starting: go back to the last
    // config that worked (and restart with it), or run management only.
    let manager = match ConfigManager::open(config_path) {
        Ok(m) => m.check_nics(crate::mgmt::nics::list),
        Err(e) => return Err(fall_back(config_path, &text, e)),
    };
    let cfg = manager.running().clone();
    let state_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let dp = match start_dataplane(&cfg, &state_dir) {
        Ok(dp) => {
            if let Err(e) = startup::mark_good(config_path, &text) {
                warn!("could not save this config as the last good one: {e:#}");
            }
            dp
        }
        Err(e) => {
            let e = fall_back(config_path, &text, e);
            if e.to_string().starts_with(RESTARTING) {
                return Err(e);
            }
            error!("data plane not started: {e:#}. Running the management plane only: fix the configuration, then restart.");
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
        epoch,
        replay,
        punts,
        endpoints,
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
                error!("API token unavailable ({e:#}); token authentication disabled");
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
        dhcp: Default::default(),
        endpoints,
        stop: &STOP,
    });
    let mgmt = m.enabled.then(|| {
        let shared = shared.clone();
        let (listen, moved) = m.bind_addr();
        if moved {
            warn!(
                "management.listen {} is not a loopback address: plain HTTP stays on {listen}, \
                 and the portal is served over HTTPS by nginx (https://<router>:8443/). \
                 Set management.insecure_remote_http = true to serve plain HTTP on the network.",
                m.listen
            );
        } else if !listen.ip().is_loopback() {
            warn!("management API on {listen} over plain HTTP: passwords cross the network unencrypted");
        }
        std::thread::Builder::new()
            .name("eph-mgmt".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                // A broken management plane must never take the data plane down.
                if let Err(e) = rt.block_on(api::serve(shared, listen)) {
                    error!("management API stopped: {e:#}");
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
            .spawn(move || crate::dhcp::service::run(&shared, rx, &STOP, &dir))
            .expect("spawning DHCP service")
    });

    // ---- SD-WAN control loop
    let selector = (overlay.enabled() && workers > 0).then(|| {
        let shared = shared.clone();
        info!(
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

    let interval = Duration::from_secs(d.stats_interval_secs.max(1));
    let mut next = Instant::now() + interval;
    while !STOP.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        if Instant::now() >= next && workers > 0 {
            next += interval;
            print_stats(&shared, d.show_sessions);
        }
    }
    info!("stopping");
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
    print_stats(&shared, d.show_sessions);
    drop(links); // detaches XDP; the kernel would also do this when we exit
    Ok(())
}

/// The image build this is, e.g. "0.5.0.123 (commit dca7076)": the
/// release, the CI build number, and the exact source it was built from.
fn build_string() -> String {
    let read = |f: &str| {
        std::fs::read_to_string(format!("/usr/lib/ephemeris/{f}"))
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
    };
    match (read("version"), read("commit")) {
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
            error!("configuration failed: {e:#}");
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
    epoch: Instant,
    /// Received overlay counters, shared by the workers (persisted by the
    /// path loop).
    replay: Arc<ReplayGuard>,
    /// DHCP packets the workers hand to the control plane.
    punts: Option<mpsc::Receiver<eph_dataplane::Punt>>,
    /// Learned addresses of SD-WAN peers without a fixed one.
    endpoints: Arc<eph_dataplane::overlay::Endpoints>,
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
            links: vec![],
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

    // ---- interfaces
    let mut ifindexes = Vec::new();
    for i in &cfg.interfaces {
        let idx = iface::ifindex(&i.device).with_context(|| format!("interface {}", i.name))?;
        if !iface::is_up(&i.device) {
            bail!(
                "device {} is down; run: ip link set dev {} up",
                i.device,
                i.device
            );
        }
        let queues = iface::rx_queues(&i.device)?;
        if queues < workers {
            bail!(
                "device {} has {queues} RX queue(s) but {workers} workers are configured \
                 (try: ethtool -L {} combined {workers})",
                i.device,
                i.device
            );
        }
        if queues > workers {
            warn!(
                "device {} has {queues} RX queues but only {workers} worker(s): traffic hashed to \
                 queues {workers}..{} will be dropped. Fix: ethtool -L {} combined {workers}",
                i.device,
                queues - 1,
                i.device
            );
        }
        ifindexes.push(idx);
    }
    let ports: Arc<[Port]> = cfg
        .ports(|i| {
            let s = iface::mac(&i.device)?;
            eth::parse_mac(&s).with_context(|| format!("device {}: bad MAC {s:?}", i.device))
        })?
        .into();
    let fib = Arc::new(cfg.fib(&ports)?);
    let mut overlay = cfg.overlay()?;
    // Overlay crypto: claim this start's run number before anything is
    // sealed. Without one the tethers stay down rather than risk reusing a
    // nonce; the rest of the router runs normally.
    let run = if overlay.enabled() {
        match overlay_state::claim_run(state_dir) {
            Ok(run) => run,
            Err(e) => {
                error!("SD-WAN tethers disabled: {e:#}");
                for t in &mut overlay.tethers {
                    t.key = None;
                }
                0
            }
        }
    } else {
        0
    };
    for t in overlay.tethers.iter().filter(|t| t.key.is_none()) {
        warn!("tether {} has no key: it stays down", t.name);
    }
    if overlay.enabled() && overlay.mtu > DEFAULT_MTU {
        warn!(
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
    let overlay = Arc::new(overlay);
    let nat = Arc::new(cfg.nat()?);
    for p in ports.iter() {
        info!(
            "port {} {} dev {} mac {} addr {}/{}",
            p.id,
            p.name,
            cfg.interfaces[p.id as usize].device,
            eth::fmt_mac(&p.mac),
            p.addr,
            p.subnet.len()
        );
    }
    info!("forwarding table: {} route(s)", fib.routes().len());

    // ---- per-worker UMEM + one socket per interface on queue `w`
    let ring = d.ring_size;
    let xcfg = XskConfig {
        rx_size: ring,
        tx_size: ring,
        fill_size: ring,
        comp_size: ring,
        bind_mode,
    };
    // Enough frames to fill every fill ring and every TX ring, rounded to a
    // whole number of 2 MiB huge pages (512 frames).
    let frames = (ports.len() as u32 * ring * 2).div_ceil(512) * 512;

    let maps: Vec<XskMap> = ports
        .iter()
        .map(|_| XskMap::new(workers))
        .collect::<Result<_, _>>()?;
    // One control channel per worker: neighbour updates from siblings, and
    // FIB/port changes from the management plane.
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..workers).map(|_| mpsc::channel()).unzip();
    let (punt_tx, punt_rx) = mpsc::channel();
    let mut zero_copy = vec![false; ports.len()];
    let reports: Vec<Arc<Mutex<Report>>> = (0..workers).map(|_| Default::default()).collect();
    let mut pool = Vec::new();

    for (w, control) in rxs.into_iter().enumerate() {
        let umem = Umem::new(frames, FRAME_SIZE).context("allocating UMEM")?;
        let first = Xsk::new(&umem, ifindexes[0], w as u32, &xcfg, None)
            .with_context(|| format!("AF_XDP socket on {} queue {w}", cfg.interfaces[0].device))?;
        let mut socks = Vec::new();
        for (p, &idx) in ifindexes.iter().enumerate().skip(1) {
            socks.push(
                Xsk::new(&umem, idx, w as u32, &xcfg, Some(&first)).with_context(|| {
                    format!("AF_XDP socket on {} queue {w}", cfg.interfaces[p].device)
                })?,
            );
        }
        socks.insert(0, first);
        for (p, s) in socks.iter().enumerate() {
            maps[p].insert(w as u32, s.fd())?;
            zero_copy[p] |= s.zero_copy;
        }
        info!(
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
            cfg.sessions.to_config(),
            overlay.clone(),
        );
        // One worker sends the SD-WAN probes; replies may land on any worker.
        pipeline.set_prober(w == 0);
        pipeline.set_worker(w as u16, workers as u16);
        pipeline.set_nat(nat.clone());
        pipeline.set_overlay_run(run, replay.clone());
        pipeline.set_endpoints(endpoints.clone());
        pool.push(Worker {
            id: w,
            socks,
            umem,
            pipeline,
            control,
            siblings,
            report: reports[w].clone(),
            punt: punt_tx.clone(),
            busy_poll: d.busy_poll,
            cpu: d.cpus.get(w).copied(),
        });
    }

    // ---- attach XDP last, once every queue has a socket to redirect to.
    let mut links = Vec::new();
    let mut runtime = Vec::new();
    for (p, &idx) in ifindexes.iter().enumerate() {
        let link = XdpRedirect::attach(idx, &maps[p], xdp_mode)
            .with_context(|| format!("attaching XDP to {}", cfg.interfaces[p].device))?;
        info!(
            "XDP attached to {} in {:?} mode",
            cfg.interfaces[p].device, link.mode
        );
        runtime.push(PortRuntime {
            device: cfg.interfaces[p].device.clone(),
            xdp_mode: format!("{:?}", link.mode),
            zero_copy: zero_copy[p],
        });
        links.push(link);
    }

    // ---- run
    let epoch = Instant::now();
    let handles: Vec<_> = pool
        .into_iter()
        .map(|w| {
            std::thread::Builder::new()
                .name(format!("eph-worker-{}", w.id))
                .spawn(move || w.run(&STOP, epoch))
                .expect("spawning worker")
        })
        .collect();
    info!("ephemerisd running with {workers} worker(s); Ctrl-C to stop");
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
        epoch,
        replay,
        punts: Some(punt_rx),
        endpoints,
    })
}

/// Twice a second: tether health from probe results, then path decisions.
/// Every few seconds, also the peers' newest runs (see `overlay_state`).
fn path_loop(shared: &Shared, epoch: Instant, replay: &ReplayGuard, state_dir: &Path) {
    let mut sel = PathSelector::new(shared.overlay.clone());
    let mut saved = overlay_state::load_peers(state_dir);
    let mut tick = 0u32;
    while !STOP.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(TICK_MS));
        tick = tick.wrapping_add(1);
        if tick.is_multiple_of(10) {
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
                    Err(e) => warn!("saving overlay peer state: {e:#}"),
                }
            }
        }
        let merged = Summary::collect(&shared.reports).tethers;
        let health = sel.health(&merged, epoch.elapsed().as_nanos() as u64);
        *shared.health.write().unwrap() = health.clone();
        if let Some((table, changes)) = sel.decide(&health) {
            for c in changes {
                info!("SD-WAN path change: {c}");
            }
            let table = Arc::new(table);
            for tx in shared.control.lock().unwrap().iter() {
                let _ = tx.send(Control::SetPaths(table.clone()));
            }
            *shared.paths.write().unwrap() = table;
        }
    }
}

fn print_stats(shared: &Shared, show_sessions: usize) {
    let s = Summary::collect(&shared.reports);
    let ports = shared.ports.read().unwrap().clone();
    let drops: Vec<String> = s.drops.iter().map(|(k, v)| format!("{k}={v}")).collect();
    info!(
        "rx={} forwarded={} originated={} kernel-drops={} fill-empty={} drops[{}]",
        s.rx,
        s.forwarded,
        s.originated,
        s.kernel_drops,
        s.fill_empty,
        drops.join(" ")
    );
    info!(
        "sessions: active={} created={} expired={}",
        s.sessions_active, s.sessions_created, s.sessions_expired
    );
    let health = shared.health.read().unwrap().clone();
    for (t, (st, h)) in shared
        .overlay
        .tethers
        .iter()
        .zip(s.tethers.iter().zip(&health))
    {
        info!(
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
    for v in s.sessions.iter().take(show_sessions) {
        info!("  {v}");
    }
    for n in &s.neighbors {
        info!(
            "  neighbor {:<15} {} on {}",
            n.ip,
            eth::fmt_mac(&n.mac),
            ports[n.port as usize].name
        );
    }
}
