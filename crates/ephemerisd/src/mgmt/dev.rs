//! Development portal for non-Linux machines: the real API and web UI
//! against a config file, with an empty data plane. Lets the UI be worked on
//! and tried in a browser on a laptop. Not compiled into Linux builds.

use super::configmgr::ConfigManager;
use super::{api, PortRuntime, Shared};
use crate::report::Report;
use eph_dataplane::overlay::PathTable;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};

static STOP: AtomicBool = AtomicBool::new(false);

pub fn serve(config: &Path) -> anyhow::Result<()> {
    let mgr = ConfigManager::open(config)?.check_nics(super::nics::list);
    let cfg = mgr.running().clone();
    crate::logging::control().apply_config(&cfg.logging);
    let ports: Arc<[_]> = cfg.ports(|_| Ok([2, 0, 0, 0, 0, 1]))?.into();
    let fib = Arc::new(cfg.fib(&ports)?);
    let overlay = Arc::new(cfg.overlay()?);
    let mut auth = super::auth::Auth::new(std::env::temp_dir());
    auth.dev_password = Some("dev".into());
    let shared = Arc::new(Shared {
        build: "dev".into(),
        started: std::time::Instant::now(),
        runtime: cfg
            .interfaces
            .iter()
            .map(|i| PortRuntime {
                device: i.device.clone(),
                xdp_mode: "Native".into(),
                zero_copy: false,
            })
            .collect(),
        workers: 1,
        ports: RwLock::new(ports),
        fib: RwLock::new(fib),
        paths: RwLock::new(Arc::new(PathTable::empty(&overlay))),
        health: RwLock::new(vec![Default::default(); overlay.tethers.len()]),
        overlay,
        reports: vec![Arc::new(Mutex::new(Report::default()))],
        control: Mutex::new(vec![]),
        config: Mutex::new(mgr),
        token: "dev".into(),
        auth,
        startup: Default::default(),
        dhcp: Default::default(),
        endpoints: Arc::new(eph_dataplane::overlay::Endpoints::new(0)),
        sdwan: crate::sdwan::SdwanState {
            public_key: crate::sdwan::Identity::generate().ok().map(|i| i.public),
            ..Default::default()
        },
        controller_key: crate::controller::Identity::generate()
            .ok()
            .map(|i| i.public()),
        history: Default::default(),
        update: Default::default(),
        system: Default::default(),
        umem_bytes: 0,
        detail: Default::default(),
        stop: &STOP,
    });
    // Made-up traffic every 5 s, so the Reporting graphs have something to
    // draw while working on them.
    {
        let shared = shared.clone();
        std::thread::spawn(move || {
            let t0 = std::time::Instant::now();
            let mut sampler = super::sysinfo::Sampler::default();
            let mut sum = super::Summary {
                ports: vec![Default::default(); shared.ports.read().unwrap().len()],
                ..Default::default()
            };
            loop {
                let t = t0.elapsed().as_secs_f64();
                let wave = 1.0 + (t / 60.0).sin();
                for (i, p) in sum.ports.iter_mut().enumerate() {
                    let pk = (4000.0 * wave / (i + 1) as f64) as u64 * 5;
                    p.rx_packets += pk;
                    p.rx_bytes += pk * 900;
                    p.tx_packets += pk / 2;
                    p.tx_bytes += pk / 2 * 400;
                }
                sum.sessions_active = (200.0 * wave) as u64 + 20;
                *sum.drops.entry("no-route").or_default() += (3.0 * wave) as u64;
                let unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let sys = sampler.sample(t, &["/"]);
                shared
                    .history
                    .lock()
                    .unwrap()
                    .record(t, unix, &sum, Some(&sys));
                *shared.system.lock().unwrap() = Some(sys);
                std::thread::sleep(std::time::Duration::from_secs(
                    super::history::INTERVAL_SECS,
                ));
            }
        });
    }
    println!("dev portal: http://127.0.0.1:8080/  (admin / dev)");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(api::serve(shared, "127.0.0.1:8080".parse()?))
}
