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
        stop: &STOP,
    });
    println!("dev portal: http://127.0.0.1:8080/  (admin / dev)");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(api::serve(shared, "127.0.0.1:8080".parse()?))
}
