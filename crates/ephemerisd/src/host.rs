//! The host path's two threads: packets for the router's own SSH and portal
//! go from the workers into the `eph-host` tun device, and the kernel's
//! replies come back to a worker to be sent (see `eph_dataplane::host`).

use crate::logging::cat;
use crate::report::Control;
use eph_xdp::tun::Tun;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::{info, warn};

/// The tun device nic-setup creates, with its address range and route.
pub const DEVICE: &str = "eph-host";
/// Packets waiting for the kernel, at most (beyond: dropped and counted).
const QUEUE: usize = 1024;
/// How often the threads look at the stop flag.
const TICK_MS: i32 = 200;

/// A running host path: where workers put packets for the host, and its
/// threads (they end when the stop flag is set).
pub type Running = (SyncSender<Vec<u8>>, Vec<JoinHandle<()>>);

/// Start the host path; replies from the host go to `inject`.
pub fn start(inject: Sender<Control>, stop: &'static AtomicBool) -> std::io::Result<Running> {
    let tun = Arc::new(Tun::attach(DEVICE)?);
    let (to_host, from_workers) = sync_channel::<Vec<u8>>(QUEUE);
    let t = tun.clone();
    let writer = std::thread::Builder::new()
        .name("eph-host-tx".into())
        .spawn(move || write_loop(&t, from_workers, stop))?;
    let reader = std::thread::Builder::new()
        .name("eph-host-rx".into())
        .spawn(move || read_loop(&tun, &inject, stop))?;
    info!(target: cat::MGMT, "host path ready ({DEVICE}): SSH and the portal on the inside interfaces that offer them");
    Ok((to_host, vec![writer, reader]))
}

fn write_loop(tun: &Tun, rx: Receiver<Vec<u8>>, stop: &AtomicBool) {
    let mut failing = false;
    while !stop.load(Ordering::Relaxed) {
        let p = match rx.recv_timeout(Duration::from_millis(TICK_MS as u64)) {
            Ok(p) => p,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        match tun.send(&p) {
            Ok(()) => failing = false,
            // Said once per run of failures, not per packet.
            Err(e) if !failing => {
                failing = true;
                warn!(target: cat::MGMT, "host path: can't hand packets to {DEVICE}: {e}");
            }
            Err(_) => {}
        }
    }
}

fn read_loop(tun: &Tun, inject: &Sender<Control>, stop: &AtomicBool) {
    let mut buf = vec![0u8; 65536];
    while !stop.load(Ordering::Relaxed) {
        match tun.recv(&mut buf, TICK_MS) {
            Ok(0) => {}
            Ok(n) => {
                if inject.send(Control::InjectHost(buf[..n].to_vec())).is_err() {
                    break; // the worker is gone: shutting down
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                warn!(target: cat::MGMT, "host path: reading {DEVICE}: {e}");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}
