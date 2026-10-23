//! A tun device: IP packets between this process and the kernel's own
//! network stack. The host path uses one, `eph-host`, to reach sshd and
//! nginx (see `eph_dataplane::host`).

use crate::sys::cvt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
/// No packet-information header: reads and writes are bare IP packets.
const IFF_NO_PI: libc::c_short = 0x1000;

pub struct Tun {
    file: File,
}

impl Tun {
    /// Attach to the tun device `name` (it's created by `ip tuntap add` with
    /// its addresses and routes; attaching to a name that doesn't exist
    /// would make a bare one, so check first).
    pub fn attach(name: &str) -> io::Result<Self> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.bytes().any(|b| b == 0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad tun name"));
        }
        if !std::path::Path::new(&format!("/sys/class/net/{name}/tun_flags")).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no tun device {name} (nic-setup creates it)"),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        // SAFETY: ifreq is plain C data; all zeros is a valid value.
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (d, s) in req.ifr_name.iter_mut().zip(name.bytes()) {
            *d = s as libc::c_char;
        }
        req.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
        // SAFETY: `req` is a live ifreq with a NUL-terminated name (checked
        // above: shorter than IFNAMSIZ, no NUL inside) and the flags set;
        // the kernel reads and updates it in place during the call.
        cvt(unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) })?;
        Ok(Tun { file })
    }

    /// Wait up to `timeout_ms` for a packet; `Ok(0)` if none came.
    pub fn recv(&self, buf: &mut [u8], timeout_ms: i32) -> io::Result<usize> {
        let mut p = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd, and the count passed is 1.
        if cvt(unsafe { libc::poll(&mut p, 1, timeout_ms) })? == 0 {
            return Ok(0);
        }
        (&self.file).read(buf)
    }

    /// Hand one IP packet to the kernel.
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        (&self.file).write(packet).map(drop)
    }
}
