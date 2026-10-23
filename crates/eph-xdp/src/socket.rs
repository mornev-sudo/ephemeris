use crate::ring::Ring;
use crate::sys::*;
use crate::umem::Umem;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMode {
    /// Let the kernel pick: zero-copy if the driver supports it, else copy.
    Auto,
    /// Kernel copies packets between its buffers and the UMEM.
    Copy,
    /// The NIC DMAs straight into/out of the UMEM. Fails if unsupported.
    ZeroCopy,
}

#[derive(Debug, Clone, Copy)]
pub struct XskConfig {
    pub rx_size: u32,
    pub tx_size: u32,
    pub fill_size: u32,
    pub comp_size: u32,
    pub bind_mode: BindMode,
}

impl Default for XskConfig {
    fn default() -> Self {
        XskConfig {
            rx_size: 2048,
            tx_size: 2048,
            fill_size: 2048,
            comp_size: 2048,
            bind_mode: BindMode::Auto,
        }
    }
}

pub type XskStats = XdpStatistics;

/// One AF_XDP socket, bound to one (interface, queue) pair.
pub struct Xsk {
    // Rings are declared before the fd so they're unmapped before it closes.
    pub rx: Ring<XdpDesc>,
    pub tx: Ring<XdpDesc>,
    pub fill: Ring<u64>,
    pub comp: Ring<u64>,
    fd: OwnedFd,
    pub ifindex: u32,
    pub queue: u32,
    pub zero_copy: bool,
}

impl Xsk {
    /// Create a socket on `ifindex`/`queue` using `umem`.
    ///
    /// The first socket of a UMEM registers it with the kernel
    /// (`shared_with = None`). Every further socket, on other interfaces,
    /// passes the first one and shares the same frames. That's what lets the
    /// router forward a packet from port A to port B without copying it: the
    /// frame address received on A's RX ring is put straight onto B's TX ring.
    pub fn new(
        umem: &Umem,
        ifindex: u32,
        queue: u32,
        cfg: &XskConfig,
        shared_with: Option<&Xsk>,
    ) -> io::Result<Self> {
        // SAFETY: plain syscall, no pointers; the result is checked.
        let fd = cvt(unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) })
            .map_err(|e| ctx(e, "socket(AF_XDP)"))?;
        // SAFETY: a new, valid descriptor nobody else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let raw = fd.as_raw_fd();

        if shared_with.is_none() {
            let (area, len) = umem.area();
            let reg = XdpUmemReg {
                addr: area as u64,
                len: len as u64,
                chunk_size: umem.frame_size(),
                ..Default::default()
            };
            setsockopt(raw, XDP_UMEM_REG, &reg).map_err(|e| ctx(e, "XDP_UMEM_REG"))?;
        }
        // Every socket on a *different* interface/queue gets its own fill and
        // completion ring, even when sharing the UMEM.
        setsockopt(raw, XDP_UMEM_FILL_RING, &cfg.fill_size)
            .map_err(|e| ctx(e, "XDP_UMEM_FILL_RING"))?;
        setsockopt(raw, XDP_UMEM_COMPLETION_RING, &cfg.comp_size)
            .map_err(|e| ctx(e, "XDP_UMEM_COMPLETION_RING"))?;
        setsockopt(raw, XDP_RX_RING, &cfg.rx_size).map_err(|e| ctx(e, "XDP_RX_RING"))?;
        setsockopt(raw, XDP_TX_RING, &cfg.tx_size).map_err(|e| ctx(e, "XDP_TX_RING"))?;

        let mut off = XdpMmapOffsets::default();
        let mut optlen = size_of::<XdpMmapOffsets>() as libc::socklen_t;
        // SAFETY: `off` and `optlen` are live locals and optlen is off's size,
        // so the kernel writes at most that much.
        cvt(unsafe {
            libc::getsockopt(
                raw,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                &mut off as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        })
        .map_err(|e| ctx(e, "XDP_MMAP_OFFSETS"))?;
        // Kernels before 5.4 answer with a shorter layout without the ring
        // flags; `flags` would stay 0 and the need-wakeup check would read
        // the producer counter instead. Refuse rather than misread.
        if optlen as usize != size_of::<XdpMmapOffsets>() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "XDP_MMAP_OFFSETS: this kernel's AF_XDP is too old (needs Linux 5.4 or newer)",
            ));
        }

        let rx = map_ring::<XdpDesc>(raw, &off.rx, cfg.rx_size, XDP_PGOFF_RX_RING)?;
        let tx = map_ring::<XdpDesc>(raw, &off.tx, cfg.tx_size, XDP_PGOFF_TX_RING)?;
        let fill = map_ring::<u64>(raw, &off.fr, cfg.fill_size, XDP_UMEM_PGOFF_FILL_RING)?;
        let comp = map_ring::<u64>(raw, &off.cr, cfg.comp_size, XDP_UMEM_PGOFF_COMPLETION_RING)?;

        let mut sa = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue,
            ..Default::default()
        };
        match shared_with {
            // Sharing sockets inherit copy/zero-copy and need-wakeup from the
            // first socket; the kernel rejects any other flag here.
            Some(first) => {
                sa.sxdp_flags = XDP_SHARED_UMEM;
                sa.sxdp_shared_umem_fd = first.fd.as_raw_fd() as u32;
            }
            None => {
                sa.sxdp_flags = XDP_USE_NEED_WAKEUP
                    | match cfg.bind_mode {
                        BindMode::Auto => 0,
                        BindMode::Copy => XDP_COPY,
                        BindMode::ZeroCopy => XDP_ZEROCOPY,
                    };
            }
        }
        // SAFETY: `sa` is a live, fully initialised sockaddr_xdp and the
        // length passed is its size.
        cvt(unsafe {
            libc::bind(
                raw,
                &sa as *const _ as *const libc::sockaddr,
                size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        })
        .map_err(|e| ctx(e, &format!("bind(ifindex {ifindex}, queue {queue})")))?;

        let mut opts: u32 = 0;
        let mut optlen = size_of::<u32>() as libc::socklen_t;
        // SAFETY: `opts`/`optlen` are live locals sized for the answer.
        let zero_copy = unsafe {
            libc::getsockopt(
                raw,
                SOL_XDP,
                XDP_OPTIONS,
                &mut opts as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        } == 0
            && opts & XDP_OPTIONS_ZEROCOPY != 0;

        Ok(Xsk {
            rx,
            tx,
            fill,
            comp,
            fd,
            ifindex,
            queue,
            zero_copy,
        })
    }

    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Tell the kernel there's something on the TX ring. In copy mode this
    /// syscall is what actually transmits; in zero-copy mode it's only needed
    /// when the driver went to sleep and set the need-wakeup flag.
    #[inline]
    pub fn kick_tx(&self) {
        if !self.zero_copy || self.tx.needs_wakeup() {
            // SAFETY: zero-length send with null buffers is the documented
            // AF_XDP kick; the kernel reads nothing through the pointers.
            unsafe {
                libc::sendto(
                    self.fd(),
                    std::ptr::null(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null(),
                    0,
                )
            };
            // EAGAIN / EBUSY / ENOBUFS just mean "try again next round".
        }
    }

    /// Wake the driver's RX processing if it is waiting for fill-ring frames.
    #[inline]
    pub fn kick_rx(&self) {
        if self.fill.needs_wakeup() {
            // SAFETY: zero-length receive with null buffers: the kernel writes
            // nothing through the pointers.
            unsafe {
                libc::recvfrom(
                    self.fd(),
                    std::ptr::null_mut(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
        }
    }

    /// Kernel-side drop counters for this socket.
    pub fn statistics(&self) -> io::Result<XskStats> {
        let mut s = XskStats::default();
        let mut optlen = size_of::<XskStats>() as libc::socklen_t;
        // SAFETY: `s`/`optlen` are live locals; older kernels fill in fewer
        // fields, and the rest stay zero from `default()`.
        cvt(unsafe {
            libc::getsockopt(
                self.fd(),
                SOL_XDP,
                XDP_STATISTICS,
                &mut s as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        })?;
        Ok(s)
    }
}

/// An AF_XDP socket option. `T` must be the `#[repr(C)]` type (or integer)
/// the kernel expects for `name`.
fn setsockopt<T>(fd: RawFd, name: libc::c_int, v: &T) -> io::Result<()> {
    // SAFETY: `v` is a live reference and the length is exactly its size, so
    // the kernel reads only initialised memory we own.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            name,
            v as *const T as *const libc::c_void,
            size_of::<T>() as libc::socklen_t,
        )
    })
    .map(drop)
}

fn map_ring<T: Copy>(
    fd: RawFd,
    off: &XdpRingOffset,
    size: u32,
    pgoff: libc::off_t,
) -> io::Result<Ring<T>> {
    let len = off.desc as usize + size as usize * size_of::<T>();
    // SAFETY: maps the socket's own ring (selected by `pgoff`) at an address
    // of the kernel's choosing: it can't alias existing memory. Checked
    // against MAP_FAILED below.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            pgoff,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(ctx(io::Error::last_os_error(), "mmap ring"));
    }
    // SAFETY: `p` is the live mapping of `len` bytes just made for this ring,
    // laid out as `off` says; the Ring takes it over (and checks the layout).
    Ok(unsafe { Ring::new(p, len, off, size) })
}

fn ctx(e: io::Error, what: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}
