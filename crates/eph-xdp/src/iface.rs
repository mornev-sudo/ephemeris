//! Small helpers to look up interface facts.

use crate::sys::{cvt, PacketMreq, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub fn ifindex(name: &str) -> io::Result<u32> {
    let c =
        CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad name"))?;
    // SAFETY: `c` is a valid NUL-terminated string, live for the call.
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no such interface: {name}"),
        )),
        i => Ok(i),
    }
}

/// MAC address as text, e.g. "bc:24:11:aa:bb:cc".
pub fn mac(name: &str) -> io::Result<String> {
    Ok(
        std::fs::read_to_string(format!("/sys/class/net/{name}/address"))?
            .trim()
            .to_string(),
    )
}

/// How many RX queues the NIC currently exposes.
pub fn rx_queues(name: &str) -> io::Result<u32> {
    let n = std::fs::read_dir(format!("/sys/class/net/{name}/queues"))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("rx-"))
        .count();
    Ok(n as u32)
}

/// Has the link been administratively set up (`ip link set dev X up`)?
///
/// This reads the IFF_UP flag, not `operstate`: right after `ip link set up`
/// the operstate can still read "down" for a moment while the carrier comes
/// up, and the router shouldn't refuse to start because of that.
pub fn is_up(name: &str) -> bool {
    const IFF_UP: u32 = 0x1;
    std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & IFF_UP != 0)
}

/// Stop the NIC taking 802.1Q tags off received frames (what `ethtool -K
/// <dev> rxvlan off` does). With "VLAN stripping" on, the card moves the tag
/// into the receive descriptor, where XDP never sees it: a tagged frame
/// would arrive looking untagged. Returns whether it was on.
///
/// This uses the old ETHTOOL_GFLAGS / SFLAGS ioctl: one flag word instead
/// of the feature-string tables `ethtool` itself walks.
pub fn disable_vlan_stripping(name: &str) -> io::Result<bool> {
    const ETHTOOL_GFLAGS: u32 = 0x25;
    const ETHTOOL_SFLAGS: u32 = 0x26;
    const ETH_FLAG_RXVLAN: u32 = 1 << 8;
    #[repr(C)]
    struct EthtoolValue {
        cmd: u32,
        data: u32,
    }
    // SAFETY: plain syscall, no pointers; the result is checked.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    // SAFETY: a new, valid descriptor nobody else owns.
    let sock = unsafe { OwnedFd::from_raw_fd(cvt(sock)?) };
    // SAFETY: ifreq is plain C data (integers, arrays, a union of them and
    // a pointer); all zeros is a valid value, and a NUL-filled name.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    // At most 15 bytes and no NUL inside, so the name stays NUL-terminated
    // and the kernel reads the whole of it (a NUL would cut it short and
    // name a different card).
    if name.len() >= req.ifr_name.len() || name.bytes().any(|b| b == 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad name"));
    }
    for (d, s) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *d = s as libc::c_char;
    }
    let mut v = EthtoolValue {
        cmd: ETHTOOL_GFLAGS,
        data: 0,
    };
    let mut call = |v: &mut EthtoolValue| {
        req.ifr_ifru.ifru_data = v as *mut EthtoolValue as *mut libc::c_char;
        // SAFETY: `req` names the card (NUL-terminated, checked above) and
        // points at `v`, a live ethtool_value the kernel reads and writes in
        // place for the duration of the call.
        cvt(unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCETHTOOL, &mut req) })
    };
    call(&mut v)?;
    if v.data & ETH_FLAG_RXVLAN == 0 {
        return Ok(false);
    }
    v.cmd = ETHTOOL_SFLAGS;
    v.data &= !ETH_FLAG_RXVLAN;
    call(&mut v)?;
    Ok(true)
}

/// The card in promiscuous mode for as long as this lives.
///
/// A card carrying VLANs needs it: many NICs (Intel's, and virtio under
/// QEMU) filter VLAN tags in hardware and drop every VLAN nobody registered.
/// The kernel registers one when a VLAN device (ens19.10) is created, but
/// the router has none: it reads the tags itself. Promiscuous mode lets all
/// VLANs through. (Frames for other MACs come in too; the pipeline drops
/// them, and on a switched network there are few.)
///
/// The request is tied to a packet socket rather than set as an interface
/// flag: closing the socket (or the process dying) takes it back, like the
/// XDP link, so nothing is left behind.
pub struct Promisc {
    _sock: OwnedFd,
}

impl Promisc {
    pub fn enable(ifindex: u32) -> io::Result<Self> {
        // Protocol 0: the socket receives nothing, it only holds the request.
        // SAFETY: plain syscall, no pointers; the result is checked.
        let sock = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        // SAFETY: a new, valid descriptor nobody else owns.
        let sock = unsafe { OwnedFd::from_raw_fd(cvt(sock)?) };
        let mreq = PacketMreq {
            mr_ifindex: ifindex as libc::c_int,
            mr_type: PACKET_MR_PROMISC,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        // SAFETY: `mreq` is a live, fully initialised packet_mreq and the
        // length passed is its size.
        cvt(unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mreq as *const PacketMreq as *const libc::c_void,
                std::mem::size_of::<PacketMreq>() as libc::socklen_t,
            )
        })?;
        Ok(Promisc { _sock: sock })
    }
}
