//! Small helpers to look up interface facts.

use std::ffi::CString;
use std::io;

pub fn ifindex(name: &str) -> io::Result<u32> {
    let c =
        CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad name"))?;
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
