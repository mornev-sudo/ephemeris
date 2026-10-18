//! The network cards this router has, as the kernel sees them. Used by the
//! portal's interface forms and to refuse configs naming a card that isn't
//! there (or that management depends on).

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Nic {
    pub name: String,
    pub mac: String,
    pub driver: String,
    /// "up", "down", ... (operstate)
    pub link: String,
    /// The kernel routes through it: it's the management NIC, and handing
    /// it to the data plane would cut the router off.
    pub kernel: bool,
}

#[cfg(target_os = "linux")]
pub fn list() -> Vec<Nic> {
    let read = |p: String| {
        std::fs::read_to_string(p)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let kernel: Vec<String> = read("/proc/net/route".into())
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect();
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
        .into_iter()
        // Only real (or virtio) cards: virtual links like lo have no device.
        .filter(|n| std::path::Path::new(&format!("/sys/class/net/{n}/device")).exists())
        .map(|n| Nic {
            mac: read(format!("/sys/class/net/{n}/address")),
            driver: std::fs::read_link(format!("/sys/class/net/{n}/device/driver"))
                .ok()
                .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
                .unwrap_or_default(),
            link: read(format!("/sys/class/net/{n}/operstate")),
            kernel: kernel.contains(&n),
            name: n,
        })
        .collect()
}

/// The dev portal has no real NICs: pretend, like a small lab router.
#[cfg(not(target_os = "linux"))]
pub fn list() -> Vec<Nic> {
    [
        ("ens16", "ixgbe", "down", false),
        ("ens18", "virtio_net", "up", true),
        ("ens19", "virtio_net", "up", false),
        ("ens20", "virtio_net", "up", false),
    ]
    .iter()
    .map(|&(n, d, l, k)| Nic {
        name: n.into(),
        mac: "02:00:00:00:00:01".into(),
        driver: d.into(),
        link: l.into(),
        kernel: k,
    })
    .collect()
}
