//! Kernel ABI: constants and structs from <linux/if_xdp.h> and <linux/bpf.h>.

pub const AF_XDP: libc::c_int = 44;
pub const SOL_XDP: libc::c_int = 283;

// setsockopt / getsockopt names
pub const XDP_MMAP_OFFSETS: libc::c_int = 1;
pub const XDP_RX_RING: libc::c_int = 2;
pub const XDP_TX_RING: libc::c_int = 3;
pub const XDP_UMEM_REG: libc::c_int = 4;
pub const XDP_UMEM_FILL_RING: libc::c_int = 5;
pub const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
pub const XDP_STATISTICS: libc::c_int = 7;
pub const XDP_OPTIONS: libc::c_int = 8;
pub const XDP_OPTIONS_ZEROCOPY: u32 = 1;

// sockaddr_xdp.sxdp_flags
pub const XDP_SHARED_UMEM: u16 = 1 << 0;
pub const XDP_COPY: u16 = 1 << 1;
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// ring flags
pub const XDP_RING_NEED_WAKEUP: u32 = 1;

// mmap page offsets selecting which ring to map
pub const XDP_PGOFF_RX_RING: libc::off_t = 0;
pub const XDP_PGOFF_TX_RING: libc::off_t = 0x8000_0000;
pub const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x1_0000_0000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x1_8000_0000;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct XdpRingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffset,
    pub tx: XdpRingOffset,
    pub fr: XdpRingOffset,
    pub cr: XdpRingOffset,
}

#[repr(C)]
#[derive(Default)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
    pub tx_metadata_len: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct SockaddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

/// An RX or TX ring entry: which frame (byte offset into the UMEM) and how
/// many bytes of it are packet.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct XdpStatistics {
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub tx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub rx_fill_ring_empty_descs: u64,
    pub tx_ring_empty_descs: u64,
}

// ---- bpf(2)

pub const BPF_MAP_CREATE: libc::c_long = 0;
pub const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
pub const BPF_PROG_LOAD: libc::c_long = 5;
pub const BPF_LINK_CREATE: libc::c_long = 28;

pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
pub const BPF_PROG_TYPE_XDP: u32 = 6;
pub const BPF_XDP: u32 = 37; // enum bpf_attach_type

pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

#[repr(C)]
#[derive(Default)]
pub struct MapCreateAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub inner_map_fd: u32,
    pub numa_node: u32,
    pub map_name: [u8; 16],
}

#[repr(C)]
#[derive(Default)]
pub struct MapUpdateAttr {
    pub map_fd: u32,
    pub _pad: u32,
    pub key: u64,
    pub value: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct ProgLoadAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: u64,
    pub kern_version: u32,
    pub prog_flags: u32,
    pub prog_name: [u8; 16],
    pub prog_ifindex: u32,
    pub expected_attach_type: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct LinkCreateAttr {
    pub prog_fd: u32,
    pub target_ifindex: u32,
    pub attach_type: u32,
    pub flags: u32,
    pub _union: [u64; 4],
}

/// One eBPF instruction (8 bytes). `regs` packs dst (low nibble) and src
/// (high nibble).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfInsn {
    pub code: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

pub unsafe fn bpf<T>(cmd: libc::c_long, attr: &mut T) -> libc::c_long {
    libc::syscall(libc::SYS_bpf, cmd, attr as *mut T, std::mem::size_of::<T>())
}

pub fn cvt(r: libc::c_int) -> std::io::Result<libc::c_int> {
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r)
    }
}
