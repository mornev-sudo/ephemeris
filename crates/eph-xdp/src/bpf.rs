//! The XDP side: an XSKMAP and a hand-assembled eBPF redirect program.
//!
//! eBPF is a small 64-bit virtual machine inside the kernel: 11 registers,
//! 8-byte instructions. The kernel *verifies* a program before accepting it
//! (it must terminate, only touch memory it's allowed to, etc.) and then
//! JIT-compiles it to native machine code. An XDP program runs inside the
//! NIC driver for every received packet, before the kernel has allocated
//! anything for it, and returns a verdict: DROP, PASS (to the normal stack),
//! TX (bounce out the same port), or REDIRECT (somewhere else, here: to our
//! AF_XDP socket).
//!
//! Our program is the C equivalent of:
//!
//! ```c
//! int redirect(struct xdp_md *ctx) {
//!     return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_DROP);
//! }
//! ```
//!
//! Six instructions. Normally a compiler (clang, or rustc via Aya) produces
//! them; writing them out by hand keeps the build free of a BPF toolchain and
//! shows there's no magic.

use crate::sys::*;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// A map from RX queue index to the AF_XDP socket bound to that queue.
pub struct XskMap {
    fd: OwnedFd,
}

impl XskMap {
    pub fn new(max_entries: u32) -> io::Result<Self> {
        let mut name = [0u8; 16];
        name[..8].copy_from_slice(b"eph_xsks\0");
        let mut attr = MapCreateAttr {
            map_type: BPF_MAP_TYPE_XSKMAP,
            key_size: 4,
            value_size: 4,
            max_entries,
            map_name: name,
            ..Default::default()
        };
        let fd = unsafe { bpf(BPF_MAP_CREATE, &mut attr) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(XskMap {
            fd: unsafe { OwnedFd::from_raw_fd(fd as RawFd) },
        })
    }

    /// Point `queue` at the socket `xsk_fd`.
    pub fn insert(&self, queue: u32, xsk_fd: RawFd) -> io::Result<()> {
        let key = queue;
        let value = xsk_fd as u32;
        let mut attr = MapUpdateAttr {
            map_fd: self.fd.as_raw_fd() as u32,
            key: &key as *const u32 as u64,
            value: &value as *const u32 as u64,
            ..Default::default()
        };
        if unsafe { bpf(BPF_MAP_UPDATE_ELEM, &mut attr) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    /// Runs inside the NIC driver ("native"). Fast; needs driver support.
    Native,
    /// Runs later, on an already allocated skb ("generic"/"SKB mode").
    /// Works on any interface but loses most of the speed benefit.
    Generic,
    /// Try native, fall back to generic.
    Auto,
}

/// A loaded program attached to an interface. Dropping it (or the process
/// dying) detaches it: the attachment is a *BPF link* owned by our fd, so a
/// crashed router never leaves an orphaned program eating traffic.
pub struct XdpRedirect {
    _prog: OwnedFd,
    _link: OwnedFd,
    pub mode: XdpMode,
}

impl XdpRedirect {
    pub fn attach(ifindex: u32, map: &XskMap, mode: XdpMode) -> io::Result<Self> {
        let prog = load_program(map.fd.as_raw_fd())?;
        let try_mode = |m: XdpMode| -> io::Result<OwnedFd> {
            let flags = match m {
                XdpMode::Native => XDP_FLAGS_DRV_MODE,
                _ => XDP_FLAGS_SKB_MODE,
            };
            let mut attr = LinkCreateAttr {
                prog_fd: prog.as_raw_fd() as u32,
                target_ifindex: ifindex,
                attach_type: BPF_XDP,
                flags,
                ..Default::default()
            };
            let fd = unsafe { bpf(BPF_LINK_CREATE, &mut attr) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
        };
        let (link, mode) = match mode {
            XdpMode::Auto => match try_mode(XdpMode::Native) {
                Ok(l) => (l, XdpMode::Native),
                Err(_) => (try_mode(XdpMode::Generic)?, XdpMode::Generic),
            },
            m => (try_mode(m)?, m),
        };
        Ok(XdpRedirect {
            _prog: prog,
            _link: link,
            mode,
        })
    }
}

// Opcode building blocks (see the kernel's Documentation/bpf/instruction-set.rst).
const BPF_LDX: u8 = 0x01;
const BPF_ALU64: u8 = 0x07;
const BPF_JMP: u8 = 0x05;
const BPF_LD: u8 = 0x00;
const BPF_MEM: u8 = 0x60;
const BPF_IMM: u8 = 0x00;
const BPF_W: u8 = 0x00; // 32-bit
const BPF_DW: u8 = 0x18; // 64-bit
const BPF_MOV: u8 = 0xb0;
const BPF_K: u8 = 0x00; // immediate operand
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;
const BPF_PSEUDO_MAP_FD: u8 = 1;
const BPF_FUNC_REDIRECT_MAP: i32 = 51;
/// XDP_DROP. (Not XDP_PASS: a queue without a socket must fail closed, not
/// hand data-plane traffic to the kernel's own network stack.)
const XDP_DROP: i32 = 1;
/// offsetof(struct xdp_md, rx_queue_index)
const XDP_MD_RX_QUEUE_INDEX: i16 = 16;

const fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> BpfInsn {
    BpfInsn {
        code,
        regs: dst | (src << 4),
        off,
        imm,
    }
}

fn program(map_fd: RawFd) -> [BpfInsn; 6] {
    [
        // r2 = ctx->rx_queue_index        (r1 holds the ctx pointer on entry)
        insn(BPF_LDX | BPF_MEM | BPF_W, 2, 1, XDP_MD_RX_QUEUE_INDEX, 0),
        // r1 = &xsks  (a 16-byte "load 64-bit immediate"; the kernel swaps the
        //              fd for the real map pointer when it loads the program)
        insn(BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, map_fd),
        insn(0, 0, 0, 0, 0),
        // r3 = XDP_DROP   (what to return if no socket is bound to this queue)
        insn(BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, XDP_DROP),
        // r0 = bpf_redirect_map(r1, r2, r3)
        insn(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP),
        // return r0
        insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]
}

fn load_program(map_fd: RawFd) -> io::Result<OwnedFd> {
    let insns = program(map_fd);
    let license = b"Dual MIT/GPL\0";
    let mut name = [0u8; 16];
    name[..12].copy_from_slice(b"eph_redirect\0");
    let mut attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        prog_name: name,
        expected_attach_type: BPF_XDP,
        ..Default::default()
    };
    let fd = unsafe { bpf(BPF_PROG_LOAD, &mut attr) };
    if fd >= 0 {
        return Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) });
    }
    let err = io::Error::last_os_error();
    // Retry with the verifier log enabled so the error says *why*.
    let mut log = vec![0u8; 64 * 1024];
    attr.log_level = 1;
    attr.log_size = log.len() as u32;
    attr.log_buf = log.as_mut_ptr() as u64;
    unsafe { bpf(BPF_PROG_LOAD, &mut attr) };
    let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
    Err(io::Error::new(
        err.kind(),
        format!(
            "BPF_PROG_LOAD: {err}\nverifier log:\n{}",
            String::from_utf8_lossy(&log[..end])
        ),
    ))
}
