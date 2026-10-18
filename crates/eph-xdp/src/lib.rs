//! AF_XDP from first principles.
//!
//! Most projects use libxdp/libbpf (C) or a crate wrapping them. This crate
//! talks to the kernel directly with `socket`, `setsockopt`, `mmap` and the
//! `bpf` syscall. It is only a few hundred lines, and every step the kernel
//! needs is visible here.
//!
//! The moving parts:
//!
//! * **UMEM** ([`Umem`]): one big chunk of memory split into equal frames
//!   (4 KiB each). The NIC writes received packets straight into these frames,
//!   and transmits from them. Packets never get copied between kernel and user
//!   space: we pass frame *addresses* around.
//! * **Four rings** per socket ([`ring`]): single-producer/single-consumer
//!   circular queues shared between us and the kernel:
//!     - *fill*: we give the kernel empty frames to receive into
//!     - *rx*: the kernel gives us frames that now contain packets
//!     - *tx*: we give the kernel frames to send
//!     - *completion*: the kernel gives back frames it finished sending
//! * **XSKMAP + XDP program** ([`bpf`]): a tiny eBPF program attached to the
//!   NIC driver that runs for every packet and says "redirect to the AF_XDP
//!   socket for this RX queue".
//!
//! Linux only; on other platforms this crate is empty.

#![cfg(target_os = "linux")]

pub mod bpf;
pub mod iface;
pub mod ring;
mod socket;
mod sys;
mod umem;

pub use bpf::{XdpMode, XdpRedirect, XskMap};
pub use socket::{BindMode, Xsk, XskConfig, XskStats};
pub use sys::XdpDesc;
pub use umem::Umem;
