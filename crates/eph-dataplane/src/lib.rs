//! The forwarding pipeline.
//!
//! This crate holds the router's packet logic, and *only* the logic: it gets
//! a mutable byte buffer and returns a [`Verdict`] saying what to do with it.
//! It never touches a socket or a NIC. That separation means everything here
//! can be unit-tested on any machine (including a Mac), and the same code can
//! later sit behind AF_XDP, DPDK, or a pcap file without changing.
//!
//! One [`Pipeline`] exists per worker thread (per CPU core). Workers share
//! nothing mutable, so no locks are needed on the fast path. The only state
//! that must be shared, learned ARP neighbours, is passed between workers as
//! messages (see [`Pipeline::learned`] / [`Pipeline::learn`]).

// No unsafe code here: packet parsing, routing and forwarding logic is
// all safe Rust, and the compiler keeps it that way.
#![forbid(unsafe_code)]

mod config;
mod filter;
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzzing;
pub mod host;
pub mod nat;
pub mod overlay;
mod pipeline;
pub mod session;
mod stats;
pub mod steer;
pub mod trace;

pub use config::{build_fib, Dhcp, NextHop, OverlayRoute, Port, PortId, Pppoe, Role, StaticRoute};
pub use pipeline::{Emit, Handoff, HandshakeIn, Neighbor, Pipeline, Punt, Verdict, NEIGHBOR_MAX};
pub use session::{
    AppTimeout, Dir, FlowKey, NatBinding, Session, SessionConfig, State, Timeouts, Unanswered,
    MAX_APP_TIMEOUTS, MAX_CLOSING_SECS, MAX_IDLE_SECS,
};
pub use stats::{DropReason, PortCounters, Stats};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_dynamic;
#[cfg(test)]
mod tests_filter;
#[cfg(test)]
mod tests_fuzz;
#[cfg(test)]
mod tests_nat;
#[cfg(test)]
mod tests_overlay;
#[cfg(test)]
mod tests_session_keys;
#[cfg(test)]
mod tests_steer;
#[cfg(test)]
mod tests_vlan;
