//! PPPoE: dialling an ISP on an outside interface (`address = "pppoe"`).
//!
//! The data plane wraps and unwraps IPv4 in the session once it's up, and
//! hands everything else (discovery, LCP, authentication, IPCP) to the
//! control plane, where [`client`] runs the protocol.

pub mod client;
