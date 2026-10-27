//! Every packet parser on raw bytes: none may panic, whatever arrives. The
//! DHCP and PPPoE ones are what the control plane reads from the network
//! (LAN clients, the ISP).
#![no_main]

use eph_packet::{arp, dhcp, ipv4, pppoe};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = arp::parse(data);
    let _ = ipv4::parse(data);
    let _ = ipv4::find_option(data, |_| true);
    if let Some(m) = dhcp::Message::parse(data) {
        // Reading every option of a parsed message must be safe too.
        let _ = (m.msg_type(), m.prefix_len(), m.text(dhcp::OPT_HOSTNAME));
        let _ = m.ips(dhcp::OPT_DNS);
        let _ = m.u32(dhcp::OPT_LEASE_TIME);
        let _ = m.encode();
    }
    let _ = dhcp::parse_frame(data);
    if let Some(f) = pppoe::Frame::parse(data) {
        let _ = f.tag(pppoe::TAG_AC_NAME);
        if let Some((_, payload)) = f.ppp() {
            if let Some(c) = pppoe::Control::parse(payload) {
                let _ = pppoe::options(&c.data);
            }
        }
    }
    let _ = pppoe::Control::parse(data);
    let _ = pppoe::options(data);
});
