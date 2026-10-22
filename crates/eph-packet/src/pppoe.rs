//! PPPoE (RFC 2516) and the PPP control protocols carried in it (LCP RFC
//! 1661, PAP RFC 1334, CHAP RFC 1994, IPCP RFC 1332 / 1877).
//!
//! Like DHCP, this is control-plane traffic (a handful of packets to dial,
//! then a keepalive every few seconds), so it allocates freely. The data
//! plane only needs [`SESSION_HDR_LEN`] and the header layout to wrap and
//! unwrap IPv4.

use crate::{eth, Mac};

pub const TYPE_DISCOVERY: u16 = 0x8863;
pub const TYPE_SESSION: u16 = 0x8864;
/// PPPoE header (6) + PPP protocol (2): what IPv4 in a session costs.
pub const SESSION_HDR_LEN: usize = 8;
/// The usual PPPoE MTU: a 1500-byte Ethernet payload minus those 8 bytes.
pub const DEFAULT_MTU: u16 = 1492;

// Discovery codes.
pub const PADI: u8 = 0x09;
pub const PADO: u8 = 0x07;
pub const PADR: u8 = 0x19;
pub const PADS: u8 = 0x65;
pub const PADT: u8 = 0xa7;
pub const CODE_SESSION: u8 = 0x00;

// Discovery tags.
pub const TAG_END: u16 = 0x0000;
pub const TAG_SERVICE_NAME: u16 = 0x0101;
pub const TAG_AC_NAME: u16 = 0x0102;
pub const TAG_HOST_UNIQ: u16 = 0x0103;
pub const TAG_AC_COOKIE: u16 = 0x0104;
pub const TAG_RELAY_SESSION_ID: u16 = 0x0110;
pub const TAG_SERVICE_NAME_ERROR: u16 = 0x0201;
pub const TAG_AC_SYSTEM_ERROR: u16 = 0x0202;
pub const TAG_GENERIC_ERROR: u16 = 0x0203;

// PPP protocol numbers.
pub const PROTO_IPV4: u16 = 0x0021;
pub const PROTO_LCP: u16 = 0xc021;
pub const PROTO_PAP: u16 = 0xc023;
pub const PROTO_CHAP: u16 = 0xc223;
pub const PROTO_IPCP: u16 = 0x8021;

// LCP / IPCP codes (shared numbering, RFC 1661 section 5).
pub const CONF_REQ: u8 = 1;
pub const CONF_ACK: u8 = 2;
pub const CONF_NAK: u8 = 3;
pub const CONF_REJ: u8 = 4;
pub const TERM_REQ: u8 = 5;
pub const TERM_ACK: u8 = 6;
pub const CODE_REJ: u8 = 7;
pub const PROTO_REJ: u8 = 8;
pub const ECHO_REQ: u8 = 9;
pub const ECHO_REPLY: u8 = 10;
pub const DISCARD_REQ: u8 = 11;

/// An LCP/IPCP code's name, for logs.
pub fn code_name(code: u8) -> &'static str {
    match code {
        CONF_REQ => "Configure-Request",
        CONF_ACK => "Configure-Ack",
        CONF_NAK => "Configure-Nak",
        CONF_REJ => "Configure-Reject",
        TERM_REQ => "Terminate-Request",
        TERM_ACK => "Terminate-Ack",
        CODE_REJ => "Code-Reject",
        PROTO_REJ => "Protocol-Reject",
        ECHO_REQ => "Echo-Request",
        ECHO_REPLY => "Echo-Reply",
        DISCARD_REQ => "Discard-Request",
        _ => "unknown code",
    }
}

// LCP options.
pub const LCP_MRU: u8 = 1;
pub const LCP_AUTH: u8 = 3;
pub const LCP_MAGIC: u8 = 5;
/// CHAP algorithm 5: MD5.
pub const CHAP_MD5: u8 = 5;

// IPCP options.
pub const IPCP_ADDRESS: u8 = 3;
pub const IPCP_DNS1: u8 = 129;
pub const IPCP_DNS2: u8 = 131;

/// A received PPPoE frame (discovery or session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub src: Mac,
    pub dst: Mac,
    pub ethertype: u16,
    pub code: u8,
    pub session: u16,
    /// The PPPoE payload: tags for discovery, PPP protocol + data for a
    /// session.
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn parse(f: &[u8]) -> Option<Frame> {
        if f.len() < eth::HDR_LEN + 6 {
            return None;
        }
        let ethertype = eth::ethertype(f);
        if ethertype != TYPE_DISCOVERY && ethertype != TYPE_SESSION {
            return None;
        }
        let p = &f[eth::HDR_LEN..];
        if p[0] != 0x11 {
            return None; // version 1, type 1
        }
        let len = u16::from_be_bytes([p[4], p[5]]) as usize;
        let payload = p.get(6..6 + len)?.to_vec();
        Some(Frame {
            src: eth::src(f),
            dst: eth::dst(f),
            ethertype,
            code: p[1],
            session: u16::from_be_bytes([p[2], p[3]]),
            payload,
        })
    }

    /// Discovery tags, in order.
    pub fn tags(&self) -> Vec<(u16, Vec<u8>)> {
        let mut out = vec![];
        let p = &self.payload;
        let mut i = 0;
        while i + 4 <= p.len() {
            let t = u16::from_be_bytes([p[i], p[i + 1]]);
            let l = u16::from_be_bytes([p[i + 2], p[i + 3]]) as usize;
            let Some(v) = p.get(i + 4..i + 4 + l) else {
                break;
            };
            if t == TAG_END {
                break;
            }
            out.push((t, v.to_vec()));
            i += 4 + l;
        }
        out
    }

    pub fn tag(&self, t: u16) -> Option<Vec<u8>> {
        self.tags()
            .into_iter()
            .find(|(x, _)| *x == t)
            .map(|(_, v)| v)
    }

    /// For a session frame: the PPP protocol and its data.
    pub fn ppp(&self) -> Option<(u16, &[u8])> {
        (self.payload.len() >= 2).then(|| {
            (
                u16::from_be_bytes([self.payload[0], self.payload[1]]),
                &self.payload[2..],
            )
        })
    }
}

/// A discovery packet.
pub fn discovery(src: Mac, dst: Mac, code: u8, session: u16, tags: &[(u16, &[u8])]) -> Vec<u8> {
    let mut payload = vec![];
    for (t, v) in tags {
        payload.extend_from_slice(&t.to_be_bytes());
        payload.extend_from_slice(&(v.len() as u16).to_be_bytes());
        payload.extend_from_slice(v);
    }
    frame(src, dst, TYPE_DISCOVERY, code, session, &payload)
}

/// A PPP packet in a session.
pub fn session(src: Mac, dst: Mac, session: u16, proto: u16, data: &[u8]) -> Vec<u8> {
    let mut payload = proto.to_be_bytes().to_vec();
    payload.extend_from_slice(data);
    frame(src, dst, TYPE_SESSION, CODE_SESSION, session, &payload)
}

fn frame(src: Mac, dst: Mac, ethertype: u16, code: u8, session: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; eth::HDR_LEN + 6];
    eth::write(&mut f, dst, src, ethertype);
    let p = &mut f[eth::HDR_LEN..];
    p[0] = 0x11;
    p[1] = code;
    p[2..4].copy_from_slice(&session.to_be_bytes());
    p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    f.extend_from_slice(payload);
    // Ethernet minimum frame (without FCS): 60 bytes.
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}

/// An LCP / IPCP / PAP / CHAP packet: code, identifier, data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub code: u8,
    pub id: u8,
    pub data: Vec<u8>,
}

impl Control {
    pub fn parse(p: &[u8]) -> Option<Control> {
        if p.len() < 4 {
            return None;
        }
        let len = u16::from_be_bytes([p[2], p[3]]) as usize;
        if len < 4 || len > p.len() {
            return None;
        }
        Some(Control {
            code: p[0],
            id: p[1],
            data: p[4..len].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut p = vec![self.code, self.id];
        p.extend_from_slice(&((self.data.len() + 4) as u16).to_be_bytes());
        p.extend_from_slice(&self.data);
        p
    }
}

/// Configure options: (type, value). Malformed lists give `None`.
pub fn options(data: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
    let mut out = vec![];
    let mut i = 0;
    while i < data.len() {
        let t = data[i];
        let l = *data.get(i + 1)? as usize;
        if l < 2 {
            return None;
        }
        out.push((t, data.get(i + 2..i + l)?.to_vec()));
        i += l;
    }
    Some(out)
}

pub fn encode_options(opts: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![];
    for (t, v) in opts {
        out.push(*t);
        out.push((v.len() + 2) as u8);
        out.extend_from_slice(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Mac = [2, 0, 0, 0, 0, 1];
    const AC: Mac = [2, 0, 0, 0, 0, 0xac];

    #[test]
    fn discovery_round_trip() {
        let f = discovery(
            ME,
            eth::BROADCAST,
            PADI,
            0,
            &[(TAG_SERVICE_NAME, b""), (TAG_HOST_UNIQ, &[1, 2, 3, 4])],
        );
        assert_eq!(f.len(), 60, "padded to the Ethernet minimum");
        let p = Frame::parse(&f).unwrap();
        assert_eq!((p.code, p.session, p.ethertype), (PADI, 0, TYPE_DISCOVERY));
        assert_eq!(p.tag(TAG_SERVICE_NAME), Some(vec![]));
        assert_eq!(p.tag(TAG_HOST_UNIQ), Some(vec![1, 2, 3, 4]));
        assert_eq!(p.tag(TAG_AC_COOKIE), None);
    }

    #[test]
    fn session_and_control_round_trip() {
        let opts = encode_options(&[
            (LCP_MRU, 1492u16.to_be_bytes().to_vec()),
            (LCP_MAGIC, vec![1, 2, 3, 4]),
        ]);
        let lcp = Control {
            code: CONF_REQ,
            id: 7,
            data: opts,
        };
        let f = session(ME, AC, 0x1234, PROTO_LCP, &lcp.encode());
        let p = Frame::parse(&f).unwrap();
        assert_eq!((p.code, p.session), (CODE_SESSION, 0x1234));
        let (proto, data) = p.ppp().unwrap();
        assert_eq!(proto, PROTO_LCP);
        let c = Control::parse(data).unwrap();
        assert_eq!(c, lcp);
        let o = options(&c.data).unwrap();
        assert_eq!(o[0], (LCP_MRU, vec![0x05, 0xd4]));
        assert_eq!(o[1].0, LCP_MAGIC);
    }

    #[test]
    fn rejects_malformed() {
        assert!(
            options(&[1, 1]).is_none(),
            "an option shorter than its header"
        );
        assert!(options(&[1, 9, 0]).is_none(), "an option past the end");
        assert!(Control::parse(&[1, 1, 0, 9, 0]).is_none());
        let mut f = session(ME, AC, 1, PROTO_LCP, &[1, 1, 0, 4]);
        f[eth::HDR_LEN] = 0x21; // wrong version
        assert!(Frame::parse(&f).is_none());
    }
}
