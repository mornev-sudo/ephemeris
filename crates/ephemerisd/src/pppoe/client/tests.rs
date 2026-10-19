//! The client against a scripted ISP: an access concentrator and PPP
//! server that answers the way pppd / a BRAS does.

use super::*;
use md5::{Digest, Md5};

const ME: Mac = [2, 0, 0, 0, 0, 1];
const AC: Mac = [2, 0, 0, 0, 0, 0xac];
const SESSION: u16 = 0x0042;

#[derive(Clone, Copy, PartialEq)]
enum IspAuth {
    Pap,
    Chap,
}

struct Isp {
    auth: IspAuth,
    user: &'static str,
    pass: &'static str,
    challenge: Vec<u8>,
    lcp_sent: bool,
    /// Stop answering (to test keepalive failure).
    silent: bool,
    /// Protocol-Rejects received.
    proto_rejects: Vec<u16>,
}

impl Isp {
    fn new(auth: IspAuth) -> Self {
        Isp {
            auth,
            user: "alice@isp",
            pass: "s3cret",
            challenge: vec![9, 8, 7, 6, 5, 4, 3, 2],
            lcp_sent: false,
            silent: false,
            proto_rejects: vec![],
        }
    }

    fn ppp(&self, proto: u16, c: Control) -> Vec<u8> {
        pppoe::session(AC, ME, SESSION, proto, &c.encode())
    }

    /// What the ISP sends in answer to one frame from the client.
    fn respond(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        if self.silent {
            return vec![];
        }
        let f = Frame::parse(frame).expect("the client sends valid PPPoE");
        let uniq = f.tag(pppoe::TAG_HOST_UNIQ).unwrap_or_default();
        if f.ethertype == pppoe::TYPE_DISCOVERY {
            return match f.code {
                pppoe::PADI => vec![pppoe::discovery(
                    AC,
                    ME,
                    pppoe::PADO,
                    0,
                    &[
                        (pppoe::TAG_AC_NAME, b"test-bras"),
                        (pppoe::TAG_SERVICE_NAME, b""),
                        (pppoe::TAG_AC_COOKIE, b"c00k"),
                        (pppoe::TAG_HOST_UNIQ, &uniq),
                    ],
                )],
                pppoe::PADR => {
                    assert_eq!(
                        f.tag(pppoe::TAG_AC_COOKIE).as_deref(),
                        Some(&b"c00k"[..]),
                        "the cookie comes back"
                    );
                    vec![pppoe::discovery(
                        AC,
                        ME,
                        pppoe::PADS,
                        SESSION,
                        &[
                            (pppoe::TAG_SERVICE_NAME, b""),
                            (pppoe::TAG_HOST_UNIQ, &uniq),
                        ],
                    )]
                }
                _ => vec![],
            };
        }
        assert_eq!(f.session, SESSION);
        let (proto, data) = f.ppp().unwrap();
        let c = Control::parse(data).unwrap();
        let mut out = vec![];
        match (proto, c.code) {
            (pppoe::PROTO_LCP, pppoe::CONF_REQ) => {
                out.push(self.ppp(
                    proto,
                    Control {
                        code: pppoe::CONF_ACK,
                        id: c.id,
                        data: c.data.clone(),
                    },
                ));
                if !self.lcp_sent {
                    self.lcp_sent = true;
                    let auth = match self.auth {
                        IspAuth::Pap => vec![0xc0, 0x23],
                        IspAuth::Chap => vec![0xc2, 0x23, pppoe::CHAP_MD5],
                    };
                    let opts = pppoe::encode_options(&[
                        (pppoe::LCP_MRU, 1492u16.to_be_bytes().to_vec()),
                        (pppoe::LCP_AUTH, auth),
                        (pppoe::LCP_MAGIC, vec![0xde, 0xad, 0xbe, 0xef]),
                    ]);
                    out.push(self.ppp(
                        proto,
                        Control {
                            code: pppoe::CONF_REQ,
                            id: 1,
                            data: opts,
                        },
                    ));
                }
            }
            (pppoe::PROTO_LCP, pppoe::CONF_ACK) if self.auth == IspAuth::Chap => {
                let mut d = vec![self.challenge.len() as u8];
                d.extend_from_slice(&self.challenge);
                d.extend_from_slice(b"test-bras");
                out.push(self.ppp(
                    pppoe::PROTO_CHAP,
                    Control {
                        code: 1,
                        id: 33,
                        data: d,
                    },
                ));
            }
            (pppoe::PROTO_LCP, pppoe::ECHO_REQ) => {
                out.push(self.ppp(
                    proto,
                    Control {
                        code: pppoe::ECHO_REPLY,
                        id: c.id,
                        data: vec![0xde, 0xad, 0xbe, 0xef],
                    },
                ));
            }
            (pppoe::PROTO_LCP, pppoe::PROTO_REJ) => {
                self.proto_rejects
                    .push(u16::from_be_bytes([c.data[0], c.data[1]]));
            }
            (pppoe::PROTO_PAP, 1) => {
                let ulen = c.data[0] as usize;
                let user = &c.data[1..1 + ulen];
                let pass = &c.data[2 + ulen..2 + ulen + c.data[1 + ulen] as usize];
                let ok = user == self.user.as_bytes() && pass == self.pass.as_bytes();
                out.push(self.ppp(
                    proto,
                    Control {
                        code: if ok { 2 } else { 3 },
                        id: c.id,
                        data: vec![0],
                    },
                ));
                if ok {
                    out.push(self.ipcp_request());
                }
            }
            (pppoe::PROTO_CHAP, 2) => {
                let mut h = Md5::new();
                h.update([c.id]);
                h.update(self.pass.as_bytes());
                h.update(&self.challenge);
                let ok = c.data[1..17] == h.finalize()[..] && &c.data[17..] == self.user.as_bytes();
                out.push(self.ppp(
                    proto,
                    Control {
                        code: if ok { 3 } else { 4 },
                        id: c.id,
                        data: b"welcome".to_vec(),
                    },
                ));
                if ok {
                    out.push(self.ipcp_request());
                }
            }
            (pppoe::PROTO_IPCP, pppoe::CONF_REQ) => {
                let opts = pppoe::options(&c.data).unwrap();
                let want = |t: u8, v: [u8; 4]| (t, v.to_vec());
                let wanted = vec![
                    want(pppoe::IPCP_ADDRESS, [203, 0, 113, 50]),
                    want(pppoe::IPCP_DNS1, [9, 9, 9, 9]),
                    want(pppoe::IPCP_DNS2, [1, 1, 1, 1]),
                ];
                if opts.iter().all(|o| wanted.contains(o)) {
                    out.push(self.ppp(
                        proto,
                        Control {
                            code: pppoe::CONF_ACK,
                            id: c.id,
                            data: c.data.clone(),
                        },
                    ));
                } else {
                    out.push(self.ppp(
                        proto,
                        Control {
                            code: pppoe::CONF_NAK,
                            id: c.id,
                            data: pppoe::encode_options(&wanted),
                        },
                    ));
                }
            }
            _ => {}
        }
        out
    }

    fn ipcp_request(&self) -> Vec<u8> {
        let opts = pppoe::encode_options(&[(pppoe::IPCP_ADDRESS, vec![203, 0, 113, 1])]);
        self.ppp(
            pppoe::PROTO_IPCP,
            Control {
                code: pppoe::CONF_REQ,
                id: 1,
                data: opts,
            },
        )
    }
}

fn client() -> Client {
    Client::new(
        Settings {
            interface: "wan".into(),
            mac: ME,
            username: "alice@isp".into(),
            password: "s3cret".into(),
            service: String::new(),
            mtu: 1492,
        },
        12345,
    )
}

/// Deliver frames back and forth until both sides are quiet; returns the
/// client's events.
fn exchange(c: &mut Client, isp: &mut Isp, first: Vec<Vec<u8>>, now: u64) -> Vec<Event> {
    let mut events = vec![];
    let mut to_isp = first;
    for _ in 0..50 {
        let mut to_client = vec![];
        for f in to_isp.drain(..) {
            to_client.extend(isp.respond(&f));
        }
        if to_client.is_empty() {
            break;
        }
        for f in to_client {
            let (out, ev) = c.handle(&Frame::parse(&f).unwrap(), now);
            to_isp.extend(out);
            events.extend(ev);
        }
    }
    events
}

fn dial(c: &mut Client, isp: &mut Isp, now: u64) -> Vec<Event> {
    let (out, ev) = c.tick(now);
    assert!(ev.is_none());
    exchange(c, isp, out, now)
}

#[test]
fn dials_with_chap_and_gets_address_and_dns() {
    let (mut c, mut isp) = (client(), Isp::new(IspAuth::Chap));
    let ev = dial(&mut c, &mut isp, 100);
    let Some(Event::Up(l)) = ev.last() else {
        panic!("not up: {ev:?}, {:?} {:?}", c.phase, c.last_error)
    };
    assert_eq!(l.session, SESSION);
    assert_eq!(l.ac_mac, AC);
    assert_eq!(l.ac_name, "test-bras");
    assert_eq!(l.addr, Ipv4Addr::new(203, 0, 113, 50));
    assert_eq!(l.peer, Ipv4Addr::new(203, 0, 113, 1));
    assert_eq!(
        l.dns,
        vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 1, 1, 1)]
    );
    assert_eq!(l.mtu, 1492);
    assert_eq!(c.phase, Phase::Up);
}

#[test]
fn dials_with_pap() {
    let (mut c, mut isp) = (client(), Isp::new(IspAuth::Pap));
    assert!(matches!(
        dial(&mut c, &mut isp, 0).last(),
        Some(Event::Up(_))
    ));
}

#[test]
fn a_wrong_password_is_reported_and_retried_later() {
    for auth in [IspAuth::Pap, IspAuth::Chap] {
        let (mut c, mut isp) = (client(), Isp::new(auth));
        isp.pass = "other";
        let ev = dial(&mut c, &mut isp, 0);
        assert!(ev.is_empty(), "never up, so no Down either: {ev:?}");
        assert_eq!(c.phase, Phase::Down);
        assert!(
            c.last_error.as_deref().unwrap().contains("login refused"),
            "{:?}",
            c.last_error
        );
        // Not straight away...
        assert!(c.tick(2).0.is_empty());
        // ...but after the back-off it dials again (a fresh PADI).
        let (out, _) = c.tick(10);
        assert_eq!(Frame::parse(&out[0]).unwrap().code, pppoe::PADI);
    }
}

#[test]
fn keepalives_and_a_dead_link() {
    let (mut c, mut isp) = (client(), Isp::new(IspAuth::Chap));
    dial(&mut c, &mut isp, 0);
    // Every 10 s an echo; the ISP answers, so the link stays up.
    for t in [10, 20, 30, 40] {
        let (out, ev) = c.tick(t);
        assert!(ev.is_none());
        assert_eq!(out.len(), 1, "one echo at {t}");
        assert!(exchange(&mut c, &mut isp, out, t).is_empty());
    }
    // Then it goes quiet: down after 30 s, with a PADT.
    isp.silent = true;
    let mut down = None;
    for t in 41..=80 {
        let (out, ev) = c.tick(t);
        if let Some(e) = ev {
            assert!(out
                .iter()
                .any(|f| Frame::parse(f).unwrap().code == pppoe::PADT));
            down = Some((t, e));
            break;
        }
    }
    let (t, e) = down.expect("goes down");
    assert_eq!(t, 70);
    assert!(matches!(e, Event::Down(_)));
    assert!(c.link.is_none());
}

#[test]
fn padt_from_the_isp_takes_the_link_down() {
    let (mut c, mut isp) = (client(), Isp::new(IspAuth::Pap));
    dial(&mut c, &mut isp, 0);
    let padt = pppoe::discovery(AC, ME, pppoe::PADT, SESSION, &[]);
    let (out, ev) = c.handle(&Frame::parse(&padt).unwrap(), 5);
    assert!(out.is_empty(), "no PADT back for a session that's gone");
    assert!(matches!(ev, Some(Event::Down(_))));
    // A PADT for someone else's session is ignored.
    let (mut c, mut isp) = (client(), Isp::new(IspAuth::Pap));
    dial(&mut c, &mut isp, 0);
    let other = pppoe::discovery(AC, ME, pppoe::PADT, SESSION + 1, &[]);
    assert_eq!(c.handle(&Frame::parse(&other).unwrap(), 5), (vec![], None));
}

#[test]
fn unknown_protocols_get_a_protocol_reject() {
    let (mut c, mut isp) = (client(), Isp::new(IspAuth::Pap));
    dial(&mut c, &mut isp, 0);
    // IPv6CP Configure-Request (we don't do IPv6 yet).
    let v6cp = pppoe::session(
        AC,
        ME,
        SESSION,
        0x8057,
        &Control {
            code: 1,
            id: 1,
            data: vec![],
        }
        .encode(),
    );
    let (out, _) = c.handle(&Frame::parse(&v6cp).unwrap(), 1);
    exchange(&mut c, &mut isp, out, 1);
    assert_eq!(isp.proto_rejects, vec![0x8057]);
    assert_eq!(c.phase, Phase::Up, "and the link stays up");
}

#[test]
fn hang_up_terminates_and_sends_padt() {
    let (mut c, mut isp) = (client(), Isp::new(IspAuth::Pap));
    dial(&mut c, &mut isp, 0);
    let out = c.hang_up();
    let codes: Vec<_> = out
        .iter()
        .map(|f| Frame::parse(f).unwrap())
        .map(|f| (f.ethertype, f.code))
        .collect();
    assert_eq!(
        codes,
        vec![
            (pppoe::TYPE_SESSION, pppoe::CODE_SESSION),
            (pppoe::TYPE_DISCOVERY, pppoe::PADT)
        ]
    );
    assert!(c.link.is_none());
}
