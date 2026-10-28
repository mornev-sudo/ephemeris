//! SD-WAN handshakes: session keys for sites configured with a public key.
//!
//! Each router has one X25519 key pair (its *identity*, kept in
//! `/var/lib/ephemeris/overlay-identity`); a `[[site]]` entry holds the other
//! router's public key, and optionally a pre-shared key both have. Two
//! routers agree fresh session keys with a Noise handshake,
//! `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, the pattern WireGuard uses:
//!
//! ```text
//!  initiator                                   responder
//!     │ ── initiation: ephemeral key, our identity (encrypted), our key id ─▶
//!     │ ◀─ response: ephemeral key, its key id ──────────────────────────────
//!  both: two keys (one per direction) from four Diffie-Hellman results and
//!        the pre-shared key; the ephemeral private keys are then forgotten
//! ```
//!
//! The keys go to the data plane ([`KeyTable`]), which seals every packet
//! with them. Every two minutes a new handshake replaces them, so a key
//! stolen later decrypts nothing recorded before (forward secrecy), and
//! keys never need changing by hand. Losing the pre-shared key alone gives
//! nothing away; losing a router's identity lets someone pose as it until
//! its public key is replaced on the other routers.
//!
//! Who starts: whichever side needs keys and knows where the other is. If
//! both start at once, the one with the higher site id answers the other's
//! initiation and drops its own. The responder may only send with new keys
//! once a packet sealed with them has arrived from the initiator, so a
//! replayed initiation can't make it switch to keys nobody else has.
//!
//! On the wire a handshake message is our 16-byte header (version 3, type
//! 4 or 5, the sender's site and tether), the Noise message, and `mac1`: a
//! keyed BLAKE2s over both, keyed with the *receiver's* public key. Anyone
//! can compute it who knows that public key, so it doesn't authenticate:
//! it lets a router throw away random junk before doing any key exchange.
//! The data plane also passes at most 20 handshake messages a second per
//! worker, and here each peer may start at most a few a second.
//!
//! Everything here is plain logic, without I/O or clocks: messages and the
//! time go in, messages to send and new key tables come out ([`Output`]).

use anyhow::{bail, Context, Result};
use blake2::digest::consts::U16;
use blake2::digest::{Digest, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac};
use eph_dataplane::overlay::{
    Cipher, KeyTable, Overlay, PeerCrypto, Session, TetherId, TetherKey, HDR_LEN, REKEY_AFTER_NS,
    TYPE_HANDSHAKE_INIT, TYPE_HANDSHAKE_RESPONSE, VERSION_HANDSHAKE,
};
use eph_dataplane::HandshakeIn;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

const PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// Mixed into every handshake, with both site ids: a handshake meant for
/// one pair of sites (or another protocol) never completes for another.
const PROLOGUE: &[u8] = b"ephemeris sd-wan handshake 1";
const MAC_LEN: usize = 16;
/// An unanswered initiation is sent again (a new one) after this long.
pub const RETRY_NS: u64 = 2_000_000_000;
/// The responder of the current keys starts a new handshake this much later
/// than the initiator would, so the two rarely start at once.
const RESPONDER_DELAY_NS: u64 = 15_000_000_000;
/// Nothing at all heard from a site for this long while sending to it: its
/// keys may be gone (it restarted), so shake hands again.
const SILENT_NS: u64 = 3_000_000_000;
/// Sessions kept per site: the current one, the one before (packets still
/// on their way), and a new one waiting for confirmation.
const KEEP: usize = 3;
/// Initiations answered per site per second, at most.
const INITS_PER_SEC: u32 = 5;

/// This router's SD-WAN key pair.
#[derive(Clone)]
pub struct Identity {
    private: [u8; 32],
    pub public: [u8; 32],
}

impl Identity {
    pub fn from_private(private: [u8; 32]) -> Self {
        let public = curve25519_dalek::MontgomeryPoint::mul_base_clamped(private).to_bytes();
        Identity { private, public }
    }

    pub fn generate() -> Result<Self> {
        let kp = snow::Builder::new(params())
            .generate_keypair()
            .context("generating the SD-WAN key pair")?;
        let private: [u8; 32] = kp.private.as_slice().try_into()?;
        Ok(Self::from_private(private))
    }

    /// The identity kept in `dir`, made on first use. Never printed or sent
    /// anywhere: only the public half leaves the router.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let p = dir.join("overlay-identity");
        match std::fs::read_to_string(&p) {
            Ok(s) => {
                let k =
                    parse_hex32(s.trim()).with_context(|| format!("{} is damaged", p.display()))?;
                Ok(Self::from_private(k))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = Self::generate()?;
                crate::files::write_private_atomic(
                    &p,
                    format!("{}\n", hex(&id.private)).as_bytes(),
                )?;
                Ok(id)
            }
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity(public {})", hex(&self.public))
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 64 hex characters -> 32 bytes.
pub fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("must be 64 hex characters");
    }
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(k)
}

fn params() -> snow::params::NoiseParams {
    PATTERN.parse().expect("a valid Noise pattern")
}

/// mac1 of a message for the router whose public key is `to`.
fn mac1(to: &[u8; 32], msg: &[u8]) -> [u8; MAC_LEN] {
    let mut h = Blake2s256::new();
    h.update(b"mac1----");
    h.update(to);
    let key = h.finalize();
    let mut m = <Blake2sMac<U16> as KeyInit>::new_from_slice(&key).expect("a 32-byte key");
    Mac::update(&mut m, msg);
    m.finalize().into_bytes().into()
}

fn mac1_ok(to: &[u8; 32], msg: &[u8], mac: &[u8]) -> bool {
    let mut h = Blake2s256::new();
    h.update(b"mac1----");
    h.update(to);
    let key = h.finalize();
    let mut m = <Blake2sMac<U16> as KeyInit>::new_from_slice(&key).expect("a 32-byte key");
    Mac::update(&mut m, msg);
    m.verify_slice(mac).is_ok()
}

fn prologue(initiator: u16, responder: u16) -> Vec<u8> {
    let mut p = PROLOGUE.to_vec();
    p.extend_from_slice(&initiator.to_be_bytes());
    p.extend_from_slice(&responder.to_be_bytes());
    p
}

/// Which cipher a router accepts for session keys (`[overlay] cipher`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CipherPref {
    /// AES-256-GCM when both routers have AES in hardware, else ChaCha20.
    #[default]
    Auto,
    /// Only this one: a router that can't use it gets no keys.
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

// In an initiation (after our key id): what we accept. In the response:
// the cipher chosen. The payloads travel inside the Noise messages, so
// they're encrypted and authenticated: nobody can downgrade the choice.
const OFFER_CHACHA: u8 = 1;
const OFFER_AES: u8 = 2;
/// "My AES is in hardware": AES only pays off when both ends have it.
const OFFER_AES_FAST: u8 = 4;
const CHOSE_CHACHA: u8 = 1;
const CHOSE_AES: u8 = 2;

fn offer(pref: CipherPref, aes_hw: bool) -> u8 {
    let fast = if aes_hw { OFFER_AES_FAST } else { 0 };
    match pref {
        CipherPref::Auto => OFFER_CHACHA | OFFER_AES | fast,
        CipherPref::Aes256Gcm => OFFER_AES | fast,
        CipherPref::ChaCha20Poly1305 => OFFER_CHACHA,
    }
}

/// The responder's choice for an initiator's `offer`, or `None`: nothing
/// both accept.
fn choose(offer: u8, pref: CipherPref, aes_hw: bool) -> Option<Cipher> {
    let (chacha, aes) = (offer & OFFER_CHACHA != 0, offer & OFFER_AES != 0);
    match pref {
        CipherPref::Aes256Gcm => aes.then_some(Cipher::Aes256Gcm),
        CipherPref::ChaCha20Poly1305 => chacha.then_some(Cipher::ChaCha20Poly1305),
        CipherPref::Auto if aes && aes_hw && offer & OFFER_AES_FAST != 0 => Some(Cipher::Aes256Gcm),
        CipherPref::Auto if chacha => Some(Cipher::ChaCha20Poly1305),
        CipherPref::Auto => aes.then_some(Cipher::Aes256Gcm),
    }
}

/// Seal full-size tether packets with each cipher for about a second each,
/// on one core, and print the rates (`ephemerisd --bench-crypto`).
pub fn bench_crypto() {
    use eph_dataplane::overlay::SessionKey;
    println!(
        "AES in hardware: {}",
        if Cipher::aes_in_hardware() {
            "yes"
        } else {
            "no (software AES is slow)"
        }
    );
    let mut hdr = [0u8; HDR_LEN];
    let mut buf = vec![0u8; eph_dataplane::overlay::DEFAULT_MTU as usize];
    for cipher in [Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
        let key = SessionKey::new(cipher, TetherKey([7; 32]));
        let (mut n, start) = (0u64, std::time::Instant::now());
        while start.elapsed() < std::time::Duration::from_secs(1) {
            for _ in 0..1000 {
                hdr[8..16].copy_from_slice(&n.to_be_bytes());
                std::hint::black_box(key.seal(&hdr, &mut buf));
                n += 1;
            }
        }
        let s = start.elapsed().as_secs_f64();
        println!(
            "{:<18} {:>6.0} ns per {}-byte packet, {:>6.2} Gbit/s per core",
            cipher.name(),
            s * 1e9 / n as f64,
            buf.len(),
            n as f64 * buf.len() as f64 * 8.0 / s / 1e9
        );
    }
}

/// What the I/O around this should do.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// Send a handshake message on a tether: to `to`, or else to its peer.
    Send {
        tether: TetherId,
        to: Option<(Ipv4Addr, u16)>,
        payload: Vec<u8>,
    },
}

/// A log line: (debug?, text). Routine rekeys are debug; the rest info.
pub type Event = (bool, String);

#[derive(Debug, Default)]
pub struct Output {
    pub actions: Vec<Action>,
    /// New session keys for the workers.
    pub keys: Option<Arc<KeyTable>>,
    pub events: Vec<Event>,
}

/// A handshake we started and are waiting on.
struct Pending {
    hs: snow::HandshakeState,
    local_id: u8,
    /// What we offered (the answer must be one of these).
    offered: u8,
}

struct Peer {
    site: u16,
    name: String,
    public: [u8; 32],
    psk: [u8; 32],
    /// Newest first.
    sessions: Vec<Arc<Session>>,
    pending: Option<Pending>,
    /// No new initiation before this (retry timer).
    next_try_ns: u64,
    /// Which candidate tether the next initiation goes on.
    turn: usize,
    next_id: u8,
    /// Initiations answered this second: (second, count).
    inits: (u64, u32),
    /// Handshakes completed, and when the last one did.
    handshakes: u64,
    last_handshake_ns: Option<u64>,
    /// Ever had keys? (The first ones are logged at info, rekeys at debug.)
    had_keys: bool,
}

impl Peer {
    /// What to seal with now: the newest confirmed session.
    fn sending(&self, now: u64) -> Option<&Arc<Session>> {
        self.sessions
            .iter()
            .find(|s| s.confirmed() && s.usable(now))
    }

    fn alloc_id(&mut self) -> u8 {
        loop {
            self.next_id = self.next_id.wrapping_add(1).max(1);
            let id = self.next_id;
            let used = self.sessions.iter().any(|s| s.local_id == id)
                || self.pending.as_ref().is_some_and(|p| p.local_id == id);
            if !used {
                return id;
            }
        }
    }

    /// Does this site need a new handshake now?
    fn needs_handshake(&self, now: u64) -> bool {
        let Some(s) = self.sending(now) else {
            // A new session we answered, waiting for the initiator's first
            // packet: give it a moment before starting one ourselves.
            return !self.sessions.first().is_some_and(|n| {
                !n.confirmed() && now.saturating_sub(n.created_ns) < 2 * RETRY_NS
            });
        };
        let age = now.saturating_sub(s.created_ns);
        let due = REKEY_AFTER_NS + if s.initiator { 0 } else { RESPONDER_DELAY_NS };
        let heard = self
            .sessions
            .iter()
            .map(|s| s.last_rx_ns())
            .max()
            .unwrap_or(0)
            .max(s.created_ns);
        age >= due || now.saturating_sub(heard) > SILENT_NS
    }

    /// Put a new session first, keep a few, drop expired ones.
    fn install(&mut self, s: Session, now: u64) {
        self.sessions.insert(0, Arc::new(s));
        self.sessions.retain(|s| s.usable(now));
        self.sessions.truncate(KEEP);
    }
}

/// What the API reads: this router's public key, and how each site's
/// handshakes are going (refreshed by the handshake thread).
#[derive(Default)]
pub struct SdwanState {
    /// `None`: the identity couldn't be loaded (see the log).
    pub public_key: Option<[u8; 32]>,
    pub peers: std::sync::Mutex<Vec<PeerStatus>>,
}

/// What the API shows per site.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerStatus {
    pub site: u16,
    pub name: String,
    pub public_key: String,
    /// Keys to send with right now.
    pub established: bool,
    /// Their cipher.
    pub cipher: Option<&'static str>,
    /// Age of those keys, seconds.
    pub key_age_s: Option<u64>,
    pub handshakes: u64,
    /// Seconds since the last handshake completed.
    pub last_handshake_s: Option<u64>,
    /// Waiting for an answer to our initiation.
    pub pending: bool,
}

/// The handshakes of every site that uses them.
pub struct Handshakes {
    me: Identity,
    site_id: u16,
    overlay: Arc<Overlay>,
    /// Per site_idx (None: that site uses its pre-shared key).
    peers: Vec<Option<Peer>>,
    serial: u64,
    pref: CipherPref,
    aes_hw: bool,
}

impl Handshakes {
    /// `names`: site id -> name, for log lines.
    pub fn new(me: Identity, overlay: Arc<Overlay>, names: &[(u16, String)]) -> Self {
        let peers = overlay
            .sites
            .iter()
            .enumerate()
            .map(|(idx, &site)| match overlay.crypto(idx) {
                PeerCrypto::PreShared => None,
                PeerCrypto::Handshake { public } => Some(Peer {
                    site,
                    name: names
                        .iter()
                        .find(|(id, _)| *id == site)
                        .map_or_else(|| format!("site {site}"), |(_, n)| n.clone()),
                    public,
                    psk: overlay
                        .tethers
                        .iter()
                        .find(|t| t.site_idx == idx)
                        .and_then(|t| t.key)
                        .map_or([0; 32], |k| k.0),
                    sessions: vec![],
                    pending: None,
                    next_try_ns: 0,
                    turn: 0,
                    next_id: 0,
                    inits: (0, 0),
                    handshakes: 0,
                    last_handshake_ns: None,
                    had_keys: false,
                }),
            })
            .collect();
        Handshakes {
            me,
            site_id: overlay.site_id,
            overlay,
            peers,
            serial: 0,
            pref: CipherPref::Auto,
            aes_hw: Cipher::aes_in_hardware(),
        }
    }

    /// Which ciphers to accept, and whether this CPU has AES in hardware.
    pub fn with_ciphers(mut self, pref: CipherPref, aes_hw: bool) -> Self {
        self.pref = pref;
        self.aes_hw = aes_hw;
        self
    }

    /// Any site using handshakes?
    pub fn active(&self) -> bool {
        self.peers.iter().any(Option::is_some)
    }

    fn key_table(&self) -> Arc<KeyTable> {
        Arc::new(KeyTable {
            peers: self
                .peers
                .iter()
                .map(|p| p.as_ref().map_or_else(Vec::new, |p| p.sessions.clone()))
                .collect(),
        })
    }

    /// A handshake message for a site: our header, the Noise message, mac1.
    fn message(&self, typ: u8, tether: TetherId, noise: &[u8], to: &[u8; 32]) -> Vec<u8> {
        let mut m = vec![0u8; HDR_LEN];
        m[0] = (VERSION_HANDSHAKE << 4) | typ;
        m[2..4].copy_from_slice(&self.site_id.to_be_bytes());
        m[4..6].copy_from_slice(&tether.to_be_bytes());
        m.extend_from_slice(noise);
        let mac = mac1(to, &m);
        m.extend_from_slice(&mac);
        m
    }

    /// Every ~100 ms: start handshakes that are due, retire old keys.
    /// `candidates(site_idx)`: the tethers an initiation to that site could
    /// go on now, best first (empty: we don't know where it is).
    pub fn tick(&mut self, now: u64, candidates: &dyn Fn(usize) -> Vec<TetherId>) -> Output {
        let mut out = Output::default();
        let mut changed = false;
        for idx in 0..self.peers.len() {
            let Some(p) = self.peers[idx].as_mut() else {
                continue;
            };
            let before = p.sessions.len();
            p.sessions.retain(|s| s.usable(now));
            changed |= p.sessions.len() != before;
            if now < p.next_try_ns || !p.needs_handshake(now) {
                continue;
            }
            let tethers = candidates(idx);
            if tethers.is_empty() {
                continue; // it will get in touch with us
            }
            let tether = tethers[p.turn % tethers.len()];
            p.turn = p.turn.wrapping_add(1);
            p.next_try_ns = now + RETRY_NS;
            let local_id = p.alloc_id();
            let (public, psk, site, name) = (p.public, p.psk, p.site, p.name.clone());
            let pro = prologue(self.site_id, site);
            let built = snow::Builder::new(params())
                .local_private_key(&self.me.private)
                .and_then(|b| b.remote_public_key(&public))
                .and_then(|b| b.psk(2, &psk))
                .and_then(|b| b.prologue(&pro))
                .and_then(|b| b.build_initiator());
            let mut hs = match built {
                Ok(hs) => hs,
                Err(e) => {
                    out.events.push((
                        false,
                        format!("SD-WAN {name}: can't start a handshake: {e}"),
                    ));
                    continue;
                }
            };
            let mut buf = [0u8; 256];
            let offered = offer(self.pref, self.aes_hw);
            let n = match hs.write_message(&[local_id, offered], &mut buf) {
                Ok(n) => n,
                Err(e) => {
                    out.events.push((
                        false,
                        format!("SD-WAN {name}: can't start a handshake: {e}"),
                    ));
                    continue;
                }
            };
            let payload = self.message(TYPE_HANDSHAKE_INIT, tether, &buf[..n], &public);
            let p = self.peers[idx].as_mut().unwrap();
            p.pending = Some(Pending {
                hs,
                local_id,
                offered,
            });
            out.events.push((
                p.had_keys,
                format!(
                    "SD-WAN {name}: starting a handshake on tether {}",
                    self.overlay
                        .tethers
                        .get(tether as usize)
                        .map_or("?", |t| t.name.as_str())
                ),
            ));
            out.actions.push(Action::Send {
                tether,
                to: None,
                payload,
            });
        }
        if changed {
            out.keys = Some(self.key_table());
        }
        out
    }

    /// A handshake message the data plane handed over.
    pub fn receive(&mut self, msg: &HandshakeIn, now: u64) -> Output {
        let mut out = Output::default();
        let Some(t) = self.overlay.tethers.get(msg.tether as usize) else {
            return out;
        };
        // A peer's address is never learned from a handshake message: a
        // captured initiation, replayed from elsewhere, still verifies. The
        // data plane follows the peer on its first sealed packet instead;
        // only the answer goes back to where the initiation came from.
        let idx = t.site_idx;
        let m = &msg.payload;
        if m.len() < HDR_LEN + MAC_LEN {
            return out;
        }
        let (body, mac) = m.split_at(m.len() - MAC_LEN);
        if !mac1_ok(&self.me.public, body, mac) {
            return out; // junk (or meant for another key): no work spent on it
        }
        let typ = m[0] & 0x0f;
        let noise = &body[HDR_LEN..];
        let site_id = self.site_id;
        let Some(p) = self.peers.get_mut(idx).and_then(Option::as_mut) else {
            return out;
        };
        let name = p.name.clone();
        match typ {
            TYPE_HANDSHAKE_INIT => {
                let sec = now / 1_000_000_000;
                if p.inits.0 != sec {
                    p.inits = (sec, 0);
                }
                if p.inits.1 >= INITS_PER_SEC {
                    return out;
                }
                p.inits.1 += 1;
                // Both started at once: the lower site id's handshake wins.
                if p.pending.is_some() && site_id < p.site {
                    return out;
                }
                let pro = prologue(p.site, site_id);
                let built = snow::Builder::new(params())
                    .local_private_key(&self.me.private)
                    .and_then(|b| b.psk(2, &p.psk))
                    .and_then(|b| b.prologue(&pro))
                    .and_then(|b| b.build_responder());
                let Ok(mut hs) = built else { return out };
                let mut pl = [0u8; 64];
                let Ok(n) = hs.read_message(noise, &mut pl) else {
                    out.events.push((
                        true,
                        format!("SD-WAN {name}: refused a handshake that didn't verify"),
                    ));
                    return out;
                };
                if hs.get_remote_static() != Some(&p.public[..]) || n < 1 {
                    out.events.push((
                        false,
                        format!("SD-WAN {name}: refused a handshake from another key"),
                    ));
                    return out;
                }
                let peer_id = pl[0];
                // An initiation without an offer (from before ciphers were
                // chosen) means ChaCha20.
                let their_offer = if n >= 2 { pl[1] } else { OFFER_CHACHA };
                let Some(cipher) = choose(their_offer, self.pref, self.aes_hw) else {
                    out.events.push((
                        false,
                        format!(
                            "SD-WAN {name}: refused a handshake: no cipher both accept (ours: {:?})",
                            self.pref
                        ),
                    ));
                    return out;
                };
                let chose = match cipher {
                    Cipher::Aes256Gcm => CHOSE_AES,
                    Cipher::ChaCha20Poly1305 => CHOSE_CHACHA,
                };
                p.pending = None;
                let local_id = p.alloc_id();
                let mut buf = [0u8; 256];
                let Ok(n) = hs.write_message(&[local_id, chose], &mut buf) else {
                    return out;
                };
                let (to_us, to_them) = hs.dangerously_get_raw_split();
                self.serial += 1;
                let s = Session::new(
                    self.serial,
                    local_id,
                    peer_id,
                    cipher,
                    TetherKey(to_them),
                    TetherKey(to_us),
                    now,
                    false,
                );
                let public = p.public;
                p.install(s, now);
                let payload = self.message(TYPE_HANDSHAKE_RESPONSE, msg.tether, &buf[..n], &public);
                out.actions.push(Action::Send {
                    tether: msg.tether,
                    to: Some((msg.src, msg.sport)),
                    payload,
                });
                self.completed(idx, now, false, &mut out);
            }
            TYPE_HANDSHAKE_RESPONSE => {
                let Some(mut pending) = p.pending.take() else {
                    return out;
                };
                let mut pl = [0u8; 64];
                let n = match pending.hs.read_message(noise, &mut pl) {
                    Ok(n) if n >= 1 => n,
                    _ => {
                        out.events.push((
                            true,
                            format!("SD-WAN {name}: ignored a response that didn't verify"),
                        ));
                        return out; // it times out and is tried again
                    }
                };
                // The cipher chosen, which must be one we offered.
                let cipher = match if n >= 2 { pl[1] } else { CHOSE_CHACHA } {
                    CHOSE_AES if pending.offered & OFFER_AES != 0 => Cipher::Aes256Gcm,
                    CHOSE_CHACHA if pending.offered & OFFER_CHACHA != 0 => Cipher::ChaCha20Poly1305,
                    _ => {
                        out.events.push((
                            false,
                            format!("SD-WAN {name}: ignored a response choosing a cipher we didn't offer"),
                        ));
                        return out;
                    }
                };
                let (to_them, to_us) = pending.hs.dangerously_get_raw_split();
                self.serial += 1;
                let s = Session::new(
                    self.serial,
                    pending.local_id,
                    pl[0],
                    cipher,
                    TetherKey(to_them),
                    TetherKey(to_us),
                    now,
                    true,
                );
                p.install(s, now);
                p.next_try_ns = 0;
                self.completed(idx, now, true, &mut out);
            }
            _ => {}
        }
        out
    }

    fn completed(&mut self, idx: usize, now: u64, initiator: bool, out: &mut Output) {
        let p = self.peers[idx].as_mut().unwrap();
        p.handshakes += 1;
        p.last_handshake_ns = Some(now);
        out.events.push((
            p.had_keys,
            format!(
                "SD-WAN {}: new session keys ({})",
                p.name,
                if initiator {
                    "we started"
                } else {
                    "it started"
                }
            ),
        ));
        p.had_keys = true;
        out.keys = Some(self.key_table());
    }

    pub fn status(&self, now: u64) -> Vec<PeerStatus> {
        self.peers
            .iter()
            .flatten()
            .map(|p| {
                let s = p.sending(now);
                PeerStatus {
                    site: p.site,
                    name: p.name.clone(),
                    public_key: hex(&p.public),
                    established: s.is_some(),
                    cipher: s.map(|s| s.tx.cipher().name()),
                    key_age_s: s.map(|s| now.saturating_sub(s.created_ns) / 1_000_000_000),
                    handshakes: p.handshakes,
                    last_handshake_s: p
                        .last_handshake_ns
                        .map(|t| now.saturating_sub(t) / 1_000_000_000),
                    pending: p.pending.is_some(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eph_dataplane::overlay::{Tether, REJECT_AFTER_NS};

    const S: u64 = 1_000_000_000;

    /// Site `id`'s view: one tether to the other site, which uses `peer`'s
    /// public key; `dynamic`: it doesn't know the other's address.
    fn overlay(id: u16, peer: &Identity, psk: Option<[u8; 32]>, dynamic: bool) -> Arc<Overlay> {
        let other = 3 - id;
        let mut o = Overlay::disabled();
        o.site_id = id;
        o.sites = vec![other];
        o.peers = vec![PeerCrypto::Handshake {
            public: peer.public,
        }];
        o.tethers = vec![Tether {
            id: 0,
            name: "fibre".into(),
            port: 1,
            remote: if dynamic {
                Ipv4Addr::UNSPECIFIED
            } else {
                format!("192.0.2.{other}").parse().unwrap()
            },
            gateway: None,
            peer_site: other,
            site_idx: 0,
            key: psk.map(TetherKey),
        }];
        Arc::new(o)
    }

    struct Pair {
        a: Handshakes,
        b: Handshakes,
    }

    fn pair(psk_a: Option<[u8; 32]>, psk_b: Option<[u8; 32]>) -> Pair {
        let (ia, ib) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        Pair {
            a: Handshakes::new(
                ia.clone(),
                overlay(1, &ib, psk_a, false),
                &[(2, "b".into())],
            ),
            b: Handshakes::new(ib, overlay(2, &ia, psk_b, false), &[(1, "a".into())]),
        }
    }

    /// A message to send: (tether, to, payload).
    type Sent = (TetherId, Option<(Ipv4Addr, u16)>, Vec<u8>);

    fn sends(o: &Output) -> Vec<Sent> {
        o.actions
            .iter()
            .map(|a| match a {
                Action::Send {
                    tether,
                    to,
                    payload,
                } => (*tether, *to, payload.clone()),
            })
            .collect()
    }

    /// `payload` arriving at a router from the other's address.
    fn arrive(from: u8, payload: &[u8]) -> HandshakeIn {
        HandshakeIn {
            tether: 0,
            src: format!("192.0.2.{from}").parse().unwrap(),
            sport: 4800,
            payload: payload.to_vec(),
        }
    }

    fn all(_: usize) -> Vec<TetherId> {
        vec![0]
    }

    fn sessions(h: &Handshakes) -> Vec<Arc<Session>> {
        h.key_table().peers[0].clone()
    }

    /// A starts; B answers; both get keys that match.
    fn shake(p: &mut Pair, now: u64) {
        let init = sends(&p.a.tick(now, &all));
        assert_eq!(init.len(), 1, "A starts");
        let out = p.b.receive(&arrive(1, &init[0].2), now);
        let resp = sends(&out);
        assert_eq!(resp.len(), 1, "B answers");
        assert_eq!(
            resp[0].1,
            Some(("192.0.2.1".parse().unwrap(), 4800)),
            "to where it came from"
        );
        assert!(out.keys.is_some());
        let out = p.a.receive(&arrive(2, &resp[0].2), now);
        assert!(out.keys.is_some());
    }

    #[test]
    fn two_routers_agree_keys() {
        let mut p = pair(None, None);
        shake(&mut p, S);
        let (a, b) = (sessions(&p.a), sessions(&p.b));
        assert_eq!((a.len(), b.len()), (1, 1));
        let (a, b) = (&a[0], &b[0]);
        assert_eq!(a.tx, b.rx);
        assert_eq!(a.rx, b.tx);
        assert_ne!(a.tx, a.rx, "a key per direction");
        assert_eq!((a.peer_id, b.peer_id), (b.local_id, a.local_id));
        assert!(
            a.confirmed() && !b.confirmed(),
            "B waits for A's first packet"
        );
        assert!(p.a.status(S)[0].established);
        assert!(!p.b.status(S)[0].established);
    }

    #[test]
    fn the_cipher_is_chosen_in_the_handshake() {
        use CipherPref::*;
        let agreed = |a: (CipherPref, bool), b: (CipherPref, bool)| {
            let mut p = pair(None, None);
            p.a = std::mem::replace(&mut p.a, pair(None, None).a).with_ciphers(a.0, a.1);
            p.b = std::mem::replace(&mut p.b, pair(None, None).b).with_ciphers(b.0, b.1);
            let init = sends(&p.a.tick(S, &all));
            let resp = sends(&p.b.receive(&arrive(1, &init[0].2), S));
            if resp.is_empty() {
                return None;
            }
            p.a.receive(&arrive(2, &resp[0].2), S);
            let (a, b) = (sessions(&p.a), sessions(&p.b));
            assert_eq!(a[0].tx, b[0].rx, "both use the same");
            Some(a[0].tx.cipher())
        };
        let (aes, chacha) = (Some(Cipher::Aes256Gcm), Some(Cipher::ChaCha20Poly1305));
        // AES when both do it in hardware; otherwise ChaCha20.
        assert_eq!(agreed((Auto, true), (Auto, true)), aes);
        assert_eq!(agreed((Auto, true), (Auto, false)), chacha);
        assert_eq!(agreed((Auto, false), (Auto, true)), chacha);
        // Forcing one: the other router goes along if it can...
        assert_eq!(agreed((Aes256Gcm, false), (Auto, false)), aes);
        assert_eq!(agreed((Auto, true), (ChaCha20Poly1305, true)), chacha);
        // ...and if both force different ones, there are no keys.
        assert_eq!(agreed((Aes256Gcm, true), (ChaCha20Poly1305, true)), None);
        assert_eq!(agreed((ChaCha20Poly1305, true), (Aes256Gcm, true)), None);
    }

    #[test]
    fn each_handshake_gives_new_keys() {
        let mut p = pair(None, None);
        shake(&mut p, S);
        let first = sessions(&p.a)[0].clone();
        // Nothing due yet.
        assert!(sends(&p.a.tick(2 * S, &all)).is_empty());
        // ...but after two minutes A (which started the first) starts again.
        sessions(&p.b)[0].accept(0, 0, 2 * S); // A's packets arrived
        sessions(&p.a)[0].accept(0, 0, 2 * S);
        let later = S + REKEY_AFTER_NS;
        for s in sessions(&p.a).iter().chain(sessions(&p.b).iter()) {
            s.accept(0, 1, later); // and keep arriving
        }
        assert!(
            sends(&p.b.tick(later, &all)).is_empty(),
            "B, the responder, waits longer"
        );
        shake(&mut p, later);
        let a = sessions(&p.a);
        assert_eq!(
            a.len(),
            2,
            "the old keys stay for packets still on their way"
        );
        assert_ne!(a[0].tx, first.tx);
        assert_eq!(a[1].tx, first.tx);
        // Expired keys are dropped.
        let out = p.a.tick(S + REJECT_AFTER_NS, &all);
        assert!(out.keys.is_some());
        assert_eq!(sessions(&p.a).len(), 1);
    }

    #[test]
    fn the_preshared_key_must_match() {
        let mut p = pair(Some([1; 32]), Some([2; 32]));
        let init = sends(&p.a.tick(S, &all));
        // The pre-shared key only counts from the response on (psk2): B
        // can't tell yet, and answers...
        let resp = sends(&p.b.receive(&arrive(1, &init[0].2), S));
        // ...but A can't read the answer, so it never gets keys, and B's
        // are never confirmed (nothing sealed with them ever arrives).
        let out = p.a.receive(&arrive(2, &resp[0].2), S);
        assert!(out.keys.is_none());
        assert!(sessions(&p.a).is_empty());
        assert!(!p.b.status(S)[0].established);
        let mut p = pair(Some([1; 32]), Some([1; 32]));
        shake(&mut p, S);
    }

    #[test]
    fn a_router_with_another_key_is_refused() {
        let mut p = pair(None, None);
        // C has B's public key but not A's private key: it can't pose as A.
        let ic = Identity::generate().unwrap();
        let ib_public = match p.a.overlay.crypto(0) {
            PeerCrypto::Handshake { public } => public,
            _ => unreachable!(),
        };
        let fake_b = Identity {
            private: [0; 32],
            public: ib_public,
        };
        let mut c = Handshakes::new(ic, overlay(1, &fake_b, None, false), &[]);
        let init = sends(&c.tick(S, &all));
        let out = p.b.receive(&arrive(1, &init[0].2), S);
        assert!(sends(&out).is_empty() && out.keys.is_none());
        assert!(out.events.iter().any(|(_, e)| e.contains("another key")));
    }

    #[test]
    fn junk_and_tampering_cost_nothing() {
        let mut p = pair(None, None);
        let init = sends(&p.a.tick(S, &all));
        // Random bytes: mac1 fails, so no key exchange is even tried.
        let out = p.b.receive(&arrive(1, &[0x34; 129]), S);
        assert!(sends(&out).is_empty() && out.events.is_empty());
        // Any changed byte breaks mac1 too.
        for at in [0, 3, 20, 100, 128] {
            let mut m = init[0].2.clone();
            m[at] ^= 1;
            assert!(
                sends(&p.b.receive(&arrive(1, &m), S)).is_empty(),
                "byte {at}"
            );
        }
        // A response without an initiation of ours is ignored.
        let out = p.b.receive(&arrive(1, &init[0].2), S);
        let resp = sends(&out);
        let mut fresh = pair(None, None);
        assert!(fresh.a.receive(&arrive(2, &resp[0].2), S).keys.is_none());
    }

    #[test]
    fn initiations_are_rate_limited() {
        let mut p = pair(None, None);
        let init = sends(&p.a.tick(S, &all));
        let answered = (0..20)
            .filter(|_| !sends(&p.b.receive(&arrive(1, &init[0].2), S)).is_empty())
            .count();
        assert_eq!(answered, INITS_PER_SEC as usize);
        assert!(sessions(&p.b).len() <= KEEP);
    }

    #[test]
    fn a_replayed_initiation_does_not_take_over() {
        let mut p = pair(None, None);
        let init = sends(&p.a.tick(S, &all));
        let resp = sends(&p.b.receive(&arrive(1, &init[0].2), S));
        p.a.receive(&arrive(2, &resp[0].2), S);
        let current = sessions(&p.b)[0].clone();
        current.accept(0, 0, S); // A's first packet: confirmed
                                 // Someone replays A's initiation a second later. B answers it (it
                                 // can't tell), but nobody else has those keys, so B keeps sending
                                 // with the confirmed ones.
        p.b.receive(&arrive(1, &init[0].2), 2 * S);
        let b = sessions(&p.b);
        assert_eq!(b.len(), 2);
        assert!(!b[0].confirmed());
        assert_eq!(
            p.b.peers[0]
                .as_ref()
                .unwrap()
                .sending(2 * S)
                .unwrap()
                .serial,
            current.serial
        );
    }

    #[test]
    fn simultaneous_starts_settle_on_one() {
        let mut p = pair(None, None);
        // Both start (say both just restarted).
        let from_a = sends(&p.a.tick(S, &all));
        let from_b = sends(&p.b.tick(S, &all));
        // A (site 1, lower) ignores B's; B drops its own and answers A's.
        assert!(sends(&p.a.receive(&arrive(2, &from_b[0].2), S)).is_empty());
        let resp = sends(&p.b.receive(&arrive(1, &from_a[0].2), S));
        assert_eq!(resp.len(), 1);
        assert!(p.a.receive(&arrive(2, &resp[0].2), S).keys.is_some());
        assert_eq!(sessions(&p.a)[0].tx, sessions(&p.b)[0].rx);
        assert!(!p.b.peers[0].as_ref().unwrap().pending.is_some());
    }

    #[test]
    fn a_silent_peer_gets_a_new_handshake() {
        let mut p = pair(None, None);
        shake(&mut p, S);
        sessions(&p.a)[0].accept(0, 0, S);
        // B restarted: nothing comes back for a few seconds.
        assert!(sends(&p.a.tick(3 * S, &all)).is_empty());
        assert_eq!(
            sends(&p.a.tick(5 * S, &all)).len(),
            1,
            "A shakes hands again"
        );
    }

    #[test]
    fn unanswered_initiations_are_retried_on_the_next_tether() {
        let mut p = pair(None, None);
        let two = |_: usize| vec![0, 1];
        let first = sends(&p.a.tick(S, &two));
        assert_eq!(first[0].0, 0);
        assert!(
            sends(&p.a.tick(S + RETRY_NS / 2, &two)).is_empty(),
            "not yet"
        );
        let again = sends(&p.a.tick(S + RETRY_NS, &two));
        assert_eq!(again[0].0, 1, "the other WAN");
        assert_ne!(
            again[0].2, first[0].2,
            "a new initiation, new ephemeral key"
        );
        // Nowhere to send (a peer without a fixed address): wait for it.
        let mut q = pair(None, None);
        assert!(sends(&q.a.tick(S, &|_| vec![])).is_empty());
    }

    #[test]
    fn the_answer_goes_where_the_initiation_came_from() {
        let (ia, ib) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let mut a = Handshakes::new(ia.clone(), overlay(1, &ib, None, false), &[]);
        let mut hub = Handshakes::new(ib, overlay(2, &ia, None, true), &[]);
        let init = sends(&a.tick(S, &all));
        let msg = HandshakeIn {
            tether: 0,
            src: "203.0.113.7".parse().unwrap(),
            sport: 61000,
            payload: init[0].2.clone(),
        };
        let out = hub.receive(&msg, S);
        // Only the answer: where the peer is gets learned from its sealed
        // packets (a replayed initiation must not move it).
        assert_eq!(out.actions.len(), 1);
        assert_eq!(
            sends(&out)[0].1,
            Some(("203.0.113.7".parse().unwrap(), 61000))
        );
    }

    #[test]
    fn the_identity_is_kept() {
        let d = std::env::temp_dir().join(format!("eph-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let a = Identity::load_or_create(&d).unwrap();
        let b = Identity::load_or_create(&d).unwrap();
        assert_eq!(a.public, b.public);
        assert!(
            !format!("{a:?}").contains(&hex(&a.private)),
            "the private key never prints"
        );
        std::fs::write(d.join("overlay-identity"), "nonsense").unwrap();
        assert!(
            Identity::load_or_create(&d).is_err(),
            "never replaced silently"
        );
    }
}
