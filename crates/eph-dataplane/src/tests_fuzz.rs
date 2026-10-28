//! Hostile packets: hundreds of thousands of malformed frames through a
//! router with every feature on (see [`crate::fuzzing`]). The pipeline must
//! never panic and never send outside its buffer.
//!
//! Starting from valid frames of every kind the router handles and
//! mutating them reaches far deeper than purely random bytes, which almost
//! never get past the first checks. Deterministic (fixed seeds), so a
//! failure reproduces; `EPH_FUZZ_ITERS` runs more.
//! `cargo fuzz` (in `fuzz/`) goes further, guided by coverage.

use crate::fuzzing::{self, templates};

/// xorshift64*: small, fast, reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// One mutated frame: a few bytes changed, maybe cut short or grown.
fn mutate(rng: &mut Rng, f: &[u8]) -> Vec<u8> {
    let mut f = f.to_vec();
    for _ in 0..1 + rng.below(6) {
        if f.is_empty() {
            break;
        }
        let i = rng.below(f.len());
        f[i] = match rng.below(4) {
            0 => rng.next() as u8,
            1 => f[i] ^ (1 << rng.below(8)),
            2 => [0, 0xff, 0x7f, 0x80][rng.below(4)],
            _ => f[i].wrapping_add(1),
        };
    }
    match rng.below(8) {
        0 => f.truncate(rng.below(f.len() + 1)),
        1 => f.extend((0..rng.below(64)).map(|_| rng.next() as u8)),
        _ => {}
    }
    f
}

fn input(card: u8, rng: &mut Rng, frame: &[u8]) -> Vec<u8> {
    let mode = if rng.below(16) == 0 { 1 } else { 0 } | if rng.below(8) == 0 { 2 } else { 0 };
    let off = [0u16, 4, 8, 12, 64, 256][rng.below(6)];
    let mut v = vec![
        mode,
        card,
        (off >> 8) as u8,
        off as u8,
        rng.below(256) as u8,
    ];
    v.extend_from_slice(frame);
    v
}

fn iterations() -> usize {
    std::env::var("EPH_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150_000)
}

#[test]
fn mutated_frames_never_break_the_pipeline() {
    let t = templates();
    let mut r = fuzzing::router();
    let mut rng = Rng(0x5eed_0001);
    for i in 0..iterations() {
        let (card, f) = &t[i % t.len()];
        let m = mutate(&mut rng, f);
        // Mostly the card it belongs on; sometimes the wrong one.
        let card = if rng.below(8) == 0 {
            rng.below(4) as u8
        } else {
            *card
        };
        fuzzing::run(&mut r, &input(card, &mut rng, &m));
    }
}

#[test]
fn random_bytes_never_break_the_pipeline() {
    let mut r = fuzzing::router();
    let mut rng = Rng(0x5eed_0002);
    for _ in 0..iterations() / 3 {
        let n = rng.below(1600);
        let f: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        fuzzing::run(&mut r, &f);
    }
}

#[test]
fn the_valid_frames_do_something() {
    // The templates are worth mutating only if they reach deep: most must
    // be forwarded, answered or handed on, not dropped at the door.
    let mut r = fuzzing::router();
    let mut deep = 0;
    for (card, f) in templates() {
        let mut frame = vec![0u8; fuzzing::FRAME];
        frame[256..256 + f.len()].copy_from_slice(&f);
        let v = r.process(card as u16, &mut frame, 256, f.len());
        if !matches!(
            v,
            crate::Verdict::Drop(
                crate::DropReason::Malformed
                    | crate::DropReason::NotForUs
                    | crate::DropReason::BadIpHeader
                    | crate::DropReason::UnsupportedEthertype
            )
        ) {
            deep += 1;
        }
    }
    assert!(
        deep >= templates().len() - 2,
        "only {deep} of {} got past parsing",
        templates().len()
    );
}

#[test]
fn fuzz_inputs_never_break_the_pipeline() {
    // The cargo-fuzz entry point, with random inputs: sequences of
    // template edits and raw frames on fresh routers.
    let mut rng = Rng(0x5eed_0003);
    for _ in 0..iterations() / 50 {
        let n = rng.below(512);
        let input: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        fuzzing::fuzz_input(&input);
    }
}

#[test]
fn the_session_key_templates_are_accepted() {
    // The tether packets from site 3 must authenticate, or mutating them
    // would only ever test the authentication check.
    let mut r = fuzzing::router();
    let mut seen = vec![];
    for (card, f) in templates() {
        if f.len() > 34 && f[26..30] == [192, 0, 2, 5] {
            let mut frame = vec![0u8; fuzzing::FRAME];
            frame[256..256 + f.len()].copy_from_slice(&f);
            seen.push(r.process(card as u16, &mut frame, 256, f.len()));
        }
    }
    assert!(
        matches!(seen[0], crate::Verdict::Tx { port: 0, .. }),
        "data: {:?}",
        seen[0]
    );
    assert!(
        matches!(seen[1], crate::Verdict::Tx { port: 2, .. }),
        "probe echoed: {:?}",
        seen[1]
    );
    assert_eq!(
        seen[2],
        crate::Verdict::Drop(crate::DropReason::OverlayHandshake)
    );
}
