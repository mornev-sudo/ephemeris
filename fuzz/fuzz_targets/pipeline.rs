//! Packets through a router with every feature on: the pipeline must never
//! panic or send outside its buffer (see eph_dataplane::fuzzing).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    eph_dataplane::fuzzing::fuzz_input(data);
});
