//! Single-producer / single-consumer rings shared with the kernel.
//!
//! Each ring is an array of `size` slots (a power of two) plus two counters,
//! `producer` and `consumer`, that only ever increase (wrapping at 2^32).
//! Slot `i` lives at `descs[i & mask]`. The producer writes slots and then
//! publishes them by advancing `producer`; the consumer reads slots and then
//! hands them back by advancing `consumer`.
//!
//! The only synchronisation is memory ordering on those two counters:
//! *store-release* when publishing, *load-acquire* when reading the other
//! side's counter. That guarantees slot contents are visible before the
//! counter that covers them. No locks, no syscalls.
//!
//! We also keep local `cached_*` copies of both counters so that, most of the
//! time, we don't even touch the shared cache line the kernel is writing.

use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

pub struct Ring<T: Copy> {
    producer: NonNull<AtomicU32>,
    consumer: NonNull<AtomicU32>,
    flags: NonNull<AtomicU32>,
    descs: NonNull<T>,
    mask: u32,
    size: u32,
    cached_prod: u32,
    cached_cons: u32,
    map: (*mut libc::c_void, usize),
}

// SAFETY: the pointers only refer to this ring's own mapping, which the
// Ring owns. User space has one side of each ring (producer or consumer), and
// only one thread at a time may use it: Ring is Send (moved to its worker)
// but not Sync (raw pointers keep it !Sync), so two threads can't share one.
unsafe impl<T: Copy> Send for Ring<T> {}

impl<T: Copy> Ring<T> {
    /// Wrap a ring the kernel mapped for us. Panics if the kernel's layout
    /// doesn't fit the mapping (checked once, here, so the per-packet paths
    /// don't have to).
    ///
    /// # Safety
    /// `map` must be a live `MAP_SHARED` mapping of `map_len` bytes of an
    /// AF_XDP ring, laid out as `off` says, holding `size` entries of `T`;
    /// the Ring takes ownership of it (unmaps it on drop).
    pub(crate) unsafe fn new(
        map: *mut libc::c_void,
        map_len: usize,
        off: &crate::sys::XdpRingOffset,
        size: u32,
    ) -> Self {
        // The masks below assume a power of two; the kernel refuses other
        // sizes, but make the assumption explicit.
        assert!(
            size.is_power_of_two(),
            "ring size {size} isn't a power of two"
        );
        let fits = |at: u64, len: usize, align: usize| {
            (at as usize)
                .checked_add(len)
                .is_some_and(|end| end <= map_len)
                && (map as usize + at as usize).is_multiple_of(align)
        };
        let counter = (
            std::mem::size_of::<AtomicU32>(),
            std::mem::align_of::<AtomicU32>(),
        );
        assert!(
            fits(off.producer, counter.0, counter.1)
                && fits(off.consumer, counter.0, counter.1)
                && fits(off.flags, counter.0, counter.1)
                && fits(
                    off.desc,
                    size as usize * std::mem::size_of::<T>(),
                    std::mem::align_of::<T>()
                ),
            "AF_XDP ring layout from the kernel doesn't fit its mapping"
        );
        let base = map as *mut u8;
        // SAFETY: every offset was checked to lie inside the mapping, aligned
        // for its type, so these pointers are in bounds and non-null.
        let (producer, consumer, flags, descs) = unsafe {
            (
                NonNull::new_unchecked(base.add(off.producer as usize) as *mut AtomicU32),
                NonNull::new_unchecked(base.add(off.consumer as usize) as *mut AtomicU32),
                NonNull::new_unchecked(base.add(off.flags as usize) as *mut AtomicU32),
                NonNull::new_unchecked(base.add(off.desc as usize) as *mut T),
            )
        };
        // SAFETY: in-bounds, aligned counters in a mapping that outlives the
        // Ring; the kernel only ever accesses them atomically too.
        let cached_prod = unsafe { producer.as_ref() }.load(Ordering::Acquire);
        // SAFETY: as above.
        let cached_cons = unsafe { consumer.as_ref() }.load(Ordering::Acquire);
        Ring {
            producer,
            consumer,
            flags,
            descs,
            mask: size - 1,
            size,
            cached_prod,
            cached_cons,
            map: (map, map_len),
        }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// Does the kernel want a syscall to wake it up? (`XDP_USE_NEED_WAKEUP`)
    #[inline]
    pub fn needs_wakeup(&self) -> bool {
        // SAFETY: the counters were checked in `new` to be in bounds and
        // aligned, the mapping lives as long as `self`, and the kernel
        // accesses them atomically as well. (The same holds for every counter
        // access below, which refer back here.)
        unsafe { self.flags.as_ref() }.load(Ordering::Relaxed) & crate::sys::XDP_RING_NEED_WAKEUP
            != 0
    }

    // ---- producer side (fill, tx)

    /// Free slots we can write right now.
    #[inline]
    pub fn free(&mut self) -> u32 {
        let free = self.size - self.cached_prod.wrapping_sub(self.cached_cons);
        if free > 0 {
            return free;
        }
        // SAFETY: see `needs_wakeup`.
        self.cached_cons = unsafe { self.consumer.as_ref() }.load(Ordering::Acquire);
        self.size - self.cached_prod.wrapping_sub(self.cached_cons)
    }

    /// Write one entry (not yet visible to the kernel; see [`Ring::commit`]).
    #[inline]
    pub fn push(&mut self, v: T) -> bool {
        if self.free() == 0 {
            return false;
        }
        // SAFETY: the index is masked into the `size` slots checked in `new`;
        // `free() > 0` means the kernel has consumed this slot (consumer is
        // past it) and won't read it until `commit` publishes it again.
        unsafe {
            self.descs
                .as_ptr()
                .add((self.cached_prod & self.mask) as usize)
                .write(v)
        };
        self.cached_prod = self.cached_prod.wrapping_add(1);
        true
    }

    /// Publish everything pushed so far.
    #[inline]
    pub fn commit(&mut self) {
        // SAFETY: see `needs_wakeup`. Release: the slots written by `push`
        // are visible to the kernel before the counter that covers them.
        unsafe { self.producer.as_ref() }.store(self.cached_prod, Ordering::Release);
    }

    /// Entries pushed but not yet consumed by the kernel.
    #[inline]
    pub fn outstanding(&self) -> u32 {
        // SAFETY: see `needs_wakeup`.
        let cons = unsafe { self.consumer.as_ref() }.load(Ordering::Acquire);
        self.cached_prod.wrapping_sub(cons)
    }

    // ---- consumer side (rx, completion)

    /// Entries available to read right now.
    #[inline]
    pub fn available(&mut self) -> u32 {
        let n = self.cached_prod.wrapping_sub(self.cached_cons);
        if n > 0 {
            return n;
        }
        // SAFETY: see `needs_wakeup`. Acquire: pairs with the kernel's
        // release, so the slots it covers are visible before we read them.
        self.cached_prod = unsafe { self.producer.as_ref() }.load(Ordering::Acquire);
        self.cached_prod.wrapping_sub(self.cached_cons)
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.available() == 0 {
            return None;
        }
        // SAFETY: the index is masked into the `size` slots checked in `new`;
        // `available() > 0` means the kernel published this slot (acquire
        // load of its producer counter) and won't reuse it until `release`.
        let v = unsafe {
            self.descs
                .as_ptr()
                .add((self.cached_cons & self.mask) as usize)
                .read()
        };
        self.cached_cons = self.cached_cons.wrapping_add(1);
        Some(v)
    }

    /// Hand consumed slots back to the kernel.
    #[inline]
    pub fn release(&mut self) {
        // SAFETY: see `needs_wakeup`. Release: our reads of the slots happen
        // before the kernel may overwrite them.
        unsafe { self.consumer.as_ref() }.store(self.cached_cons, Ordering::Release);
    }
}

impl<T: Copy> Drop for Ring<T> {
    fn drop(&mut self) {
        // SAFETY: the mapping handed over in `new`, unmapped exactly once; no
        // reference into it outlives `&mut self`.
        unsafe { libc::munmap(self.map.0, self.map.1) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::XdpRingOffset;

    /// An anonymous mapping standing in for one the kernel made, with the
    /// counters first and `size` u64 slots after them.
    fn fake(size: u32, off: XdpRingOffset) -> Ring<u64> {
        let len = 4096;
        // SAFETY: a fresh anonymous mapping, checked below.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        // SAFETY: a live mapping of `len` bytes, handed over to the Ring.
        unsafe { Ring::new(p, len, &off, size) }
    }

    const OFF: XdpRingOffset = XdpRingOffset {
        producer: 0,
        consumer: 64,
        desc: 192,
        flags: 128,
    };

    #[test]
    fn producer_and_consumer_follow_the_protocol() {
        let mut r = fake(4, OFF);
        assert_eq!(r.free(), 4);
        for v in 10..14 {
            assert!(r.push(v));
        }
        assert!(!r.push(99), "full: nothing overwritten");
        assert_eq!(r.outstanding(), 4);
        r.commit();
        // The "kernel" consumes two, then we can push two more.
        // SAFETY: the test owns the mapping; the counter is in bounds.
        unsafe { r.consumer.as_ref() }.store(2, Ordering::Release);
        assert_eq!(r.free(), 2);
        assert!(r.push(14) && r.push(15));
        r.commit();
        // Read back as a consumer from the start: the slots wrap around.
        let mut c = Ring::<u64> {
            producer: r.producer,
            consumer: r.consumer,
            flags: r.flags,
            descs: r.descs,
            mask: 3,
            size: 4,
            cached_prod: 2,
            cached_cons: 2,
            map: (std::ptr::null_mut(), 0),
        };
        let got: Vec<u64> = std::iter::from_fn(|| c.pop()).collect();
        assert_eq!(got, [12, 13, 14, 15]);
        c.release();
        assert_eq!(r.outstanding(), 0);
        // `c` shares `r`'s mapping: don't unmap it twice.
        std::mem::forget(c);
    }

    #[test]
    fn a_layout_outside_the_mapping_is_refused() {
        for bad in [
            XdpRingOffset { desc: 4090, ..OFF },  // slots past the end
            XdpRingOffset { producer: 2, ..OFF }, // misaligned counter
            XdpRingOffset { flags: 5000, ..OFF }, // counter past the end
        ] {
            let r = std::panic::catch_unwind(|| fake(4, bad));
            assert!(r.is_err(), "{bad:?}");
        }
        assert!(
            std::panic::catch_unwind(|| fake(3, OFF)).is_err(),
            "not a power of two"
        );
    }
}
