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

// The ring is owned by exactly one thread at a time.
unsafe impl<T: Copy> Send for Ring<T> {}

impl<T: Copy> Ring<T> {
    /// # Safety
    /// `map` must be the mmap()ed ring with the kernel-provided offsets.
    pub(crate) unsafe fn new(
        map: *mut libc::c_void,
        map_len: usize,
        off: &crate::sys::XdpRingOffset,
        size: u32,
    ) -> Self {
        let base = map as *mut u8;
        let producer = NonNull::new(base.add(off.producer as usize) as *mut AtomicU32).unwrap();
        let consumer = NonNull::new(base.add(off.consumer as usize) as *mut AtomicU32).unwrap();
        let flags = NonNull::new(base.add(off.flags as usize) as *mut AtomicU32).unwrap();
        let descs = NonNull::new(base.add(off.desc as usize) as *mut T).unwrap();
        let cached_prod = producer.as_ref().load(Ordering::Acquire);
        let cached_cons = consumer.as_ref().load(Ordering::Acquire);
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
        self.cached_cons = unsafe { self.consumer.as_ref() }.load(Ordering::Acquire);
        self.size - self.cached_prod.wrapping_sub(self.cached_cons)
    }

    /// Write one entry (not yet visible to the kernel; see [`Ring::commit`]).
    #[inline]
    pub fn push(&mut self, v: T) -> bool {
        if self.free() == 0 {
            return false;
        }
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
        unsafe { self.producer.as_ref() }.store(self.cached_prod, Ordering::Release);
    }

    /// Entries pushed but not yet consumed by the kernel.
    #[inline]
    pub fn outstanding(&self) -> u32 {
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
        self.cached_prod = unsafe { self.producer.as_ref() }.load(Ordering::Acquire);
        self.cached_prod.wrapping_sub(self.cached_cons)
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.available() == 0 {
            return None;
        }
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
        unsafe { self.consumer.as_ref() }.store(self.cached_cons, Ordering::Release);
    }
}

impl<T: Copy> Drop for Ring<T> {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.map.0, self.map.1) };
    }
}
