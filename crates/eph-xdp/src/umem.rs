use std::io;

/// The packet buffer area: `frames` frames of `frame_size` bytes each.
///
/// We try to back it with 2 MiB huge pages: 32 MiB of frames is then 16 TLB
/// entries instead of 8192, which matters when every packet touches a
/// different frame. If no huge pages are reserved (`vm.nr_hugepages`), we fall
/// back to normal pages.
pub struct Umem {
    area: *mut u8,
    len: usize,
    frame_size: u32,
    frames: u32,
    pub huge_pages: bool,
}

// SAFETY: `area` is a private anonymous mapping owned by this value alone;
// nothing else in the process holds the pointer. Moving the owner to another
// thread (a worker) moves all access with it. Umem is not Sync: frames are
// handed out through `frame_mut`, whose contract keeps one owner per frame.
unsafe impl Send for Umem {}

impl Umem {
    pub fn new(frames: u32, frame_size: u32) -> io::Result<Self> {
        assert!(frame_size.is_power_of_two() && (2048..=4096).contains(&frame_size));
        let len = frames as usize * frame_size as usize;
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE;
        let mut huge_pages = true;
        // SAFETY: a fresh anonymous mapping (fd -1, no address hint): it
        // can't alias any memory Rust already uses. The result is checked
        // against MAP_FAILED before use.
        let mut p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                flags | libc::MAP_HUGETLB,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            huge_pages = false;
            // SAFETY: as above, without MAP_HUGETLB.
            p = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags, -1, 0) };
            if p == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Umem {
            area: p as *mut u8,
            len,
            frame_size,
            frames,
            huge_pages,
        })
    }

    pub fn frame_size(&self) -> u32 {
        self.frame_size
    }
    pub fn frames(&self) -> u32 {
        self.frames
    }
    pub(crate) fn area(&self) -> (*mut u8, usize) {
        (self.area, self.len)
    }

    /// Address (UMEM offset) of frame `i`.
    pub fn frame_addr(&self, i: u32) -> u64 {
        i as u64 * self.frame_size as u64
    }

    /// Start of the frame containing `addr`. RX descriptors may point a bit
    /// into a frame (driver headroom), so mask down to the frame boundary.
    #[inline(always)]
    pub fn frame_base(&self, addr: u64) -> u64 {
        addr & !(self.frame_size as u64 - 1)
    }

    /// The bytes from `addr` to the end of its frame.
    ///
    /// Panics if `addr` isn't inside the UMEM: a bad address (a corrupt
    /// descriptor, a bug) stops the worker instead of reaching past the
    /// mapping.
    ///
    /// # Safety
    /// The caller must own the frame: it came off an RX or completion ring
    /// or the free list, and isn't on a fill or TX ring (where the kernel
    /// may write it). No other slice of the same frame may be alive while
    /// this one is.
    // Handing out `&mut` from `&self` is the point: frames are owned by
    // whoever holds their address, not by Rust's borrow of the UMEM.
    #[allow(clippy::mut_from_ref)]
    #[inline(always)]
    pub unsafe fn frame_mut(&self, addr: u64) -> &mut [u8] {
        let end = self.frame_base(addr) + self.frame_size as u64;
        // A real check, not a debug_assert: the release build is the one
        // that runs on a router. One comparison per packet.
        assert!(
            end <= self.len as u64,
            "frame address {addr:#x} outside the UMEM"
        );
        // SAFETY: `addr..end` lies inside the mapping (checked above), which
        // lives as long as `self`; the caller guarantees nobody else uses
        // this frame for the slice's lifetime.
        unsafe {
            std::slice::from_raw_parts_mut(self.area.add(addr as usize), (end - addr) as usize)
        }
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        // SAFETY: `area`/`len` are exactly the mapping made in `new`, unmapped
        // once. Frames handed out by `frame_mut` borrow `self`, so none can
        // outlive this; the sockets using the UMEM must be closed first (the
        // owner's field order: see ephemerisd's `Worker`).
        unsafe { libc::munmap(self.area as *mut libc::c_void, self.len) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_stay_inside_the_umem() {
        let u = Umem::new(4, 4096).unwrap();
        // SAFETY: the test owns every frame; one slice at a time.
        let f = unsafe { u.frame_mut(u.frame_addr(3) + 256) };
        assert_eq!(
            f.len(),
            4096 - 256,
            "from the address to the end of its frame"
        );
        f[0] = 1;
        let past = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: as above; this one must panic before making a slice.
            let _ = unsafe { u.frame_mut(u.frame_addr(4)) };
        }));
        assert!(past.is_err(), "an address past the end is refused");
    }
}
