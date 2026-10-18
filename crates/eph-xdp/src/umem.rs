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

unsafe impl Send for Umem {}

impl Umem {
    pub fn new(frames: u32, frame_size: u32) -> io::Result<Self> {
        assert!(frame_size.is_power_of_two() && (2048..=4096).contains(&frame_size));
        let len = frames as usize * frame_size as usize;
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE;
        let mut huge_pages = true;
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
    /// # Safety
    /// The caller must own the frame (it is not on a fill or tx ring) and
    /// must not create overlapping mutable slices.
    // Handing out `&mut` from `&self` is the point: frames are owned by
    // whoever holds their address, not by Rust's borrow of the UMEM.
    #[allow(clippy::mut_from_ref)]
    #[inline(always)]
    pub unsafe fn frame_mut(&self, addr: u64) -> &mut [u8] {
        let end = self.frame_base(addr) + self.frame_size as u64;
        debug_assert!((end as usize) <= self.len);
        std::slice::from_raw_parts_mut(self.area.add(addr as usize), (end - addr) as usize)
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.area as *mut libc::c_void, self.len) };
    }
}
