use crate::descriptor::VBusDmiDescriptor;
use std::alloc::{alloc_zeroed, dealloc, Layout};

pub struct MappedRegion {
    pub ring_area_size: usize,
    pub data_area_size: usize,
    inner: RegionInner,
}

enum RegionInner {
    #[cfg(target_os = "linux")]
    Linux(LinuxRegion),
    Heap(HeapRegion),
}

#[cfg(target_os = "linux")]
struct LinuxRegion {
    addr: *mut u8,
    vsize: usize,
    fd: libc::c_int,
}
#[cfg(target_os = "linux")]
unsafe impl Send for LinuxRegion {}
#[cfg(target_os = "linux")]
unsafe impl Sync for LinuxRegion {}

/// 64-byte-aligned heap allocation used as a fallback on non-Linux platforms.
struct HeapRegion {
    ptr: *mut u8,
    layout: Layout,
}

unsafe impl Send for HeapRegion {}
unsafe impl Sync for HeapRegion {}

impl MappedRegion {
    pub fn new_mirrored(
        ring_descriptor_count: usize,
        data_area_size: usize,
    ) -> Result<Self, String> {
        let ring_area = ring_descriptor_count * VBusDmiDescriptor::SIZE;
        let total = ring_area + data_area_size;

        #[cfg(target_os = "linux")]
        {
            match Self::new_linux(ring_area, data_area_size, total) {
                Ok(r) => return Ok(r),
                Err(e) => eprintln!("Linux mirrored mmap failed ({e}), using heap fallback"),
            }
        }

        // Allocate with VBusDmiDescriptor alignment (64 bytes) so cast is safe.
        let align = std::mem::align_of::<VBusDmiDescriptor>(); // 64
        let layout = Layout::from_size_align(total, align)
            .map_err(|e| e.to_string())?;
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err("heap allocation failed".into());
        }
        Ok(Self {
            ring_area_size: ring_area,
            data_area_size,
            inner: RegionInner::Heap(HeapRegion { ptr, layout }),
        })
    }

    #[cfg(target_os = "linux")]
    fn new_linux(ring_area: usize, data_area_size: usize, total: usize) -> Result<Self, String> {
        use libc::*;
        unsafe {
            let name = std::ffi::CString::new("vbus_dmi_ring").unwrap();
            let fd = memfd_create(name.as_ptr(), MFD_ALLOW_SEALING);
            if fd < 0 {
                return Err(format!("memfd_create: {}", std::io::Error::last_os_error()));
            }
            if ftruncate(fd, total as off_t) != 0 {
                close(fd);
                return Err(format!("ftruncate: {}", std::io::Error::last_os_error()));
            }
            let va = mmap(
                std::ptr::null_mut(), total * 2,
                PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
            );
            if va == MAP_FAILED { close(fd); return Err("mmap reserve failed".into()); }
            let m1 = mmap(va, total, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
            if m1 == MAP_FAILED { munmap(va, total * 2); close(fd); return Err("mmap first failed".into()); }
            let m2 = mmap(
                (va as usize + total) as *mut c_void, total,
                PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0,
            );
            if m2 == MAP_FAILED { munmap(va, total * 2); close(fd); return Err("mmap mirror failed".into()); }
            Ok(Self {
                ring_area_size: ring_area,
                data_area_size,
                inner: RegionInner::Linux(LinuxRegion { addr: va as *mut u8, vsize: total * 2, fd }),
            })
        }
    }

    pub fn base_ptr(&self) -> *mut u8 {
        match &self.inner {
            #[cfg(target_os = "linux")]
            RegionInner::Linux(r) => r.addr,
            RegionInner::Heap(r) => r.ptr,
        }
    }

    pub fn descriptor_mut_ptr(&self) -> *mut VBusDmiDescriptor {
        self.base_ptr() as *mut VBusDmiDescriptor
    }

    pub fn descriptor_ptr(&self) -> *const VBusDmiDescriptor {
        self.base_ptr() as *const VBusDmiDescriptor
    }

    pub fn data_ptr(&self) -> *mut u8 {
        unsafe { self.base_ptr().add(self.ring_area_size) }
    }
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        match &self.inner {
            #[cfg(target_os = "linux")]
            RegionInner::Linux(r) => unsafe {
                libc::munmap(r.addr as *mut libc::c_void, r.vsize);
                libc::close(r.fd);
            },
            RegionInner::Heap(r) => unsafe { dealloc(r.ptr, r.layout) },
        }
    }
}

unsafe impl Send for MappedRegion {}
unsafe impl Sync for MappedRegion {}
