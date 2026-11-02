//! Physical frame allocator: bitmap over 4 KiB frames, next-fit scan.
//!
//! Covers PA 0..32 GiB (1 MiB of .bss) — ample for QEMU (RAM at 1 GiB) and
//! OCI A1 free tier (up to 24 GiB). Single-core and never called from ISR
//! context (ISRs only set wake bits), so no locking.

use crate::uefi::MemoryMapInfo;

pub const FRAME_SIZE: u64 = 4096;
const MAX_FRAMES: usize = 8 * 1024 * 1024; // 32 GiB
const WORDS: usize = MAX_FRAMES / 64;

// Memory map descriptor types we care about.
const LOADER_CODE: u32 = 1;
const LOADER_DATA: u32 = 2;
const BS_CODE: u32 = 3;
const BS_DATA: u32 = 4;
const CONVENTIONAL: u32 = 7;

struct Frames {
    /// bit set = free
    bitmap: [u64; WORDS],
    next: usize, // next-fit cursor (word index)
    free: u64,
}

static mut FRAMES: Frames = Frames {
    bitmap: [0; WORDS],
    next: 0,
    free: 0,
};

#[allow(static_mut_refs)]
fn frames() -> &'static mut Frames {
    unsafe { &mut FRAMES }
}

fn mark(f: &mut Frames, pa: u64, pages: u64, free: bool) {
    let start = (pa / FRAME_SIZE) as usize;
    for i in start..start + pages as usize {
        if i >= MAX_FRAMES {
            break;
        }
        let (w, b) = (i / 64, i % 64);
        let was = f.bitmap[w] & (1 << b) != 0;
        if free && !was {
            f.bitmap[w] |= 1 << b;
            f.free += 1;
        } else if !free && was {
            f.bitmap[w] &= !(1 << b);
            f.free -= 1;
        }
    }
}

/// Phase 1 (pre-MMU-switch): only EfiConventionalMemory is handed out.
/// BootServices regions still back the live UEFI page tables, and the loader
/// regions are our own image + memory-map buffer.
pub fn init(mmap: &MemoryMapInfo) {
    let f = frames();
    for d in mmap.iter() {
        if d.typ == CONVENTIONAL {
            mark(f, d.physical_start, d.number_of_pages, true);
        }
    }
    // Never hand out frame 0 (null guard) even if listed as usable.
    mark(f, 0, 1, false);
}

/// Phase 2 (post-MMU-switch): UEFI's page tables and boot-services pools are
/// dead — reclaim them. Loader regions stay reserved (kernel image + the
/// memory-map buffer itself).
pub fn release_boot_services(mmap: &MemoryMapInfo) {
    let f = frames();
    for d in mmap.iter() {
        if d.typ == BS_CODE || d.typ == BS_DATA {
            mark(f, d.physical_start, d.number_of_pages, true);
        }
        let _ = (LOADER_CODE, LOADER_DATA); // documented-reserved
    }
}

/// Allocate `n` physically contiguous frames with `align` frame alignment
/// (power of two). Returns the zeroed base PA.
pub fn alloc_contig(n: usize, align: usize) -> Option<u64> {
    let f = frames();
    // Two passes: next-fit from the cursor, then from the start.
    for pass in 0..2 {
        let mut idx = if pass == 0 { f.next * 64 } else { 0 };
        let end = MAX_FRAMES;
        'scan: while idx + n <= end {
            idx = (idx + align - 1) & !(align - 1);
            if idx + n > end {
                break;
            }
            // Fast-skip fully-allocated words.
            if f.bitmap[idx / 64] == 0 {
                idx = (idx / 64 + 1) * 64;
                continue;
            }
            for i in idx..idx + n {
                if f.bitmap[i / 64] & (1 << (i % 64)) == 0 {
                    idx = i + 1;
                    continue 'scan;
                }
            }
            let pa = idx as u64 * FRAME_SIZE;
            mark(f, pa, n as u64, false);
            f.next = idx / 64;
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, n * FRAME_SIZE as usize) };
            return Some(pa);
        }
    }
    None
}

pub fn alloc() -> Option<u64> {
    alloc_contig(1, 1)
}

pub fn free(pa: u64, n: usize) {
    mark(frames(), pa, n as u64, true);
}

pub fn free_frames() -> u64 {
    frames().free
}
