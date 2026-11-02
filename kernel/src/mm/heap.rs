//! `#[global_allocator]`: size-class segregated slab (16 B..2048 B) backed by
//! the frame allocator; larger allocations go straight to contiguous frames.
//!
//! Single-core, never called from ISR context (ISRs only set wake bits in the
//! executor bitmap) — so plain non-atomic free lists are safe.

use crate::mm::frames;
use core::alloc::{GlobalAlloc, Layout};

const CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];

struct Heap {
    /// Head of intrusive free list per class (each free chunk stores the next
    /// pointer in its first 8 bytes).
    free: [usize; 8],
}

static mut HEAP: Heap = Heap { free: [0; 8] };

fn class_for(layout: Layout) -> Option<usize> {
    let need = layout.size().max(layout.align());
    CLASSES.iter().position(|&c| c >= need)
}

pub struct KernelAlloc;

unsafe impl GlobalAlloc for KernelAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[allow(static_mut_refs)]
        let h = &mut HEAP;
        match class_for(layout) {
            Some(ci) => {
                if h.free[ci] == 0 {
                    // Refill: carve one frame into class-size chunks. Chunks
                    // are class-aligned by construction (4096 % class == 0).
                    let Some(pa) = frames::alloc() else {
                        return core::ptr::null_mut();
                    };
                    let size = CLASSES[ci];
                    let mut p = pa as usize;
                    let end = p + 4096;
                    while p + size <= end {
                        *(p as *mut usize) = h.free[ci];
                        h.free[ci] = p;
                        p += size;
                    }
                }
                let p = h.free[ci];
                h.free[ci] = *(p as *const usize);
                p as *mut u8
            }
            None => {
                let pages = layout.size().div_ceil(4096);
                let align_frames = (layout.align().div_ceil(4096)).max(1);
                match frames::alloc_contig(pages, align_frames) {
                    Some(pa) => pa as *mut u8,
                    None => core::ptr::null_mut(),
                }
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[allow(static_mut_refs)]
        let h = &mut HEAP;
        match class_for(layout) {
            Some(ci) => {
                *(ptr as *mut usize) = h.free[ci];
                h.free[ci] = ptr as usize;
            }
            None => {
                frames::free(ptr as u64, layout.size().div_ceil(4096));
            }
        }
    }
}

#[global_allocator]
static ALLOCATOR: KernelAlloc = KernelAlloc;
