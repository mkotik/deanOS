//! Alignment-safe mem* intrinsics.
//!
//! These strong symbols override compiler_builtins' weak ones. The prebuilt
//! core/compiler_builtins are NOT compiled with +strict-align, so their
//! memcpy issues unaligned word loads — fatal whenever the MMU is off and
//! every access is Device-nGnRnE (pre-M2 window, post-EL2-drop window).
//! Word-sized fast paths run only when both pointers are 8-byte aligned.

#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    if (dst as usize) % 8 == 0 && (src as usize) % 8 == 0 {
        while i + 8 <= n {
            *(dst.add(i) as *mut u64) = *(src.add(i) as *const u64);
            i += 8;
        }
    }
    while i < n {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) < (src as usize) || (dst as usize) >= (src as usize) + n {
        return memcpy(dst, src, n);
    }
    let mut i = n;
    while i > 0 {
        i -= 1;
        *dst.add(i) = *src.add(i);
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    let b = val as u8;
    let mut i = 0;
    if (dst as usize) % 8 == 0 {
        let word = u64::from_ne_bytes([b; 8]);
        while i + 8 <= n {
            *(dst.add(i) as *mut u64) = word;
            i += 8;
        }
    }
    while i < n {
        *dst.add(i) = b;
        i += 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let (x, y) = (*a.add(i), *b.add(i));
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}
