//! AArch64 early boot: EL2→EL1 normalization, FPEN, stack switch (PLAN.md §2.3).

use core::arch::global_asm;

// el_setup(x0 = kernel_main arg, x1 = kernel_main fn, x2 = new stack top).
// Never returns.
//
// EL2 path notes:
//  - EL1 sysregs are architecturally UNKNOWN from EL2 → write a sane
//    SCTLR_EL1 (RES1 | I-cache on, MMU/D-cache off: 0x30D01800) and SP_EL1
//    BEFORE eret (SPSR selects EL1h).
//  - HCR_EL2.RW=1 (EL1 is AArch64), CNTHCTL_EL2 |= EL1PCTEN|EL1PCEN (untrap
//    timers), CNTVOFF_EL2=0, CPTR_EL2=0x33FF (RES1, no FP trap).
//  - Post-drop EL1 runs MMU-off; safe only because of +strict-align.
// EL1 path: UEFI's identity-mapped TTBR0_EL1 stays live until M2.
global_asm!(
    r#"
.section .text
.global el_setup
el_setup:
    msr daifset, #0xf           // mask all async exceptions during handoff
    mrs x9, CurrentEL
    lsr x9, x9, #2
    cmp x9, #2
    b.ne 1f

    // --- entered at EL2: normalize and drop to EL1h ---
    movz x10, #0x1800
    movk x10, #0x30D0, lsl #16  // SCTLR_EL1 = RES1 | I, MMU+D-cache off
    msr sctlr_el1, x10
    msr sp_el1, x2
    mov x10, #(1 << 31)         // HCR_EL2.RW = AArch64 EL1
    msr hcr_el2, x10
    mrs x10, cnthctl_el2
    orr x10, x10, #3            // EL1PCTEN | EL1PCEN
    msr cnthctl_el2, x10
    msr cntvoff_el2, xzr
    movz x10, #0x33FF           // CPTR_EL2 RES1, no traps
    msr cptr_el2, x10
    mov x10, #0x3C5             // EL1h, DAIF masked
    msr spsr_el2, x10
    adr x10, 1f
    msr elr_el2, x10
    isb
    eret

1:  // --- at EL1 ---
    mrs x9, cpacr_el1
    orr x9, x9, #(3 << 20)      // FPEN = 0b11: untrap FP/NEON (mandatory:
    msr cpacr_el1, x9           // target spec enables NEON — PLAN.md §2.1)
    adrp x9, vector_table
    add x9, x9, :lo12:vector_table
    msr vbar_el1, x9
    isb
    mov sp, x2
    br x1

// 16-entry EL1 exception vector table. Each entry records its index and
// jumps to a common trampoline that hands ESR/ELR/FAR to Rust. Faulting
// context is never resumed in M1/M2 bring-up except where M2 tests expect it.
.macro VECTOR idx
    .balign 0x80
    mov x0, #\idx
    b fault_trampoline
.endm

// Vector 5 (IRQ, current EL, SP_ELx) gets a real handler; everything else is
// a fatal dump. The IRQ path saves the full caller-saved set INCLUDING all
// SIMD registers — LLVM freely uses NEON in any Rust function it interrupts.
.balign 0x800
.global vector_table
vector_table:
    VECTOR 0
    VECTOR 1
    VECTOR 2
    VECTOR 3
    VECTOR 4
    .balign 0x80            // entry 5: IRQ from current EL (SP_ELx)
    b irq_trampoline
    VECTOR 6
    VECTOR 7
    VECTOR 8
    VECTOR 9
    VECTOR 10
    VECTOR 11
    VECTOR 12
    VECTOR 13
    VECTOR 14
    VECTOR 15

fault_trampoline:
    mrs x1, esr_el1
    mrs x2, elr_el1
    mrs x3, far_el1
    b rust_fault

irq_trampoline:
    sub sp, sp, #(34 * 8 + 32 * 16)
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x29, [sp, #144]
    mrs x9, elr_el1
    mrs x10, spsr_el1
    stp x30, x9, [sp, #160]
    stp x10, xzr, [sp, #176]
    add x11, sp, #(34 * 8)
    stp q0, q1, [x11, #0]
    stp q2, q3, [x11, #32]
    stp q4, q5, [x11, #64]
    stp q6, q7, [x11, #96]
    stp q8, q9, [x11, #128]
    stp q10, q11, [x11, #160]
    stp q12, q13, [x11, #192]
    stp q14, q15, [x11, #224]
    stp q16, q17, [x11, #256]
    stp q18, q19, [x11, #288]
    stp q20, q21, [x11, #320]
    stp q22, q23, [x11, #352]
    stp q24, q25, [x11, #384]
    stp q26, q27, [x11, #416]
    stp q28, q29, [x11, #448]
    stp q30, q31, [x11, #480]
    bl rust_irq
    add x11, sp, #(34 * 8)
    ldp q0, q1, [x11, #0]
    ldp q2, q3, [x11, #32]
    ldp q4, q5, [x11, #64]
    ldp q6, q7, [x11, #96]
    ldp q8, q9, [x11, #128]
    ldp q10, q11, [x11, #160]
    ldp q12, q13, [x11, #192]
    ldp q14, q15, [x11, #224]
    ldp q16, q17, [x11, #256]
    ldp q18, q19, [x11, #288]
    ldp q20, q21, [x11, #320]
    ldp q22, q23, [x11, #352]
    ldp q24, q25, [x11, #384]
    ldp q26, q27, [x11, #416]
    ldp q28, q29, [x11, #448]
    ldp q30, q31, [x11, #480]
    ldr x10, [sp, #176]
    ldp x30, x9, [sp, #160]
    msr spsr_el1, x10
    msr elr_el1, x9
    ldp x18, x29, [sp, #144]
    ldp x16, x17, [sp, #128]
    ldp x14, x15, [sp, #112]
    ldp x12, x13, [sp, #96]
    ldp x10, x11, [sp, #80]
    ldp x8, x9, [sp, #64]
    ldp x6, x7, [sp, #48]
    ldp x4, x5, [sp, #32]
    ldp x2, x3, [sp, #16]
    ldp x0, x1, [sp, #0]
    add sp, sp, #(34 * 8 + 32 * 16)
    eret
"#
);

extern "C" {
    pub fn el_setup(arg: *mut core::ffi::c_void, entry: extern "C" fn(*mut core::ffi::c_void) -> !, stack_top: u64) -> !;
}

// enable_mmu(x0=ttbr0, x1=tcr, x2=mair): disable translation, reprogram, and
// re-enable with our identity tables. The MMU-off window is pure sysreg code
// (no loads/stores), so UEFI-MAIR vs our-MAIR index mismatch can't bite, and
// both entry paths (UEFI MMU on at EL1 / MMU off post-EL2-drop) converge here.
global_asm!(
    r#"
.global enable_mmu
enable_mmu:
    mrs x9, sctlr_el1
    bic x9, x9, #1              // M=0
    msr sctlr_el1, x9
    isb
    msr mair_el1, x2
    msr tcr_el1, x1
    msr ttbr0_el1, x0
    dsb nsh
    tlbi vmalle1
    dsb nsh
    ic iallu
    dsb nsh
    isb
    mrs x9, sctlr_el1
    orr x9, x9, #1              // M: MMU on
    orr x9, x9, #(1 << 2)       // C: D-cache on
    orr x9, x9, #(1 << 12)      // I: I-cache on
    msr sctlr_el1, x9
    isb
    ret
"#
);

extern "C" {
    pub fn enable_mmu(ttbr0: u64, tcr: u64, mair: u64);
}

/// Exception sink: raw-print the fault (core::fmt may be unusable — the MMU
/// might be off or the fault may come from core itself) and halt.
#[no_mangle]
extern "C" fn rust_fault(vector: u64, esr: u64, elr: u64, far: u64) -> ! {
    use crate::drivers::uart::{put_dec, put_hex, puts};
    puts("\n*** EXCEPTION vector=");
    put_dec(vector);
    puts(" EC=");
    put_hex(esr >> 26);
    puts(" ESR=");
    put_hex(esr);
    puts(" ELR=");
    put_hex(elr);
    puts(" FAR=");
    put_hex(far);
    puts("\n");
    loop {
        wfi();
    }
}

#[inline]
pub fn current_el() -> u64 {
    let el: u64;
    unsafe { core::arch::asm!("mrs {}, CurrentEL", out(reg) el) };
    el >> 2
}

#[inline]
pub fn wfi() {
    unsafe { core::arch::asm!("wfi") };
}
