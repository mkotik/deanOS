//! deanOS — zero-dependency aarch64 UEFI unikernel (see PLAN.md).
//! M1: UEFI handoff, ACPI discovery, EL normalization, PL011 serial console.

#![no_std]
#![no_main]

extern crate alloc;

mod acpi;
mod arch;
mod drivers;
mod http;
mod httpd;
mod mm;
mod net;
mod netglue;
mod runtime;
mod uefi;

use core::ffi::c_void;
use core::fmt::Write;

/// Everything the kernel needs after ExitBootServices, captured while boot
/// services were still alive. Lives in .bss so it survives the stack switch.
pub struct BootInfo {
    pub image_base: u64,
    pub image_size: u64,
    pub acpi: acpi::AcpiInfo,
    pub mmap: uefi::MemoryMapInfo,
}

static mut BOOT_INFO: BootInfo = BootInfo {
    image_base: 0,
    image_size: 0,
    acpi: acpi::AcpiInfo::empty(),
    mmap: uefi::MemoryMapInfo::empty(),
};

const KSTACK_SIZE: usize = 256 * 1024;

#[repr(C, align(4096))]
struct KernelStack([u8; KSTACK_SIZE]);

static mut KSTACK: KernelStack = KernelStack([0; KSTACK_SIZE]);

// QEMU-virt PL011; last-resort fallback if firmware ships no SPCR.
const FALLBACK_UART: u64 = 0x0900_0000;

#[no_mangle]
pub extern "efiapi" fn efi_main(image: uefi::Handle, st: *mut uefi::SystemTable) -> uefi::Status {
    unsafe {
        let st = &*st;
        let mut con = uefi::ConOut(st.con_out);
        let _ = writeln!(con, "deanOS: efi_main (EL{})", arch::current_el());

        let bi = &mut *core::ptr::addr_of_mut!(BOOT_INFO);

        if let Some((base, size)) = uefi::loaded_image_extent(st, image) {
            bi.image_base = base;
            bi.image_size = size;
        }

        match uefi::find_config_table(st, &uefi::ACPI_20_TABLE_GUID) {
            Some(rsdp) => bi.acpi = acpi::parse(rsdp as u64),
            None => {
                let _ = writeln!(con, "deanOS: FATAL no ACPI 2.0 table");
                return 1;
            }
        }

        let _ = writeln!(con, "deanOS: exiting boot services");
        match uefi::exit_boot_services(st, image) {
            Some(m) => bi.mmap = m,
            None => {
                return 1;
            }
        }

        // Boot services are gone. Normalize EL, switch to the kernel stack,
        // and never come back.
        let stack_top = core::ptr::addr_of!(KSTACK) as u64 + KSTACK_SIZE as u64;
        arch::el_setup(bi as *mut BootInfo as *mut c_void, kernel_main, stack_top)
    }
}

extern "C" fn kernel_main(arg: *mut c_void) -> ! {
    // NOTE (M1): everything here may run MMU-off (EL2-drop path), where the
    // prebuilt, non-strict-align core::fmt alignment-faults. Raw print
    // helpers only until M2 turns the MMU on.
    use drivers::uart::{put_dec, put_hex, puts};

    let bi = unsafe { &mut *(arg as *mut BootInfo) };

    let uart = if bi.acpi.uart_base != 0 {
        bi.acpi.uart_base
    } else {
        FALLBACK_UART
    };
    drivers::uart::init(uart);

    puts("\ndeanOS v0.1 | aarch64 unikernel | EL");
    put_dec(arch::current_el());
    puts("\nimage: base=");
    put_hex(bi.image_base);
    puts(" size=");
    put_hex(bi.image_size);
    puts("\nacpi : rsdp=");
    put_hex(bi.acpi.rsdp);
    puts(" xsdt=");
    put_hex(bi.acpi.xsdt);
    puts("\nuart : base=");
    put_hex(uart);
    puts(" spcr-subtype=");
    put_hex(bi.acpi.uart_subtype as u64);
    puts("\ngic  : v");
    put_dec(bi.acpi.gic_version as u64);
    puts(" GICD=");
    put_hex(bi.acpi.gicd_base);
    puts(" GICR=");
    put_hex(bi.acpi.gicr_base);
    puts("+");
    put_hex(bi.acpi.gicr_len as u64);
    puts(" ITS=");
    put_hex(bi.acpi.its_base);
    puts("\npcie : ECAM=");
    put_hex(bi.acpi.ecam_base);
    puts(" bus ");
    put_dec(bi.acpi.bus_start as u64);
    puts("..=");
    put_dec(bi.acpi.bus_end as u64);
    puts("\ntimer: vtimer GSIV=");
    put_dec(bi.acpi.vtimer_gsiv as u64);
    puts("\n");

    print_memory_map(bi);

    puts("M1 GATE OK\n");

    // --- M2: frame allocator -> identity page tables -> MMU switch ---------
    mm::frames::init(&bi.mmap);
    puts("mm   : frames free=");
    put_dec(mm::frames::free_frames());
    puts("\n");
    let stack_guard = core::ptr::addr_of!(KSTACK) as u64; // first page of KSTACK
    mm::paging::init(bi, stack_guard);
    mm::frames::release_boot_services(&bi.mmap);
    // MMU is on with Normal WB RAM: core::fmt is safe from here on.
    kprintln!(
        "mm   : MMU on (TTBR0 switched), frames free={} ({} MiB)",
        mm::frames::free_frames(),
        mm::frames::free_frames() * 4 / 1024
    );

    heap_stress_test();

    #[cfg(feature = "fault-test")]
    fault_test();

    kprintln!("M2 GATE OK");

    // --- M3: GICv3 + virtual timer + async executor ------------------------
    drivers::gicv3::init(bi.acpi.gicd_base, bi.acpi.gicr_base);
    drivers::gicv3::enable_ppi(bi.acpi.vtimer_gsiv);
    runtime::executor::VTIMER_GSIV
        .store(bi.acpi.vtimer_gsiv as u64, core::sync::atomic::Ordering::Relaxed);
    kprintln!(
        "gic  : up (vtimer PPI {}), cntfrq={} Hz",
        bi.acpi.vtimer_gsiv,
        drivers::timer::freq()
    );

    runtime::executor::spawn(m3_gate_task());
    runtime::executor::spawn(ticker("A", 150));
    runtime::executor::spawn(ticker("B", 230));
    runtime::executor::spawn(ticker("C", 410));

    // --- M4/M5: VirtIO-net + full L2/L3 stack (DHCP, ARP, ICMP) ------------
    let ecam = drivers::pci::Ecam::new(bi.acpi.ecam_base, bi.acpi.bus_start, bi.acpi.bus_end);
    runtime::executor::spawn(netglue::net_task(ecam));
    runtime::executor::spawn(m5_gate_task());

    // --- M6: TCP echo server on :7 (gate/regression via hostfwd) -----------
    runtime::executor::spawn(echo_server(7));

    // --- M7: HTTP/1.1 REST server on :80 -----------------------------------
    runtime::executor::spawn(httpd::serve(80));

    runtime::executor::run()
}

async fn echo_server(port: u16) {
    use runtime::sleep::sleep_ms;
    while !netglue::net_ready() {
        sleep_ms(20).await;
    }
    netglue::tcp_listen(port);
    kprintln!("tcp  : echo server on :{port} — M6 READY");
    loop {
        let h = netglue::tcp_accept(port).await;
        runtime::executor::spawn(echo_conn(h));
    }
}

async fn echo_conn(h: usize) {
    let mut buf = alloc::boxed::Box::new([0u8; 2048]);
    loop {
        let n = netglue::tcp_read(h, &mut buf[..]).await;
        if n == 0 {
            break;
        }
        if !netglue::tcp_write_all(h, &buf[..n]).await {
            break;
        }
    }
    netglue::tcp_close(h);
}

fn fmt_ip(ip: u32) -> alloc::string::String {
    use alloc::format;
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff
    )
}

/// M5 gate: DHCP acquires a lease, then ICMP echo to the gateway round-trips.
async fn m5_gate_task() {
    use netglue::with_net;
    use runtime::sleep::sleep_ms;

    // Wait for DHCP (slirp answers in well under a second).
    let mut waited = 0u64;
    loop {
        sleep_ms(50).await;
        waited += 50;
        if netglue::net_ready() && with_net(|s| s.cfg.up) {
            break;
        }
        if waited > 15_000 {
            kprintln!("M5 GATE FAIL: no DHCP lease after 15 s");
            return;
        }
    }
    let cfg = with_net(|s| s.cfg);
    kprintln!(
        "dhcp : bound in {} ms: ip={} mask={} gw={} dns={}",
        waited,
        fmt_ip(cfg.ip),
        fmt_ip(cfg.mask),
        fmt_ip(cfg.gw),
        fmt_ip(cfg.dns)
    );

    // Ping the gateway: 3 echo requests, require at least one reply.
    let t0 = drivers::timer::now_ms();
    for seq in 1..=3u16 {
        with_net(|s| s.ping(cfg.gw, 0xdea0, seq, drivers::timer::now_ms()));
        sleep_ms(120).await;
    }
    let mut ok = false;
    for _ in 0..30 {
        if with_net(|s| !s.pongs.is_empty()) {
            ok = true;
            break;
        }
        sleep_ms(100).await;
    }
    let (rx, tx) = with_net(|s| (s.rx_frames, s.tx_frames));
    if ok {
        let (id, seq) = with_net(|s| s.pongs[0]);
        kprintln!(
            "icmp : echo reply id={:#x} seq={} rtt<{} ms (frames rx={} tx={})",
            id,
            seq,
            drivers::timer::now_ms() - t0,
            rx,
            tx
        );
        kprintln!("M5 GATE OK");
    } else {
        kprintln!("M5 GATE FAIL: no echo reply (frames rx={rx} tx={tx})");
    }
}

/// M3 gate: three tickers at co-prime periods; after 2 s check each advanced
/// the expected number of times (timer accuracy + concurrent wakeups).
async fn m3_gate_task() {
    use runtime::sleep::sleep_ms;
    let t0 = drivers::timer::now_ms();
    sleep_ms(2000).await;
    let dt = drivers::timer::now_ms() - t0;
    let (a, b, c) = unsafe { (TICKS[0], TICKS[1], TICKS[2]) };
    kprintln!("m3   : after {} ms ticks A={} B={} C={}", dt, a, b, c);
    let ok = (1900..=2200).contains(&dt)
        && (11..=15).contains(&a) // 2000/150 ≈ 13
        && (7..=10).contains(&b) // 2000/230 ≈ 8
        && (3..=6).contains(&c); // 2000/410 ≈ 4
    if ok {
        kprintln!("M3 GATE OK");
    } else {
        kprintln!("M3 GATE FAIL");
    }
}

static mut TICKS: [u64; 3] = [0; 3];

async fn ticker(name: &'static str, period_ms: u64) {
    use runtime::sleep::sleep_ms;
    let idx = match name {
        "A" => 0,
        "B" => 1,
        _ => 2,
    };
    loop {
        sleep_ms(period_ms).await;
        unsafe { TICKS[idx] += 1 };
    }
}

fn heap_stress_test() {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;

    let before = mm::frames::free_frames();

    let mut v: Vec<u64> = Vec::new();
    for i in 0..200_000u64 {
        v.push(i * 3);
    }
    assert_eq!(v[199_999], 199_999 * 3);
    assert_eq!(v.iter().rev().take(5).sum::<u64>(), (199_999 - 2) * 3 * 5);

    let mut s = String::new();
    for _ in 0..1000 {
        s.push_str("deanOS");
    }
    assert_eq!(s.len(), 6000);
    assert!(s.ends_with("deanOS"));

    let b = Box::new([0xA5u8; 3000]); // > 2048 -> page path
    assert!(b.iter().all(|&x| x == 0xA5));

    // Churn: interleaved alloc/free across classes.
    let mut boxes: Vec<Box<[u8; 100]>> = Vec::new();
    for _ in 0..500 {
        boxes.push(Box::new([7u8; 100]));
    }
    boxes.truncate(100);
    for _ in 0..400 {
        boxes.push(Box::new([9u8; 100]));
    }
    assert!(boxes.len() == 500);

    drop(v);
    drop(s);
    drop(b);
    drop(boxes);

    let after = mm::frames::free_frames();
    kprintln!("heap : stress OK (frames {} -> {})", before, after);
}

/// Deliberate faults for the M2 gate (build with --features fault-test).
#[cfg(feature = "fault-test")]
fn fault_test() {
    kprintln!("fault-test: reading null...");
    let v = unsafe { core::ptr::read_volatile(0x10 as *const u64) };
    kprintln!("fault-test: UNEXPECTED survival ({v})");
}

fn print_memory_map(bi: &BootInfo) {
    use drivers::uart::{put_dec, puts};
    let mut pages_by_type = [0u64; 16];
    let mut entries = 0usize;
    for d in bi.mmap.iter() {
        entries += 1;
        let t = (d.typ as usize).min(15);
        pages_by_type[t] += d.number_of_pages;
    }
    puts("mmap : ");
    put_dec(entries as u64);
    puts(" descriptors (desc_size=");
    put_dec(bi.mmap.desc_size as u64);
    puts(")\n");
    for (t, pages) in pages_by_type.iter().enumerate() {
        if *pages == 0 {
            continue;
        }
        puts("       ");
        puts(uefi::MEM_TYPE_NAMES.get(t).copied().unwrap_or("Unknown"));
        puts(": ");
        put_dec(pages * 4);
        puts(" KiB\n");
    }
    let usable = pages_by_type[3] + pages_by_type[4] + pages_by_type[7];
    puts("       usable RAM (conv+bs): ");
    put_dec(usable * 4 / 1024);
    puts(" MiB\n");
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    kprintln!("\n*** KERNEL PANIC: {}", info);
    loop {
        arch::wfi();
    }
}
