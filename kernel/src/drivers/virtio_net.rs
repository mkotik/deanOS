//! VirtIO-net 1.0 Modern PCI driver: split virtqueues, poll-driven RX/TX.
//!
//! Negotiates VERSION_1 | MAC | STATUS only — all checksums stay in software,
//! and every RX/TX buffer starts with the mandatory 12-byte virtio_net_hdr.
//! Interrupt mode starts as timer-poll (PLAN.md M4); ITS MSI-X is a later,
//! separable step — the RX task just polls the used ring at sub-ms latency.

use crate::drivers::pci::{self, Device, Ecam};
use crate::mm::frames;
use core::sync::atomic::{fence, Ordering};

pub const VIRTIO_NET_HDR_LEN: usize = 12;
const QUEUE_SIZE: u16 = 256;
const RX_BUF_LEN: u32 = 2048;

// device status bits
const ACKNOWLEDGE: u8 = 1;
const DRIVER: u8 = 2;
const DRIVER_OK: u8 = 4;
const FEATURES_OK: u8 = 8;

// features
const F_MAC: u64 = 1 << 5;
const F_STATUS: u64 = 1 << 16;
const F_VERSION_1: u64 = 1 << 32;

// common cfg offsets
const DEV_FEATURE_SEL: usize = 0;
const DEV_FEATURE: usize = 4;
const DRV_FEATURE_SEL: usize = 8;
const DRV_FEATURE: usize = 12;
const DEVICE_STATUS: usize = 20;
const QUEUE_SELECT: usize = 22;
const QUEUE_SIZE_OFF: usize = 24;
const QUEUE_ENABLE: usize = 28;
const QUEUE_NOTIFY_OFF: usize = 30;
const QUEUE_DESC: usize = 32;
const QUEUE_DRIVER: usize = 40;
const QUEUE_DEVICE: usize = 48;

#[repr(C)]
#[derive(Clone, Copy)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

const DESC_F_WRITE: u16 = 2;

struct Virtq {
    size: u16,
    desc: *mut Desc,
    avail: *mut u16, // [flags, idx, ring[size]...]
    used: *mut u8,   // {flags u16, idx u16, ring: {id u32, len u32}[size]}
    notify: *mut u16,
    buf_base: u64, // contiguous buffer region, size * RX_BUF_LEN
    avail_shadow: u16,
    last_used: u16,
}

impl Virtq {
    fn used_idx(&self) -> u16 {
        unsafe { core::ptr::read_volatile((self.used as usize + 2) as *const u16) }
    }

    fn push_avail(&mut self, desc_id: u16) {
        unsafe {
            let ring = self.avail.add(2);
            core::ptr::write_volatile(
                ring.add((self.avail_shadow % self.size) as usize),
                desc_id,
            );
            fence(Ordering::SeqCst);
            self.avail_shadow = self.avail_shadow.wrapping_add(1);
            core::ptr::write_volatile(self.avail.add(1), self.avail_shadow);
        }
    }

    fn pop_used(&mut self) -> Option<(u16, u32)> {
        if self.last_used == self.used_idx() {
            return None;
        }
        fence(Ordering::SeqCst);
        unsafe {
            let ring = (self.used as usize + 4) as *const [u32; 2];
            let e = core::ptr::read_volatile(ring.add((self.last_used % self.size) as usize));
            self.last_used = self.last_used.wrapping_add(1);
            Some((e[0] as u16, e[1]))
        }
    }

    fn notify(&self, queue_idx: u16) {
        fence(Ordering::SeqCst);
        unsafe { core::ptr::write_volatile(self.notify, queue_idx) };
    }

    fn buf(&self, desc_id: u16) -> *mut u8 {
        (self.buf_base + desc_id as u64 * RX_BUF_LEN as u64) as *mut u8
    }
}

pub struct VirtioNet {
    common: u64,
    rx: Virtq,
    tx: Virtq,
    tx_free: alloc::vec::Vec<u16>, // free TX descriptor ids
    pub mac: [u8; 6],
}

#[inline]
fn c_r32(base: u64, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base as usize + off) as *const u32) }
}
#[inline]
fn c_w32(base: u64, off: usize, v: u32) {
    unsafe { core::ptr::write_volatile((base as usize + off) as *mut u32, v) }
}
#[inline]
fn c_r16(base: u64, off: usize) -> u16 {
    unsafe { core::ptr::read_volatile((base as usize + off) as *const u16) }
}
#[inline]
fn c_w16(base: u64, off: usize, v: u16) {
    unsafe { core::ptr::write_volatile((base as usize + off) as *mut u16, v) }
}
#[inline]
fn c_r8(base: u64, off: usize) -> u8 {
    unsafe { core::ptr::read_volatile((base as usize + off) as *const u8) }
}
#[inline]
fn c_w8(base: u64, off: usize, v: u8) {
    unsafe { core::ptr::write_volatile((base as usize + off) as *mut u8, v) }
}

fn setup_queue(common: u64, idx: u16, notify_base: u64, notify_mult: u32) -> Virtq {
    c_w16(common, QUEUE_SELECT, idx);
    let max = c_r16(common, QUEUE_SIZE_OFF);
    assert!(max > 0, "queue {idx} absent");
    let size = max.min(QUEUE_SIZE);
    c_w16(common, QUEUE_SIZE_OFF, size);

    // Ring memory: desc (16*size), avail (6+2*size), used (6+8*size), each in
    // its own page run for alignment simplicity; identity DMA (PA == VA).
    let desc_pages = (16 * size as usize).div_ceil(4096);
    let avail_pages = (6 + 2 * size as usize).div_ceil(4096);
    let used_pages = (6 + 8 * size as usize).div_ceil(4096);
    let desc = frames::alloc_contig(desc_pages, 1).expect("vq desc");
    let avail = frames::alloc_contig(avail_pages, 1).expect("vq avail");
    let used = frames::alloc_contig(used_pages, 1).expect("vq used");
    let bufs = frames::alloc_contig(
        (size as usize * RX_BUF_LEN as usize).div_ceil(4096),
        1,
    )
    .expect("vq buffers");

    unsafe {
        core::ptr::write_volatile((common as usize + QUEUE_DESC) as *mut u64, desc);
        core::ptr::write_volatile((common as usize + QUEUE_DRIVER) as *mut u64, avail);
        core::ptr::write_volatile((common as usize + QUEUE_DEVICE) as *mut u64, used);
    }
    let notify_off = c_r16(common, QUEUE_NOTIFY_OFF);
    c_w16(common, QUEUE_ENABLE, 1);

    Virtq {
        size,
        desc: desc as *mut Desc,
        avail: avail as *mut u16,
        used: used as *mut u8,
        notify: (notify_base + notify_off as u64 * notify_mult as u64) as *mut u16,
        buf_base: bufs,
        avail_shadow: 0,
        last_used: 0,
    }
}

impl VirtioNet {
    /// Full VirtIO 1.0 modern init handshake on the given ECAM.
    pub fn init(ecam: &Ecam) -> Option<VirtioNet> {
        // 0x1041 = virtio-net modern; skip the virtio-blk boot disk (0x1042).
        let dev: Device = ecam.find(0x1af4, 0x1041)?;
        dev.enable();

        let caps = dev.virtio_caps();
        let (common_cap, notify_cap, device_cap) = (&caps[1], &caps[2], &caps[4]);
        assert!(
            common_cap.present && notify_cap.present && device_cap.present,
            "virtio caps missing"
        );
        let common = dev.map_cap(common_cap);
        let notify_base = dev.map_cap(notify_cap);
        let device_cfg = dev.map_cap(device_cap);

        // Reset, then ACKNOWLEDGE -> DRIVER.
        c_w8(common, DEVICE_STATUS, 0);
        while c_r8(common, DEVICE_STATUS) != 0 {}
        c_w8(common, DEVICE_STATUS, ACKNOWLEDGE);
        c_w8(common, DEVICE_STATUS, ACKNOWLEDGE | DRIVER);

        // Features: low + high dwords.
        c_w32(common, DEV_FEATURE_SEL, 0);
        let f_lo = c_r32(common, DEV_FEATURE) as u64;
        c_w32(common, DEV_FEATURE_SEL, 1);
        let f_hi = (c_r32(common, DEV_FEATURE) as u64) << 32;
        let offered = f_lo | f_hi;
        let wanted = F_VERSION_1 | (offered & (F_MAC | F_STATUS));
        assert!(offered & F_VERSION_1 != 0, "legacy-only device");
        c_w32(common, DRV_FEATURE_SEL, 0);
        c_w32(common, DRV_FEATURE, wanted as u32);
        c_w32(common, DRV_FEATURE_SEL, 1);
        c_w32(common, DRV_FEATURE, (wanted >> 32) as u32);

        c_w8(common, DEVICE_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK);
        assert!(
            c_r8(common, DEVICE_STATUS) & FEATURES_OK != 0,
            "FEATURES_OK rejected"
        );

        let mut rx = setup_queue(common, 0, notify_base, notify_cap.notify_mult);
        let tx = setup_queue(common, 1, notify_base, notify_cap.notify_mult);

        c_w8(
            common,
            DEVICE_STATUS,
            ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
        );

        // MAC from device config (F_MAC was offered by QEMU and OCI).
        let mut mac = [0u8; 6];
        for (i, b) in mac.iter_mut().enumerate() {
            *b = c_r8(device_cfg, i);
        }

        // Pre-post every RX descriptor.
        for i in 0..rx.size {
            unsafe {
                rx.desc.add(i as usize).write(Desc {
                    addr: rx.buf_base + i as u64 * RX_BUF_LEN as u64,
                    len: RX_BUF_LEN,
                    flags: DESC_F_WRITE,
                    next: 0,
                });
            }
            rx.push_avail(i);
        }
        rx.notify(0);

        Some(VirtioNet {
            common,
            rx,
            tx_free: (0..tx.size).collect(),
            tx,
            mac,
        })
    }

    /// Receive one frame (without the virtio header) into `out`.
    /// Non-blocking; returns the frame length.
    pub fn recv(&mut self, out: &mut [u8]) -> Option<usize> {
        let (id, len) = self.rx.pop_used()?;
        let total = len as usize;
        let n = total.saturating_sub(VIRTIO_NET_HDR_LEN).min(out.len());
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.rx.buf(id).add(VIRTIO_NET_HDR_LEN),
                out.as_mut_ptr(),
                n,
            );
        }
        // Repost the descriptor.
        self.rx.push_avail(id);
        self.rx.notify(0);
        Some(n)
    }

    /// Transmit one Ethernet frame (virtio header added here). Returns false
    /// if the TX ring is momentarily full.
    pub fn send(&mut self, frame: &[u8]) -> bool {
        // Reclaim completed TX descriptors into the free list.
        while let Some((id, _)) = self.tx.pop_used() {
            self.tx_free.push(id);
        }
        assert!(frame.len() + VIRTIO_NET_HDR_LEN <= RX_BUF_LEN as usize);
        let Some(id) = self.tx_free.pop() else {
            return false;
        };
        let buf = self.tx.buf(id);
        unsafe {
            core::ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_LEN); // zeroed hdr
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                buf.add(VIRTIO_NET_HDR_LEN),
                frame.len(),
            );
            self.tx.desc.add(id as usize).write(Desc {
                addr: self.tx.buf_base + id as u64 * RX_BUF_LEN as u64,
                len: (frame.len() + VIRTIO_NET_HDR_LEN) as u32,
                flags: 0,
                next: 0,
            });
        }
        self.tx.push_avail(id);
        self.tx.notify(1);
        true
    }

    pub fn link_up(&self) -> bool {
        // F_STATUS negotiated on QEMU/OCI; assume up if not readable.
        let _ = self.common;
        true
    }
}

impl crate::net::stack::L2Device for VirtioNet {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn send(&mut self, frame: &[u8]) -> bool {
        VirtioNet::send(self, frame)
    }
    fn recv(&mut self, out: &mut [u8]) -> Option<usize> {
        VirtioNet::recv(self, out)
    }
}
