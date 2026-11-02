//! PCIe ECAM enumeration + capability parsing (MCFG-discovered, no AML).

use crate::mm::paging;

pub struct Ecam {
    base: u64,
    bus_start: u8,
    bus_end: u8,
}

#[derive(Clone, Copy)]
pub struct Device {
    pub cfg: u64, // ECAM config-space base for this function
    pub vendor: u16,
    pub device: u16,
}

/// A parsed virtio modern capability (vendor cap 0x09).
#[derive(Clone, Copy, Default)]
pub struct VirtioCap {
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
    pub notify_mult: u32, // notify cap only
    pub present: bool,
}

impl Ecam {
    pub fn new(base: u64, bus_start: u8, bus_end: u8) -> Self {
        Ecam {
            base,
            bus_start,
            bus_end,
        }
    }

    fn cfg_addr(&self, bus: u8, dev: u8, func: u8) -> u64 {
        self.base
            + (((bus - self.bus_start) as u64) << 20)
            + ((dev as u64) << 15)
            + ((func as u64) << 12)
    }

    /// Find the first function matching vendor:device.
    pub fn find(&self, vendor: u16, device: u16) -> Option<Device> {
        for bus in self.bus_start..=self.bus_end {
            for dev in 0..32u8 {
                for func in 0..8u8 {
                    let cfg = self.cfg_addr(bus, dev, func);
                    let id = r32(cfg, 0x00);
                    if id == 0xffff_ffff {
                        if func == 0 {
                            break; // no device, skip other functions
                        }
                        continue;
                    }
                    let (v, d) = ((id & 0xffff) as u16, (id >> 16) as u16);
                    if v == vendor && d == device {
                        return Some(Device { cfg, vendor: v, device: d });
                    }
                    // Non-multifunction device: don't probe funcs 1..7.
                    if func == 0 && r32(cfg, 0x0c) & 0x0080_0000 == 0 {
                        break;
                    }
                }
            }
        }
        None
    }
}

#[inline]
pub fn r32(cfg: u64, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((cfg as usize + off) as *const u32) }
}
#[inline]
pub fn w32(cfg: u64, off: usize, v: u32) {
    unsafe { core::ptr::write_volatile((cfg as usize + off) as *mut u32, v) }
}
#[inline]
pub fn r16(cfg: u64, off: usize) -> u16 {
    unsafe { core::ptr::read_volatile((cfg as usize + off) as *const u16) }
}
#[inline]
pub fn w16(cfg: u64, off: usize, v: u16) {
    unsafe { core::ptr::write_volatile((cfg as usize + off) as *mut u16, v) }
}
#[inline]
pub fn r8(cfg: u64, off: usize) -> u8 {
    unsafe { core::ptr::read_volatile((cfg as usize + off) as *const u8) }
}

impl Device {
    /// Read a (possibly 64-bit) memory BAR address. Assumes firmware assigned
    /// it (EDK2 does on both QEMU virt and OCI; we check and panic loudly).
    pub fn bar_addr(&self, idx: u8) -> u64 {
        let off = 0x10 + 4 * idx as usize;
        let lo = r32(self.cfg, off);
        assert!(lo & 1 == 0, "BAR{idx} is I/O space");
        let is64 = lo & 0b110 == 0b100;
        let mut addr = (lo & !0xf) as u64;
        if is64 {
            addr |= (r32(self.cfg, off + 4) as u64) << 32;
        }
        assert!(addr != 0, "BAR{idx} unassigned by firmware");
        addr
    }

    pub fn bar_size(&self, idx: u8) -> u64 {
        let off = 0x10 + 4 * idx as usize;
        let orig_lo = r32(self.cfg, off);
        let is64 = orig_lo & 0b110 == 0b100;
        w32(self.cfg, off, 0xffff_ffff);
        let mask_lo = r32(self.cfg, off);
        w32(self.cfg, off, orig_lo);
        let mut mask = (mask_lo & !0xf) as u64;
        if is64 {
            let orig_hi = r32(self.cfg, off + 4);
            w32(self.cfg, off + 4, 0xffff_ffff);
            mask |= (r32(self.cfg, off + 4) as u64) << 32;
            w32(self.cfg, off + 4, orig_hi);
        } else {
            mask |= 0xffff_ffff_0000_0000;
        }
        !mask + 1
    }

    /// Enable Memory Space + Bus Master decoding.
    pub fn enable(&self) {
        let cmd = r16(self.cfg, 0x04);
        w16(self.cfg, 0x04, cmd | 0b110);
    }

    /// Walk the capability list; collect virtio modern caps by cfg_type.
    /// Returns (common, notify, isr, device_cfg).
    pub fn virtio_caps(&self) -> [VirtioCap; 5] {
        let mut caps = [VirtioCap::default(); 5]; // indexed by cfg_type (1..=4)
        let status = r16(self.cfg, 0x06);
        if status & (1 << 4) == 0 {
            return caps; // no capability list
        }
        let mut ptr = r8(self.cfg, 0x34) as usize & !0x3;
        let mut guard = 0;
        while ptr != 0 && guard < 48 {
            guard += 1;
            let id = r8(self.cfg, ptr);
            if id == 0x09 {
                let cfg_type = r8(self.cfg, ptr + 3) as usize;
                if (1..=4).contains(&cfg_type) && !caps[cfg_type].present {
                    caps[cfg_type] = VirtioCap {
                        bar: r8(self.cfg, ptr + 4),
                        offset: r32(self.cfg, ptr + 8),
                        length: r32(self.cfg, ptr + 12),
                        notify_mult: if cfg_type == 2 { r32(self.cfg, ptr + 16) } else { 0 },
                        present: true,
                    };
                }
            }
            ptr = r8(self.cfg, ptr + 1) as usize & !0x3;
        }
        caps
    }

    /// Map the BAR backing a virtio cap and return the structure's VA (==PA).
    pub fn map_cap(&self, cap: &VirtioCap) -> u64 {
        let base = self.bar_addr(cap.bar);
        let size = self.bar_size(cap.bar);
        paging::map_device(base, size);
        base + cap.offset as u64
    }
}
