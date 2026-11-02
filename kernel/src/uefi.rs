//! Raw UEFI FFI: just enough of the 2.x spec to print, locate configuration
//! tables, query LoadedImage, and perform the GetMemoryMap/ExitBootServices
//! handoff. All layouts follow the UEFI 2.10 spec field order exactly.

use core::ffi::c_void;
use core::fmt;

pub type Status = usize;
pub type Handle = *mut c_void;

pub const STATUS_SUCCESS: Status = 0;
const ERR_BIT: usize = 1 << 63;
pub const STATUS_BUFFER_TOO_SMALL: Status = ERR_BIT | 5;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);

pub const ACPI_20_TABLE_GUID: Guid = Guid(
    0x8868_e871,
    0xe4f1,
    0x11d3,
    [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);

pub const LOADED_IMAGE_PROTOCOL_GUID: Guid = Guid(
    0x5b1b_31a1,
    0x9562,
    0x11d2,
    [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SimpleTextOutput {
    reset: extern "efiapi" fn(*mut SimpleTextOutput, u8) -> Status,
    output_string: extern "efiapi" fn(*mut SimpleTextOutput, *const u16) -> Status,
    // remaining members unused
}

#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *mut c_void,
}

#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut c_void,
    pub console_out_handle: Handle,
    pub con_out: *mut SimpleTextOutput,
    pub standard_error_handle: Handle,
    pub std_err: *mut c_void,
    pub runtime_services: *mut c_void,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *mut ConfigurationTable,
}

#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,
    raise_tpl: usize,
    restore_tpl: usize,
    allocate_pages: usize,
    free_pages: usize,
    get_memory_map: extern "efiapi" fn(
        *mut usize, // MemoryMapSize (in/out)
        *mut u8,    // MemoryMap
        *mut usize, // MapKey
        *mut usize, // DescriptorSize
        *mut u32,   // DescriptorVersion
    ) -> Status,
    allocate_pool: extern "efiapi" fn(u32, usize, *mut *mut u8) -> Status,
    free_pool: extern "efiapi" fn(*mut u8) -> Status,
    create_event: usize,
    set_timer: usize,
    wait_for_event: usize,
    signal_event: usize,
    close_event: usize,
    check_event: usize,
    install_protocol_interface: usize,
    reinstall_protocol_interface: usize,
    uninstall_protocol_interface: usize,
    handle_protocol: extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    reserved: usize,
    register_protocol_notify: usize,
    locate_handle: usize,
    locate_device_path: usize,
    install_configuration_table: usize,
    load_image: usize,
    start_image: usize,
    exit: usize,
    unload_image: usize,
    exit_boot_services: extern "efiapi" fn(Handle, usize) -> Status,
    // remaining members unused
}

#[repr(C)]
pub struct LoadedImage {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    pub file_path: *mut c_void,
    pub reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

const EFI_LOADER_DATA: u32 = 2;

/// UEFI memory descriptor (fixed prefix; firmware's DescriptorSize may be
/// larger — always advance by the reported size, never size_of::<Self>()).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryDescriptor {
    pub typ: u32,
    pub pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

pub const MEM_TYPE_NAMES: [&str; 15] = [
    "Reserved",
    "LoaderCode",
    "LoaderData",
    "BootServicesCode",
    "BootServicesData",
    "RuntimeServicesCode",
    "RuntimeServicesData",
    "Conventional",
    "Unusable",
    "AcpiReclaim",
    "AcpiNvs",
    "Mmio",
    "MmioPortSpace",
    "PalCode",
    "Persistent",
];

/// Snapshot of the final UEFI memory map, valid after ExitBootServices. The
/// buffer lives in EfiLoaderData, which the M2 frame allocator preserves.
pub struct MemoryMapInfo {
    pub buf: *mut u8,
    pub size: usize,
    pub desc_size: usize,
    pub desc_version: u32,
}

impl MemoryMapInfo {
    pub const fn empty() -> Self {
        MemoryMapInfo {
            buf: core::ptr::null_mut(),
            size: 0,
            desc_size: 0,
            desc_version: 0,
        }
    }

    pub fn iter(&self) -> MemoryMapIter {
        MemoryMapIter {
            cur: self.buf,
            end: unsafe { self.buf.add(self.size) },
            desc_size: self.desc_size,
        }
    }
}

pub struct MemoryMapIter {
    cur: *mut u8,
    end: *mut u8,
    desc_size: usize,
}

impl Iterator for MemoryMapIter {
    type Item = MemoryDescriptor;
    fn next(&mut self) -> Option<MemoryDescriptor> {
        if self.cur.is_null() || unsafe { self.cur.add(self.desc_size) } > self.end {
            return None;
        }
        let d = unsafe { core::ptr::read_unaligned(self.cur as *const MemoryDescriptor) };
        self.cur = unsafe { self.cur.add(self.desc_size) };
        Some(d)
    }
}

/// `core::fmt::Write` adapter over SimpleTextOutput (pre-ExitBootServices only).
pub struct ConOut(pub *mut SimpleTextOutput);

impl fmt::Write for ConOut {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // UCS-2 chunk conversion; '\n' needs a preceding '\r' on UEFI consoles.
        let mut buf = [0u16; 65];
        let mut i = 0;
        let flush = |buf: &mut [u16; 65], i: &mut usize| {
            buf[*i] = 0;
            unsafe { ((*self.0).output_string)(self.0, buf.as_ptr()) };
            *i = 0;
        };
        for c in s.chars() {
            if i >= 62 {
                flush(&mut buf, &mut i);
            }
            if c == '\n' {
                buf[i] = b'\r' as u16;
                i += 1;
            }
            buf[i] = if (c as u32) < 0x1_0000 { c as u16 } else { b'?' as u16 };
            i += 1;
        }
        if i > 0 {
            flush(&mut buf, &mut i);
        }
        Ok(())
    }
}

/// Find a vendor table in the configuration table array by GUID.
pub unsafe fn find_config_table(st: &SystemTable, guid: &Guid) -> Option<*mut c_void> {
    for i in 0..st.number_of_table_entries {
        let entry = &*st.configuration_table.add(i);
        if entry.vendor_guid == *guid {
            return Some(entry.vendor_table);
        }
    }
    None
}

/// Query EFI_LOADED_IMAGE_PROTOCOL for our own PE image base + size.
/// MUST run before ExitBootServices — the protocol database dies with it.
pub unsafe fn loaded_image_extent(st: &SystemTable, image: Handle) -> Option<(u64, u64)> {
    let bs = &*st.boot_services;
    let mut iface: *mut c_void = core::ptr::null_mut();
    if (bs.handle_protocol)(image, &LOADED_IMAGE_PROTOCOL_GUID, &mut iface) != STATUS_SUCCESS {
        return None;
    }
    let li = &*(iface as *const LoadedImage);
    Some((li.image_base as u64, li.image_size))
}

/// GetMemoryMap → ExitBootServices retry loop (PLAN.md §2.3 step 1).
///
/// The buffer is allocated once, oversized, while allocation is still legal.
/// Between the final GetMemoryMap and ExitBootServices NOTHING may allocate —
/// including console printing — or the map key goes stale. On a stale-key
/// failure only these two calls remain legal, so we simply loop.
pub unsafe fn exit_boot_services(st: &SystemTable, image: Handle) -> Option<MemoryMapInfo> {
    let bs = &*st.boot_services;

    let mut size = 0usize;
    let mut key = 0usize;
    let mut desc_size = 0usize;
    let mut desc_version = 0u32;
    let s = (bs.get_memory_map)(
        &mut size,
        core::ptr::null_mut(),
        &mut key,
        &mut desc_size,
        &mut desc_version,
    );
    if s != STATUS_BUFFER_TOO_SMALL {
        return None;
    }
    // Headroom: the pool allocation below plus ExitBootServices-internal
    // bookkeeping can add descriptors between calls.
    size += 8 * desc_size.max(48) + 4096;
    let mut buf: *mut u8 = core::ptr::null_mut();
    if (bs.allocate_pool)(EFI_LOADER_DATA, size, &mut buf) != STATUS_SUCCESS {
        return None;
    }

    let cap = size;
    for _ in 0..8 {
        size = cap;
        if (bs.get_memory_map)(&mut size, buf, &mut key, &mut desc_size, &mut desc_version)
            != STATUS_SUCCESS
        {
            return None;
        }
        if (bs.exit_boot_services)(image, key) == STATUS_SUCCESS {
            return Some(MemoryMapInfo {
                buf,
                size,
                desc_size,
                desc_version,
            });
        }
    }
    None
}
