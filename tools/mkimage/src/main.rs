//! mkimage — build a bootable disk image without mtools or sudo.
//!
//! Layout: Protective MBR + GPT + one 64 MiB FAT32 EFI System Partition
//! containing \EFI\BOOT\BOOTAA64.EFI, then `qemu-img convert` to qcow2.
//!
//! Usage: mkimage <BOOTAA64.EFI> <out.qcow2>

use std::env;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::process::Command;

const SECTOR: u64 = 512;
const DISK_SECTORS: u64 = 2 * 1024 * 1024; // 1 GiB virtual disk
const ESP_START: u64 = 2048; // 1 MiB aligned
// 64 MiB ESP: FAT32 requires >= 65,525 clusters; at 1 sector/cluster this
// gives ~129k clusters — comfortably valid (PLAN.md §2.1).
const ESP_SECTORS: u64 = 131072;

const GPT_ENTRIES: u32 = 128;
const GPT_ENTRY_SIZE: u32 = 128;
const GPT_ENTRY_SECTORS: u64 = (GPT_ENTRIES as u64 * GPT_ENTRY_SIZE as u64) / SECTOR; // 32

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// On-disk GUID encoding: first three fields little-endian, rest verbatim.
fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&d1.to_le_bytes());
    g[4..6].copy_from_slice(&d2.to_le_bytes());
    g[6..8].copy_from_slice(&d3.to_le_bytes());
    g[8..16].copy_from_slice(&d4);
    g
}

fn esp_type_guid() -> [u8; 16] {
    guid(
        0xC12A_7328,
        0xF81F,
        0x11D2,
        [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
    )
}

// Fixed GUIDs → bit-reproducible images.
fn disk_guid() -> [u8; 16] {
    guid(
        0xDEA2_05DE,
        0x0001,
        0x4000,
        [0x8E, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    )
}

fn part_guid() -> [u8; 16] {
    guid(
        0xDEA2_05DE,
        0x0002,
        0x4000,
        [0x8E, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
}

fn write_at(f: &mut File, lba: u64, data: &[u8]) {
    f.seek(SeekFrom::Start(lba * SECTOR)).unwrap();
    f.write_all(data).unwrap();
}

fn protective_mbr() -> [u8; 512] {
    let mut s = [0u8; 512];
    let e = &mut s[446..462];
    e[0] = 0x00; // status
    e[1] = 0x00;
    e[2] = 0x02;
    e[3] = 0x00; // CHS first
    e[4] = 0xEE; // protective GPT
    e[5] = 0xFF;
    e[6] = 0xFF;
    e[7] = 0xFF; // CHS last
    e[8..12].copy_from_slice(&1u32.to_le_bytes());
    e[12..16].copy_from_slice(&((DISK_SECTORS - 1).min(0xFFFF_FFFF) as u32).to_le_bytes());
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

fn gpt_entries() -> Vec<u8> {
    let mut entries = vec![0u8; (GPT_ENTRIES * GPT_ENTRY_SIZE) as usize];
    let e = &mut entries[0..128];
    e[0..16].copy_from_slice(&esp_type_guid());
    e[16..32].copy_from_slice(&part_guid());
    e[32..40].copy_from_slice(&ESP_START.to_le_bytes());
    e[40..48].copy_from_slice(&(ESP_START + ESP_SECTORS - 1).to_le_bytes());
    // attributes = 0
    let name: Vec<u8> = "EFI System"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    e[56..56 + name.len()].copy_from_slice(&name);
    entries
}

fn gpt_header(current: u64, backup: u64, entries_lba: u64, entries_crc: u32) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[0..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // rev 1.0
    h[12..16].copy_from_slice(&92u32.to_le_bytes());
    // crc32 @16 filled below
    h[24..32].copy_from_slice(&current.to_le_bytes());
    h[32..40].copy_from_slice(&backup.to_le_bytes());
    h[40..48].copy_from_slice(&(2 + GPT_ENTRY_SECTORS).to_le_bytes()); // first usable
    h[48..56].copy_from_slice(&(DISK_SECTORS - 2 - GPT_ENTRY_SECTORS).to_le_bytes()); // last usable
    h[56..72].copy_from_slice(&disk_guid());
    h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    h[80..84].copy_from_slice(&GPT_ENTRIES.to_le_bytes());
    h[84..88].copy_from_slice(&GPT_ENTRY_SIZE.to_le_bytes());
    h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let crc = crc32(&h[0..92]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    h
}

// ---------------------------------------------------------------- FAT32 ----

struct Fat32 {
    rsvd: u32,
    fatsz: u32, // sectors per FAT
    clusters: u32,
}

fn fat32_geometry() -> Fat32 {
    let total = ESP_SECTORS as u32;
    let rsvd = 32u32;
    // 1 sector/cluster; iterate FAT size to a fixpoint.
    let mut fatsz = 1024u32;
    for _ in 0..8 {
        let clusters = total - rsvd - 2 * fatsz;
        let need = ((clusters as u64 + 2) * 4).div_ceil(SECTOR) as u32;
        if need == fatsz {
            break;
        }
        fatsz = need;
    }
    let clusters = total - rsvd - 2 * fatsz;
    assert!(clusters >= 65_525, "not FAT32: {clusters} clusters");
    Fat32 {
        rsvd,
        fatsz,
        clusters,
    }
}

fn boot_sector(g: &Fat32) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[0] = 0xEB;
    s[1] = 0x58;
    s[2] = 0x90;
    s[3..11].copy_from_slice(b"MKIMAGE ");
    s[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes/sector
    s[13] = 1; // sectors/cluster
    s[14..16].copy_from_slice(&(g.rsvd as u16).to_le_bytes());
    s[16] = 2; // num FATs
    // root entries / totsec16 / fatsz16 = 0 for FAT32
    s[21] = 0xF8; // media
    s[24..26].copy_from_slice(&32u16.to_le_bytes()); // sectors/track
    s[26..28].copy_from_slice(&64u16.to_le_bytes()); // heads
    s[28..32].copy_from_slice(&(ESP_START as u32).to_le_bytes()); // hidden
    s[32..36].copy_from_slice(&(ESP_SECTORS as u32).to_le_bytes()); // totsec32
    s[36..40].copy_from_slice(&g.fatsz.to_le_bytes()); // fatsz32
    // ext_flags=0 (mirrored), fs_ver=0
    s[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
    s[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo sector
    s[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup boot sector
    s[64] = 0x80; // drive number
    s[66] = 0x29; // extended boot signature
    s[67..71].copy_from_slice(&0xDEA0_05u32.to_le_bytes()); // volume id
    s[71..82].copy_from_slice(b"DEANOS     ");
    s[82..90].copy_from_slice(b"FAT32   ");
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

fn fsinfo_sector(free: u32, next_free: u32) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    s[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    s[488..492].copy_from_slice(&free.to_le_bytes());
    s[492..496].copy_from_slice(&next_free.to_le_bytes());
    s[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
    s
}

fn dirent(name11: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..11].copy_from_slice(name11);
    e[11] = attr;
    e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

const ATTR_DIR: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_VOLUME_ID: u8 = 0x08;
const EOC: u32 = 0x0FFF_FFFF;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: mkimage <BOOTAA64.EFI> <out.qcow2>");
        std::process::exit(2);
    }
    let efi = fs::read(&args[1]).expect("read EFI binary");
    let out_qcow2 = &args[2];
    let raw_path = format!("{out_qcow2}.raw");

    let g = fat32_geometry();
    let file_clusters = (efi.len() as u64).div_ceil(SECTOR) as u32;
    // Cluster map: 2=root dir, 3=\EFI, 4=\EFI\BOOT, 5.. = BOOTAA64.EFI
    let first_file_cluster = 5u32;
    assert!(first_file_cluster + file_clusters <= g.clusters + 2);

    let mut f = File::create(&raw_path).expect("create raw image");

    // --- GPT ---
    write_at(&mut f, 0, &protective_mbr());
    let entries = gpt_entries();
    let ecrc = crc32(&entries);
    write_at(&mut f, 2, &entries);
    write_at(&mut f, 1, &gpt_header(1, DISK_SECTORS - 1, 2, ecrc));
    let backup_entries_lba = DISK_SECTORS - 1 - GPT_ENTRY_SECTORS;
    write_at(&mut f, backup_entries_lba, &entries);
    write_at(
        &mut f,
        DISK_SECTORS - 1,
        &gpt_header(DISK_SECTORS - 1, 1, backup_entries_lba, ecrc),
    );

    // --- FAT32 ESP ---
    let p = |rel: u64| ESP_START + rel; // partition-relative LBA -> disk LBA
    let bs = boot_sector(&g);
    let used = 3 + file_clusters; // root, EFI, BOOT + file
    let fsi = fsinfo_sector(g.clusters - used, first_file_cluster + file_clusters);
    write_at(&mut f, p(0), &bs);
    write_at(&mut f, p(1), &fsi);
    write_at(&mut f, p(6), &bs); // backup boot region
    write_at(&mut f, p(7), &fsi);

    // FAT (mirrored to both copies)
    let mut fat = vec![0u8; (g.fatsz as u64 * SECTOR) as usize];
    let mut set = |fat: &mut Vec<u8>, i: u32, v: u32| {
        let o = i as usize * 4;
        fat[o..o + 4].copy_from_slice(&v.to_le_bytes());
    };
    set(&mut fat, 0, 0x0FFF_FFF8);
    set(&mut fat, 1, EOC);
    set(&mut fat, 2, EOC); // root dir
    set(&mut fat, 3, EOC); // \EFI
    set(&mut fat, 4, EOC); // \EFI\BOOT
    for i in 0..file_clusters {
        let c = first_file_cluster + i;
        let next = if i == file_clusters - 1 { EOC } else { c + 1 };
        set(&mut fat, c, next);
    }
    write_at(&mut f, p(g.rsvd as u64), &fat);
    write_at(&mut f, p((g.rsvd + g.fatsz) as u64), &fat);

    // Directories (1 cluster = 1 sector = 16 entries)
    let data_start = (g.rsvd + 2 * g.fatsz) as u64;
    let cluster_lba = |c: u32| p(data_start + (c as u64 - 2));

    let mut root = [0u8; 512];
    root[0..32].copy_from_slice(&dirent(b"DEANOS     ", ATTR_VOLUME_ID, 0, 0));
    root[32..64].copy_from_slice(&dirent(b"EFI        ", ATTR_DIR, 3, 0));
    write_at(&mut f, cluster_lba(2), &root);

    let mut efi_dir = [0u8; 512];
    efi_dir[0..32].copy_from_slice(&dirent(b".          ", ATTR_DIR, 3, 0));
    efi_dir[32..64].copy_from_slice(&dirent(b"..         ", ATTR_DIR, 0, 0));
    efi_dir[64..96].copy_from_slice(&dirent(b"BOOT       ", ATTR_DIR, 4, 0));
    write_at(&mut f, cluster_lba(3), &efi_dir);

    let mut boot_dir = [0u8; 512];
    boot_dir[0..32].copy_from_slice(&dirent(b".          ", ATTR_DIR, 4, 0));
    boot_dir[32..64].copy_from_slice(&dirent(b"..         ", ATTR_DIR, 3, 0));
    boot_dir[64..96].copy_from_slice(&dirent(
        b"BOOTAA64EFI",
        ATTR_ARCHIVE,
        first_file_cluster,
        efi.len() as u32,
    ));
    write_at(&mut f, cluster_lba(4), &boot_dir);

    // File data
    write_at(&mut f, cluster_lba(first_file_cluster), &efi);

    // Force full virtual size (sparse on disk).
    f.set_len(DISK_SECTORS * SECTOR).unwrap();
    f.sync_all().unwrap();
    drop(f);

    let status = Command::new("qemu-img")
        .args(["convert", "-f", "raw", "-O", "qcow2", &raw_path, out_qcow2])
        .status()
        .expect("run qemu-img");
    assert!(status.success(), "qemu-img convert failed");
    fs::remove_file(&raw_path).ok();
    println!(
        "mkimage: {out_qcow2} ({} KiB EFI payload, {} FAT clusters)",
        efi.len() / 1024,
        g.clusters
    );
}
