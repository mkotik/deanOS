//! Hardware-independent TCP/IP stack (PLAN.md §2.6).
//!
//! IMPORTANT: modules under net/ (and http/) reference ONLY core, alloc, and
//! each other — never crate::drivers or crate::arch. The same source files are
//! compiled by tools/netharness on the host for `cargo test`.

pub mod arp;
pub mod dhcp;
pub mod icmp;
pub mod ipv4;
pub mod ring;
pub mod stack;
pub mod tcp;
pub mod wire;
