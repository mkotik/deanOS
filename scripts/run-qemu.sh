#!/bin/sh
# Build BOOTAA64.EFI + deanos.qcow2 and launch QEMU.
#
# Flags:
#   --el2       boot firmware at EL2 (virtualization=on) to exercise the EL2->EL1 drop
#   --tcg       use TCG instead of hvf (works in sandboxes/CI; -cpu max)
#   --headless  no interactive console; serial to target/serial.log
#   --net-vmnet use vmnet-shared (real L2, inbound ICMP; requires sudo)
set -e
cd "$(dirname "$0")/.."

# kernel-irqchip=off: Apple's in-kernel vGIC has no ITS; the emulated GICv3
# keeps MSI-X parity with OCI (verified: hvf+hw-vGIC rejects its=on).
MACHINE="virt,gic-version=3,its=on,kernel-irqchip=off"
ACCEL="-cpu host -accel hvf"
SERIAL="-nographic"
NETDEV="-netdev user,id=net0,hostfwd=tcp::8080-:80"

for arg in "$@"; do
  case "$arg" in
    --el2) MACHINE="$MACHINE,virtualization=on" ;;
    --tcg) ACCEL="-cpu max -accel tcg" ;;
    --headless) SERIAL="-display none -serial file:target/serial.log" ;;
    --net-vmnet) NETDEV="-netdev vmnet-shared,id=net0" ;;
  esac
done

cargo build --release -p kernel --target aarch64-unknown-uefi
cargo build --release -p mkimage
./target/release/mkimage \
  target/aarch64-unknown-uefi/release/kernel.efi target/deanos.qcow2

exec qemu-system-aarch64 \
  -M "$MACHINE" \
  $ACCEL -m 512M $SERIAL \
  -bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
  -drive if=virtio,format=qcow2,file=target/deanos.qcow2 \
  $NETDEV \
  -device virtio-net-pci,netdev=net0,disable-legacy=on
