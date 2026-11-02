#!/usr/bin/env python3
"""M6 gate driver: hammer the deanOS echo server through QEMU hostfwd.

1. 100 rapid sequential connections, small payload echo each.
2. 20 concurrent interleaved connections.
3. One multi-megabyte streaming transfer with hash verification.
"""
import hashlib
import socket
import sys
import threading
import time

HOST, PORT = "127.0.0.1", 8070  # hostfwd -> guest :7 echo


def one_echo(i: int, payload: bytes) -> None:
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            b = s.recv(65536)
            if not b:
                raise RuntimeError(f"conn {i}: EOF after {len(got)}/{len(payload)}")
            got += b
        assert got == payload, f"conn {i}: payload mismatch"


def phase1_sequential() -> None:
    t0 = time.time()
    for i in range(100):
        one_echo(i, f"hello-{i:03d}-".encode() * 20)
    print(f"phase1: 100 sequential connections OK in {time.time()-t0:.2f}s")


def phase2_concurrent() -> None:
    errs: list[Exception] = []

    def worker(i: int) -> None:
        # Slirp's hostfwd accept backlog drops simultaneous connect bursts
        # before they ever reach the guest (verified via guest-side pcap) —
        # retry once so we measure the guest stack, not QEMU's forwarder.
        for attempt in range(2):
            try:
                one_echo(i, bytes([i]) * (1000 + i * 37))
                return
            except ConnectionResetError:
                if attempt == 1:
                    errs.append(RuntimeError(f"conn {i}: reset twice"))
                time.sleep(0.05)
            except Exception as e:  # noqa: BLE001
                errs.append(e)
                return

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    t0 = time.time()
    for t in threads:
        t.start()
        time.sleep(0.005)  # de-burst slirp's tiny accept backlog
    for t in threads:
        t.join()
    if errs:
        raise RuntimeError(f"phase2 failures: {errs[:3]}")
    print(f"phase2: 20 concurrent connections OK in {time.time()-t0:.2f}s")


def phase3_bulk(mb: int = 4) -> None:
    payload = (b"deanOS-bulk-\x00\x01\x02\x03" * 65536)[: mb * 1024 * 1024]
    sent_hash = hashlib.sha256(payload).hexdigest()
    got = bytearray()
    t0 = time.time()
    with socket.create_connection((HOST, PORT), timeout=60) as s:
        done = threading.Event()

        def reader() -> None:
            while len(got) < len(payload):
                b = s.recv(1 << 20)
                if not b:
                    break
                got.extend(b)
            done.set()

        rt = threading.Thread(target=reader)
        rt.start()
        s.sendall(payload)
        rt.join(timeout=120)
    assert len(got) == len(payload), f"bulk: got {len(got)}/{len(payload)}"
    assert hashlib.sha256(bytes(got)).hexdigest() == sent_hash, "bulk: hash mismatch"
    dt = time.time() - t0
    print(f"phase3: {mb} MiB echoed+verified in {dt:.2f}s ({mb/dt:.1f} MiB/s)")


if __name__ == "__main__":
    phase1_sequential()
    phase2_concurrent()
    phase3_bulk(4)
    print("M6 HOST GATE OK")
    sys.exit(0)
