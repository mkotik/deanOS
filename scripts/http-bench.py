#!/usr/bin/env python3
"""M7 concurrent keep-alive benchmark: N workers, each M requests on one
persistent connection."""
import socket
import threading
import time

HOST, PORT = "127.0.0.1", 8080
WORKERS, REQS = 16, 100


def worker(i: int, errs: list) -> None:
    try:
        with socket.create_connection((HOST, PORT), timeout=15) as s:
            buf = b""
            for r in range(REQS):
                s.sendall(b"GET /health HTTP/1.1\r\nHost: deanos\r\n\r\n")
                # Read one complete response (Content-Length framing).
                while b"\r\n\r\n" not in buf:
                    buf += s.recv(65536)
                head, rest = buf.split(b"\r\n\r\n", 1)
                cl = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":")[1])
                while len(rest) < cl:
                    rest += s.recv(65536)
                body, buf = rest[:cl], rest[cl:]
                assert b'"status":"ok"' in body, f"worker {i} req {r}: {body!r}"
    except Exception as e:  # noqa: BLE001
        errs.append(f"worker {i}: {e}")


errs: list = []
threads = [threading.Thread(target=worker, args=(i, errs)) for i in range(WORKERS)]
t0 = time.time()
for t in threads:
    t.start()
    time.sleep(0.005)  # de-burst slirp accept backlog
for t in threads:
    t.join()
dt = time.time() - t0
total = WORKERS * REQS
if errs:
    raise SystemExit(f"FAIL: {errs[:5]}")
print(f"{total} keep-alive requests over {WORKERS} concurrent conns in {dt:.2f}s "
      f"({total/dt:.0f} req/s)")
print("M7 BENCH OK")
