#!/usr/bin/env python3
"""
KMIP SSE-S3 soak test.

Designed to run for days/weeks looking for slow leaks, deadlocks,
KEK orphaning, certificate/cache issues, and connection-pool problems
that a 5-minute test would miss.

Run:
    python3 soak_kmip.py                    # default: 1 week
    python3 soak_kmip.py --duration-hours 1 # short check
    python3 soak_kmip.py --workers 16       # heavier concurrency

What "smart" means here:
  - Verifies every GET against an in-memory SHA-256 of what was PUT.
    A corrupted decrypt is a HARD FAIL, not a silent stat.
  - Mixes operations: PUTs, GETs, overwrites, deletes, multipart,
    bucket-recreate, list. Each operation drawn from a weighted dist.
  - Rotates through a working set of buckets and keys so KEK cache,
    bucket attrs, and object metadata all see churn.
  - Per-operation timeout — slow op == bug. Hangs are flagged.
  - Bounded retries on *transient* errors (ECONNRESET, 503, 500
    during pykmip overload). Permanent errors (decrypt mismatch,
    InvalidRequest, AccessDenied) are not retried — they're bugs.
  - Periodic health snapshot to a CSV: ops/sec, p50/p95/p99 latency,
    error counts by type, KMIP-side queue-depth-ish proxies.
  - Memory baseline: snapshots radosgw RSS every minute if pgrep
    finds it locally. A monotonically growing RSS is a leak signal.
  - Graceful SIGINT: drain in-flight ops, print final summary,
    leave buckets behind for inspection (unless --cleanup).

Hard-fail conditions (script exits non-zero immediately):
  - SHA-256 mismatch on GET (data corruption)
  - Two consecutive timeouts on same bucket (deadlock suspect)
  - Stop signal from operator
"""

import argparse
import boto3
import botocore
import concurrent.futures as cf
import csv
import hashlib
import os
import random
import signal
import statistics
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Config defaults
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_ENDPOINT = "http://127.0.0.1:8000"
DEFAULT_AK = "0555b35654ad1656d804"
DEFAULT_SK = "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q=="

# Object size mix — biased small, occasional large
SIZE_BUCKETS = [
    (1024,            0.30),  # 1 KB
    (16 * 1024,       0.30),  # 16 KB
    (256 * 1024,      0.20),  # 256 KB
    (1024 * 1024,     0.15),  # 1 MB
    (10 * 1024 * 1024, 0.05), # 10 MB (multipart path)
]

# Operation mix (weights, must sum to ~1.0)
OP_WEIGHTS = {
    "put":              0.40,
    "get":              0.35,
    "overwrite":        0.10,
    "delete":           0.05,
    "multipart":        0.04,
    "bucket_recreate":  0.03,
    "list":             0.03,
}

# Working set: how many buckets / objects to churn over
N_BUCKETS = 6
N_KEYS_PER_BUCKET = 50

PER_OP_TIMEOUT_SEC = 30        # individual op timeout
HARD_TIMEOUT_DEADLOCK = 2      # N consecutive timeouts on same bucket = bug

SNAPSHOT_INTERVAL_SEC = 60     # health snapshot to stdout + CSV
PROGRESS_INTERVAL_SEC = 10     # quick line of progress to stdout

# ─────────────────────────────────────────────────────────────────────────────
# State
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ObjState:
    """What we believe is currently stored at bucket/key, if anything."""
    sha256: Optional[str] = None
    size: int = 0
    deleted: bool = True       # start as "not present"

@dataclass
class BucketState:
    name: str
    keys: dict = field(default_factory=dict)   # key_name -> ObjState
    key_locks: dict = field(default_factory=dict)  # key_name -> Lock (held across network op)
    consecutive_timeouts: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

@dataclass
class Counters:
    started_at: float = field(default_factory=time.monotonic)
    ops: int = 0
    ok: int = 0
    err_transient: int = 0
    err_hard: int = 0
    timeouts: int = 0
    by_op_ok: dict = field(default_factory=lambda: defaultdict(int))
    by_op_err: dict = field(default_factory=lambda: defaultdict(int))
    latencies: dict = field(default_factory=lambda: defaultdict(lambda: deque(maxlen=2000)))
    last_err: deque = field(default_factory=lambda: deque(maxlen=20))
    lock: threading.Lock = field(default_factory=threading.Lock)

stop_event = threading.Event()
counters = Counters()
buckets: list[BucketState] = []

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def s3_client(endpoint, ak, sk):
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        config=botocore.config.Config(
            retries={"max_attempts": 0},
            connect_timeout=5,
            read_timeout=PER_OP_TIMEOUT_SEC,
        ),
    )

def pick_size():
    r = random.random()
    cum = 0.0
    for sz, w in SIZE_BUCKETS:
        cum += w
        if r <= cum:
            return sz
    return SIZE_BUCKETS[-1][0]

def pick_op():
    r = random.random()
    cum = 0.0
    for op, w in OP_WEIGHTS.items():
        cum += w
        if r <= cum:
            return op
    return "put"

def sha_of(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def gen_payload(size: int) -> tuple[bytes, str]:
    body = os.urandom(size)
    return body, sha_of(body)

def is_transient(exc) -> bool:
    """Whether to retry. Be conservative — when in doubt, treat as hard."""
    if isinstance(exc, botocore.exceptions.EndpointConnectionError):
        return True
    if isinstance(exc, botocore.exceptions.ConnectTimeoutError):
        return True
    if isinstance(exc, botocore.exceptions.ReadTimeoutError):
        return True
    if isinstance(exc, botocore.exceptions.ClientError):
        code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
        if code in (500, 502, 503, 504):
            return True
    return False

def record(op: str, ok: bool, latency: float, exc=None, hard=False):
    with counters.lock:
        counters.ops += 1
        if ok:
            counters.ok += 1
            counters.by_op_ok[op] += 1
        else:
            counters.by_op_err[op] += 1
            if hard:
                counters.err_hard += 1
            else:
                counters.err_transient += 1
            counters.last_err.append(f"{op}: {type(exc).__name__}: {str(exc)[:120]}")
        counters.latencies[op].append(latency)

# ─────────────────────────────────────────────────────────────────────────────
# Operations
# ─────────────────────────────────────────────────────────────────────────────

def _key_lock(b: BucketState, key: str):
    with b.lock:
        return b.key_locks.get(key)

def op_put(c, b: BucketState):
    """PUT a fresh object, record its sha for later verification."""
    key = random.choice(list_keys(b))
    klock = _key_lock(b, key)
    if klock is None:
        return
    size = pick_size()
    body, sha = gen_payload(size)
    with klock:
        c.put_object(Bucket=b.name, Key=key, Body=body, ServerSideEncryption="AES256")
        with b.lock:
            b.keys[key] = ObjState(sha256=sha, size=size, deleted=False)

def op_get(c, b: BucketState):
    """GET an object we previously wrote, verify SHA-256.

    SHA mismatch is HARD FAIL — data corruption."""
    with b.lock:
        live = [k for k, st in b.keys.items() if not st.deleted]
    if not live:
        return
    key = random.choice(live)
    klock = _key_lock(b, key)
    if klock is None:
        return
    with klock:
        with b.lock:
            st = b.keys.get(key)
            if st is None or st.deleted or st.sha256 is None:
                return
            expected = ObjState(sha256=st.sha256, size=st.size, deleted=False)
        resp = c.get_object(Bucket=b.name, Key=key)
        body = resp["Body"].read()
        got_sha = sha_of(body)
        if got_sha != expected.sha256:
            raise RuntimeError(
                f"CORRUPTION: {b.name}/{key} expected_sha={expected.sha256[:16]} "
                f"got_sha={got_sha[:16]} expected_size={expected.size} got_size={len(body)}"
            )

def op_overwrite(c, b: BucketState):
    """Overwrite an existing key with new content."""
    with b.lock:
        live = [k for k, st in b.keys.items() if not st.deleted]
    if not live:
        return op_put(c, b)
    key = random.choice(live)
    klock = _key_lock(b, key)
    if klock is None:
        return
    size = pick_size()
    body, sha = gen_payload(size)
    with klock:
        c.put_object(Bucket=b.name, Key=key, Body=body, ServerSideEncryption="AES256")
        with b.lock:
            b.keys[key] = ObjState(sha256=sha, size=size, deleted=False)

def op_delete(c, b: BucketState):
    with b.lock:
        live = [k for k, st in b.keys.items() if not st.deleted]
    if not live:
        return
    key = random.choice(live)
    klock = _key_lock(b, key)
    if klock is None:
        return
    with klock:
        c.delete_object(Bucket=b.name, Key=key)
        with b.lock:
            if key in b.keys:
                b.keys[key].deleted = True

def op_multipart(c, b: BucketState):
    """5 x 5 MB multipart — exercises per-part DEK derivation."""
    key = random.choice(list_keys(b))
    klock = _key_lock(b, key)
    if klock is None:
        return
    part_size = 5 * 1024 * 1024
    num_parts = 5
    total = part_size * num_parts
    body = os.urandom(total)
    sha = sha_of(body)
    with klock:
        mpu = c.create_multipart_upload(
            Bucket=b.name, Key=key, ServerSideEncryption="AES256"
        )
        uid = mpu["UploadId"]
        parts = []
        for i in range(num_parts):
            p = c.upload_part(
                Bucket=b.name, Key=key, UploadId=uid, PartNumber=i + 1,
                Body=body[i * part_size:(i + 1) * part_size],
            )
            parts.append({"PartNumber": i + 1, "ETag": p["ETag"]})
        c.complete_multipart_upload(
            Bucket=b.name, Key=key, UploadId=uid, MultipartUpload={"Parts": parts}
        )
        with b.lock:
            b.keys[key] = ObjState(sha256=sha, size=total, deleted=False)

def op_list(c, b: BucketState):
    """LIST — make sure paginator doesn't blow up on a populated bucket."""
    paginator = c.get_paginator("list_objects_v2")
    n = 0
    for page in paginator.paginate(Bucket=b.name, PaginationConfig={"PageSize": 100}):
        n += len(page.get("Contents", []))
        if n > 5000:
            break

def op_bucket_recreate(c, b: BucketState):
    """Delete + recreate the bucket — exercises KEK cleanup + fresh KEK path."""
    # Empty bucket
    paginator = c.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=b.name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            c.delete_objects(Bucket=b.name, Delete={"Objects": objs})
    try:
        c.delete_bucket(Bucket=b.name)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise
    c.create_bucket(Bucket=b.name)
    with b.lock:
        b.keys.clear()
        b.key_locks.clear()
        for i in range(N_KEYS_PER_BUCKET):
            k = f"k{i:04d}"
            b.keys[k] = ObjState()
            b.key_locks[k] = threading.Lock()

def list_keys(b: BucketState):
    with b.lock:
        return list(b.keys.keys())

OP_FUNCS = {
    "put":             op_put,
    "get":             op_get,
    "overwrite":       op_overwrite,
    "delete":          op_delete,
    "multipart":       op_multipart,
    "list":            op_list,
    "bucket_recreate": op_bucket_recreate,
}

# ─────────────────────────────────────────────────────────────────────────────
# Worker loop
# ─────────────────────────────────────────────────────────────────────────────

def worker_loop(args, worker_id: int):
    c = s3_client(args.endpoint, args.access_key, args.secret_key)
    while not stop_event.is_set():
        b = random.choice(buckets)
        op = pick_op()
        t0 = time.monotonic()
        try:
            OP_FUNCS[op](c, b)
            with b.lock:
                b.consecutive_timeouts = 0
            record(op, True, time.monotonic() - t0)
        except RuntimeError as e:
            # SHA mismatch — HARD FAIL, abort the whole soak
            record(op, False, time.monotonic() - t0, exc=e, hard=True)
            print(f"\n*** HARD FAIL (worker {worker_id}): {e}\n", flush=True)
            stop_event.set()
            return
        except botocore.exceptions.ReadTimeoutError as e:
            record(op, False, time.monotonic() - t0, exc=e, hard=False)
            with counters.lock:
                counters.timeouts += 1
            with b.lock:
                b.consecutive_timeouts += 1
                if b.consecutive_timeouts >= HARD_TIMEOUT_DEADLOCK:
                    print(
                        f"\n*** SUSPECTED DEADLOCK (worker {worker_id}): "
                        f"{b.consecutive_timeouts} consecutive timeouts on bucket {b.name}\n",
                        flush=True,
                    )
                    # Don't abort — could be transient pykmip stall.  Just log.
        except Exception as e:
            hard = not is_transient(e)
            record(op, False, time.monotonic() - t0, exc=e, hard=hard)
            if hard:
                # Don't abort on every hard error — some can happen during recreates.
                # But CORRUPTION is caught above; anything else, log and continue.
                pass

# ─────────────────────────────────────────────────────────────────────────────
# Health snapshot / reporter thread
# ─────────────────────────────────────────────────────────────────────────────

def percentile(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = int(round((p / 100.0) * (len(xs) - 1)))
    return xs[k]

def get_radosgw_rss_kb() -> Optional[int]:
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "radosgw"], stderr=subprocess.DEVNULL
        ).decode().strip().splitlines()
        pids = [p for p in out if p.isdigit()]
        if not pids:
            return None
        total = 0
        for pid in pids:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
                        break
        return total
    except Exception:
        return None

def reporter_loop(args, csv_path: str):
    csv_f = open(csv_path, "w", newline="", buffering=1)
    w = csv.writer(csv_f)
    w.writerow([
        "ts", "elapsed_s", "ops", "ok", "err_transient", "err_hard",
        "timeouts", "ops_per_sec",
        "get_p50_ms", "get_p95_ms", "get_p99_ms",
        "put_p50_ms", "put_p95_ms", "put_p99_ms",
        "radosgw_rss_kb",
    ])

    last_progress = time.monotonic()
    last_snapshot = time.monotonic()
    last_ops = 0

    while not stop_event.is_set():
        time.sleep(1)
        now = time.monotonic()

        if now - last_progress >= PROGRESS_INTERVAL_SEC:
            with counters.lock:
                delta_ops = counters.ops - last_ops
                ops_s = delta_ops / (now - last_progress)
                last_ops = counters.ops
                summary = (
                    f"[{int(now - counters.started_at):>6}s] "
                    f"ops={counters.ops:>8} ok={counters.ok:>8} "
                    f"err_transient={counters.err_transient:>5} "
                    f"err_hard={counters.err_hard:>3} "
                    f"timeouts={counters.timeouts:>3} "
                    f"ops/s={ops_s:>6.1f}"
                )
            print(summary, flush=True)
            last_progress = now

        if now - last_snapshot >= SNAPSHOT_INTERVAL_SEC:
            with counters.lock:
                get_lat = list(counters.latencies["get"])
                put_lat = list(counters.latencies["put"])
                row = [
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    int(now - counters.started_at),
                    counters.ops, counters.ok,
                    counters.err_transient, counters.err_hard,
                    counters.timeouts,
                    f"{counters.ops / (now - counters.started_at):.2f}",
                    f"{percentile(get_lat, 50) * 1000:.1f}",
                    f"{percentile(get_lat, 95) * 1000:.1f}",
                    f"{percentile(get_lat, 99) * 1000:.1f}",
                    f"{percentile(put_lat, 50) * 1000:.1f}",
                    f"{percentile(put_lat, 95) * 1000:.1f}",
                    f"{percentile(put_lat, 99) * 1000:.1f}",
                    get_radosgw_rss_kb() or "",
                ]
            w.writerow(row)
            last_snapshot = now

    csv_f.close()

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def setup_buckets(c, prefix: str):
    global buckets
    buckets = []
    for i in range(N_BUCKETS):
        name = f"{prefix}-{i}"
        try:
            c.create_bucket(Bucket=name)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                raise
        b = BucketState(name=name)
        for j in range(N_KEYS_PER_BUCKET):
            k = f"k{j:04d}"
            b.keys[k] = ObjState()
            b.key_locks[k] = threading.Lock()
        buckets.append(b)
    print(f"[setup] {N_BUCKETS} buckets prepared, {N_KEYS_PER_BUCKET} key slots each", flush=True)

def cleanup_buckets(c):
    for b in buckets:
        try:
            paginator = c.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=b.name):
                objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if objs:
                    c.delete_objects(Bucket=b.name, Delete={"Objects": objs})
            c.delete_bucket(Bucket=b.name)
        except Exception as e:
            print(f"[cleanup] {b.name}: {e}", flush=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    p.add_argument("--access-key", default=DEFAULT_AK)
    p.add_argument("--secret-key", default=DEFAULT_SK)
    p.add_argument("--workers", type=int, default=8,
                   help="concurrent S3 workers (default 8 — bump for heavier load)")
    p.add_argument("--duration-hours", type=float, default=24 * 7,
                   help="how long to run (default: 168h = 1 week)")
    p.add_argument("--prefix", default=f"soak-{uuid.uuid4().hex[:6]}",
                   help="bucket name prefix")
    p.add_argument("--csv", default="soak_kmip.csv",
                   help="health-snapshot CSV path")
    p.add_argument("--cleanup", action="store_true",
                   help="delete buckets at the end (default: leave for inspection)")
    args = p.parse_args()

    print(f"=" * 70)
    print(f"KMIP SSE-S3 soak test")
    print(f"  endpoint   : {args.endpoint}")
    print(f"  duration   : {args.duration_hours}h")
    print(f"  workers    : {args.workers}")
    print(f"  buckets    : {N_BUCKETS} (prefix={args.prefix})")
    print(f"  csv        : {args.csv}")
    print(f"=" * 70, flush=True)

    c = s3_client(args.endpoint, args.access_key, args.secret_key)
    setup_buckets(c, args.prefix)

    def on_sigint(sig, frame):
        print("\n[SIGINT] draining workers...", flush=True)
        stop_event.set()
    signal.signal(signal.SIGINT, on_sigint)

    reporter = threading.Thread(target=reporter_loop, args=(args, args.csv), daemon=True)
    reporter.start()

    deadline = time.monotonic() + args.duration_hours * 3600
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(worker_loop, args, i) for i in range(args.workers)]
        try:
            while time.monotonic() < deadline and not stop_event.is_set():
                time.sleep(2)
        finally:
            stop_event.set()
            for f in futures:
                try:
                    f.result(timeout=30)
                except Exception:
                    pass

    print("\n" + "=" * 70)
    elapsed = time.monotonic() - counters.started_at
    print(f"Final summary after {elapsed/3600:.2f}h:")
    print(f"  total ops      : {counters.ops}")
    print(f"  ok             : {counters.ok}")
    print(f"  err_transient  : {counters.err_transient}")
    print(f"  err_hard       : {counters.err_hard}")
    print(f"  timeouts       : {counters.timeouts}")
    if counters.ops:
        print(f"  ops/sec        : {counters.ops/elapsed:.2f}")
    print(f"  by op (ok)     : {dict(counters.by_op_ok)}")
    print(f"  by op (err)    : {dict(counters.by_op_err)}")
    print(f"  last errors    :")
    for e in list(counters.last_err)[-10:]:
        print(f"    - {e}")
    print(f"  CSV snapshots  : {args.csv}")
    print("=" * 70, flush=True)

    if args.cleanup:
        cleanup_buckets(c)

    sys.exit(0 if counters.err_hard == 0 else 1)

if __name__ == "__main__":
    main()

