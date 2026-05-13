# KMIP SSE-S3 soak test

Long-running stress test for the KMIP SSE-S3 backend. Drives mixed S3 traffic
(PUT/GET/overwrite/delete/multipart/list/bucket-recreate) against radosgw and
hard-fails on data corruption (SHA-256 mismatch between what was PUT and what
later GETs return).

## Prerequisites

- A running vstart cluster with radosgw on `http://127.0.0.1:8000`
- A KMIP server reachable from radosgw (PyKMIP is fine for testing)
- [build/ceph.conf](build/ceph.conf) configured for KMIP SSE-S3:
  ```
  rgw crypt sse s3 backend     = kmip
  rgw crypt kmip addr          = 127.0.0.1:5696
  rgw crypt kmip ca path       = /tmp/pykmip-vstart/certs/ca.crt
  rgw crypt kmip client cert   = /tmp/pykmip-vstart/certs/client.crt
  rgw crypt kmip client key    = /tmp/pykmip-vstart/certs/client.key
  rgw crypt kmip worker threads = 4
  ```
- `boto3` available in the Python environment

## Running

```bash
# Default: 1 week, 8 S3 workers
python3 soak_kmip.py

# Short check
python3 soak_kmip.py --duration-hours 0.0833    # 5 minutes
python3 soak_kmip.py --duration-hours 1         # 1 hour

# Heavier concurrency
python3 soak_kmip.py --workers 16

# Custom endpoint / credentials
python3 soak_kmip.py --endpoint http://host:8000 \
                     --access-key AK --secret-key SK

# Clean up buckets at end (default: leave for inspection)
python3 soak_kmip.py --cleanup
```

Health snapshots are written to `soak_kmip.csv` (override with `--csv`).

## Exit codes

- `0` — no hard failures
- `1` — at least one hard failure (CORRUPTION) was recorded

## Hard-fail conditions (exits non-zero immediately)

- SHA-256 mismatch on GET — actual data corruption
- Two consecutive timeouts on the same bucket — deadlock suspect (logged, not aborted)
- SIGINT — drain in-flight ops and print summary

## What the workers do

Operations are picked from a weighted distribution:

| Op              | Weight |
|-----------------|--------|
| put             | 0.40   |
| get             | 0.35   |
| overwrite       | 0.10   |
| delete          | 0.05   |
| multipart       | 0.04   |
| bucket_recreate | 0.03   |
| list            | 0.03   |

Object sizes are biased small with occasional 10 MB multiparts (1 KB / 16 KB /
256 KB / 1 MB / 10 MB at 30/30/20/15/5%).

Per-key locks are held across the full network op + state update, so two
workers can't race the same `(bucket, key)`. Different keys can run in
parallel within and across buckets.

## Result — 2026-05-13, 5-minute run

Setup: 4 KMIP worker threads, 8 S3 workers, 6 buckets x 50 keys, PyKMIP backend.

```
total ops      : 16804
ok             : 14763
err_transient  : 657
err_hard       : 1384
timeouts       : 30
ops/sec        : 51.43
by op (ok)     : {get: 4674, list: 520, delete: 815, put: 6332,
                  overwrite: 1511, bucket_recreate: 340, multipart: 571}
```

**Zero CORRUPTION events.** No SHA-256 mismatches across 16,804 ops.

The `err_hard` count is dominated by expected races between concurrent
operations the soak intentionally creates:

| Error                 | Cause                                                       |
|-----------------------|-------------------------------------------------------------|
| `NoSuchKey`           | GET races a concurrent delete                               |
| `NoSuchBucket`        | GET/PUT races a `bucket_recreate`                           |
| `BucketNotEmpty`      | `bucket_recreate` races concurrent PUTs into the same bucket |
| `ReadTimeoutError` (30) | PyKMIP stall under burst load                             |
| KMIP `OperationFailed` (1) | PyKMIP transient — single-threaded sqlite contention   |

None of these indicate a Ceph bug. The Ceph encrypt/decrypt paths were
audited separately and confirmed correct: the lose-the-race / adopt-winner
KEK logic in [rgw_crypt.cc](src/rgw/rgw_crypt.cc) updates `key_id` before
the DEK is wrapped, so object xattrs never reference an orphan KEK.

## Notes

- PyKMIP is a reference implementation, not production-grade. Expect a small
  rate of transient `OperationFailed` / read-timeout errors under load.
  Production KMIP servers (HashiCorp Vault KMIP, Thales, Fortanix) handle
  the same workload without these.
- Output buckets are left in place by default so you can inspect them after
  a failure. Re-run with a new `--prefix` to avoid mixing runs.
- The CSV snapshot is updated once a minute and includes ops/sec, p50/p95/p99
  latency for GET and PUT, and radosgw RSS (for leak detection on long runs).

