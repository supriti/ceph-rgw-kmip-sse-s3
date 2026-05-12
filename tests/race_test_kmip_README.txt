# 1. Set KMIP workers to >1 so concurrency is real (not serialized at queue)
./bin/ceph config set client.rgw.8000 rgw_crypt_kmip_worker_threads 4

# 2. Restart rgw to pick up new worker count (read once at startup)
kill <radosgw-pid>
./bin/radosgw -c /workspaces/ceph/build/ceph.conf ... -n client.rgw.8000 ...

# 3. Confirm 4 workers started
grep "kmip_worker\[" build/out/radosgw.8000.log | tail -5
#   kmip_worker[0] start
#   kmip_worker[1] start
#   kmip_worker[2] start
#   kmip_worker[3] start

# 4. Run the race test
python3 race_test_kmip.py

What the test exercises

3 brand-new buckets × 8 concurrent PUTs each = 24 parallel S3 PUTs
                       │
                       ▼  (all 8 racers per bucket arrive at empty bucket attrs)
            get_sse_s3_bucket_key()
                       │
                       ├─ all 8 frontend threads call create_sse_s3_bucket_key
                       ├─ 8 KMIP Create+Activate ops dispatched to KMIP workers in parallel
                       ├─ 1 winner persists key_id to bucket attrs
                       └─ 7 losers get ECANCELED, refresh, see winner, destroy their orphan
Run output

[race] created 3 buckets, 8 racers each, total 24 PUTs
[race] 24/24 PUTs OK in 0.45s
[race] verifying GET + MD5...
[race] verify: 24/24 matched
Log snippets (with worker_id-in-log change applied)
KMIP workers spawned (4 of them):


2026-05-11T14:17:52.298 ffff917a89e0 10 kmip_worker[0] start
2026-05-11T14:17:52.298 ffff83ff89e0 10 kmip_worker[2] start
2026-05-11T14:17:52.299 ffff837e89e0 10 kmip_worker[3] start
2026-05-11T14:17:52.299 ffff90f989e0 10 kmip_worker[1] start
Concurrent KMIP traffic, all 4 workers serving requests:


ffff788409e0 10 kmip_worker[0] remaining queue depth 0
ffff6afd89e0 10 kmip_worker[3] remaining queue depth 0
ffff6bff89e0 10 kmip_worker[1] remaining queue depth 0
ffff6b7e89e0 10 kmip_worker[2] remaining queue depth 0
Lost-KEK-race resolution — losers destroying their orphan KEKs, spread across all workers:


fffe97c289e0  5 req 4396605090539481889  0.260s kmip_worker[2] Lost KEK race; destroying our orphan KEK (id_len=3) and adopting winner (id_len=3)
fffe96c089e0  5 req 13529979629012045358 0.260s kmip_worker[0] Lost KEK race; destroying our orphan KEK (id_len=3) and adopting winner (id_len=3)
fffe94bc89e0  5 req 6956660627351869560  0.255s kmip_worker[3] Lost KEK race; destroying our orphan KEK (id_len=3) and adopting winner (id_len=3)
fffe92b889e0  5 req 8450687387147717364  0.253s kmip_worker[1] Lost KEK race; destroying our orphan KEK (id_len=3) and adopting winner (id_len=3)
fffe913589e0  5 req 675242402913958624   0.265s kmip_worker[2] Lost KEK race; destroying our orphan KEK (id_len=3) and adopting winner (id_len=3)
Counters validated
metric	observed	meaning
PUTs	24/24 OK	no encryption failures under contention
GETs	24/24 MD5 match	wrapped-DEK round-trip correct after race
KMIP workers used	0, 1, 2, 3 (all four)	real KMIP-layer concurrency, not just frontend serialization
"Lost KEK race" lines	21 (= 7 losers × 3 buckets)	exactly the expected count: 1 winner + 7 losers per bucket × 3 buckets
Orphan KEK destroys	21/21 succeeded	no KEK leakage on pykmip
Duration	~0.45-0.71s	wall time for 24 concurrent PUTs with KEK creation + race resolution
The MD5 match is the critical correctness gate — it proves every loser correctly adopted the winner's KEK and re-wrapped/unwrapped its DEK against the right key. If a loser had kept using its own (about-to-be-destroyed) orphan KEK, GET would fail to decrypt.
