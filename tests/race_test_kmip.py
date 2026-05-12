#!/usr/bin/env python3
"""KMIP race test: N racers concurrently PUT into M brand-new buckets.

Goal: force concurrent get_sse_s3_bucket_key() into the same bucket from
multiple frontend threads while KMIP has multiple workers — so KMIP
Locate/Create/Activate calls genuinely overlap.
"""
import boto3
import botocore
import concurrent.futures as cf
import os, sys, time, uuid, hashlib

ENDPOINT = "http://127.0.0.1:8000"
AK = "0555b35654ad1656d804"
SK = "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q=="
N_BUCKETS = 3
N_RACERS_PER_BUCKET = 8
PAYLOAD = os.urandom(64 * 1024)
PAYLOAD_MD5 = hashlib.md5(PAYLOAD).hexdigest()

def s3():
    return boto3.client("s3", endpoint_url=ENDPOINT,
        aws_access_key_id=AK, aws_secret_access_key=SK,
        config=botocore.config.Config(retries={"max_attempts": 0}))

def put(bucket, key):
    c = s3()
    t0 = time.monotonic()
    try:
        c.put_object(Bucket=bucket, Key=key, Body=PAYLOAD,
                     ServerSideEncryption="AES256")
        return ("ok", bucket, key, time.monotonic() - t0, None)
    except Exception as e:
        return ("err", bucket, key, time.monotonic() - t0, str(e)[:200])

def verify(bucket, key):
    c = s3()
    try:
        r = c.get_object(Bucket=bucket, Key=key)
        body = r["Body"].read()
        return hashlib.md5(body).hexdigest() == PAYLOAD_MD5
    except Exception:
        return False

def main():
    suffix = uuid.uuid4().hex[:8]
    buckets = [f"race-{suffix}-{i}" for i in range(N_BUCKETS)]
    c = s3()
    for b in buckets:
        c.create_bucket(Bucket=b)
    print(f"[race] created {N_BUCKETS} buckets, {N_RACERS_PER_BUCKET} racers each, "
          f"total {N_BUCKETS * N_RACERS_PER_BUCKET} PUTs")

    jobs = [(b, f"obj-{i}") for b in buckets for i in range(N_RACERS_PER_BUCKET)]

    t0 = time.monotonic()
    with cf.ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        results = list(ex.map(lambda j: put(*j), jobs))
    elapsed = time.monotonic() - t0

    ok = sum(1 for r in results if r[0] == "ok")
    err = [r for r in results if r[0] != "ok"]
    print(f"[race] {ok}/{len(jobs)} PUTs OK in {elapsed:.2f}s")
    for e in err:
        print(f"  ERR {e[1]}/{e[2]}: {e[4]}")

    print("[race] verifying GET + MD5...")
    bad = sum(0 if verify(b, k) else 1 for b, k in jobs)
    print(f"[race] verify: {len(jobs) - bad}/{len(jobs)} matched")

    return 0 if (ok == len(jobs) and bad == 0) else 1

if __name__ == "__main__":
    sys.exit(main())

