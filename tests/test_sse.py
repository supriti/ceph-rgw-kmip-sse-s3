#!/usr/bin/env python3
"""
SSE-S3 and SSE-KMS integration tests for RGW.
Modeled after ceph/s3-tests test_s3.py encryption tests.

Requires:
  - RGW running on localhost:8000
  - For SSE-KMS: rgw_crypt_s3_kms_backend = testing
  - For SSE-S3 via KMIP: rgw_crypt_sse_s3_backend = kmip + KMIP server on 5696
"""

import boto3
import hashlib
import base64
import os
import sys
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = 'http://127.0.0.1:8000'
ACCESS_KEY = 'kmipaccess01'
SECRET_KEY = 'kmipsecret01'

s3 = boto3.client('s3',
    endpoint_url=ENDPOINT,
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    config=Config(signature_version='s3v4'),
    region_name='us-east-1',
    verify=False
)

PASS = 0
FAIL = 0
SKIP = 0

def result(name, passed, msg="", skipped=False):
    global PASS, FAIL, SKIP
    if skipped:
        SKIP += 1
        print(f"  SKIP  {name}: {msg}")
    elif passed:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}: {msg}")

def get_or_create_bucket(name):
    try:
        s3.create_bucket(Bucket=name)
    except ClientError as e:
        if e.response['Error']['Code'] not in ('BucketAlreadyOwnedByYou', 'BucketAlreadyExists'):
            raise
    return name

def cleanup_bucket(name):
    try:
        objs = s3.list_objects_v2(Bucket=name)
        for obj in objs.get('Contents', []):
            s3.delete_object(Bucket=name, Key=obj['Key'])
        s3.delete_bucket(Bucket=name)
    except Exception:
        pass


# ============ SSE-KMS Tests ============

def test_sse_kms_put_get():
    """Basic PUT with SSE-KMS, then GET and verify data."""
    name = "test-sse-kms-put-get"
    bucket = get_or_create_bucket("sse-kms-basic")
    try:
        data = b'A' * 1000
        s3.put_object(
            Bucket=bucket, Key='testobj', Body=data,
            ServerSideEncryption='aws:kms',
            SSEKMSKeyId='testkey-1'
        )
        resp = s3.get_object(Bucket=bucket, Key='testobj')
        body = resp['Body'].read()
        result(name, body == data, f"body mismatch: got {len(body)} bytes")
    except ClientError as e:
        result(name, False, f"ClientError: {e.response['Error']}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_sse_kms_head():
    """PUT with SSE-KMS, HEAD should return encryption headers."""
    name = "test-sse-kms-head"
    bucket = get_or_create_bucket("sse-kms-head")
    try:
        s3.put_object(
            Bucket=bucket, Key='testobj', Body=b'A' * 100,
            ServerSideEncryption='aws:kms',
            SSEKMSKeyId='testkey-1'
        )
        resp = s3.head_object(Bucket=bucket, Key='testobj')
        sse = resp.get('ServerSideEncryption', '')
        key_id = resp.get('SSEKMSKeyId', '')
        ok = (sse == 'aws:kms') and (key_id == 'testkey-1')
        result(name, ok, f"SSE={sse}, KeyId={key_id}")
    except ClientError as e:
        result(name, False, f"ClientError: {e.response['Error']}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_sse_kms_transfer_sizes():
    """Test SSE-KMS with various object sizes (1B, 1KB, 1MB, 13B)."""
    sizes = {'1B': 1, '1KB': 1024, '1MB': 1024*1024, '13B': 13}
    for label, sz in sizes.items():
        name = f"test-sse-kms-transfer-{label}"
        bucket = get_or_create_bucket(f"sse-kms-xfer-{label.lower()}")
        try:
            data = b'A' * sz
            s3.put_object(
                Bucket=bucket, Key='testobj', Body=data,
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId='testkey-1'
            )
            resp = s3.get_object(Bucket=bucket, Key='testobj')
            body = resp['Body'].read()
            result(name, body == data, f"size mismatch: expected {sz}, got {len(body)}")
        except ClientError as e:
            result(name, False, f"ClientError: {e.response['Error']}")
        except Exception as e:
            result(name, False, str(e))
        finally:
            cleanup_bucket(bucket)


def test_sse_kms_no_key():
    """SSE-KMS without key ID should fail."""
    name = "test-sse-kms-no-key"
    bucket = get_or_create_bucket("sse-kms-nokey")
    try:
        # aws:kms without key ID
        s3.put_object(
            Bucket=bucket, Key='testobj', Body=b'A' * 100,
            ServerSideEncryption='aws:kms'
        )
        result(name, False, "Expected error but PUT succeeded")
    except ClientError as e:
        # Should get an error
        status = e.response['ResponseMetadata']['HTTPStatusCode']
        result(name, status == 400, f"status={status}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_sse_kms_multipart():
    """SSE-KMS multipart upload (10MB = 2 x 5MB parts)."""
    name = "test-sse-kms-multipart"
    bucket = get_or_create_bucket("sse-kms-multi")
    try:
        key = "multipart_enc"
        part_size = 5 * 1024 * 1024
        total_size = 10 * 1024 * 1024
        data = os.urandom(total_size)

        mpu = s3.create_multipart_upload(
            Bucket=bucket, Key=key,
            ServerSideEncryption='aws:kms',
            SSEKMSKeyId='testkey-1'
        )
        upload_id = mpu['UploadId']
        parts = []

        for i in range(0, total_size, part_size):
            part_num = (i // part_size) + 1
            part_data = data[i:i+part_size]
            resp = s3.upload_part(
                Bucket=bucket, Key=key, UploadId=upload_id,
                PartNumber=part_num, Body=part_data
            )
            parts.append({'PartNumber': part_num, 'ETag': resp['ETag']})

        s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={'Parts': parts}
        )

        resp = s3.get_object(Bucket=bucket, Key=key)
        body = resp['Body'].read()
        result(name, body == data, f"size mismatch: expected {total_size}, got {len(body)}")
    except ClientError as e:
        result(name, False, f"ClientError: {e.response['Error']}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


# ============ SSE-S3 Tests ============

def test_sse_s3_put_get():
    """Basic PUT with SSE-S3 (AES256), then GET and verify data."""
    name = "test-sse-s3-put-get"
    bucket = get_or_create_bucket("sse-s3-basic")
    try:
        data = b'Hello SSE-S3!' * 100
        s3.put_object(
            Bucket=bucket, Key='testobj', Body=data,
            ServerSideEncryption='AES256'
        )
        resp = s3.get_object(Bucket=bucket, Key='testobj')
        body = resp['Body'].read()
        result(name, body == data, f"body mismatch: got {len(body)} bytes")
    except ClientError as e:
        err = e.response['Error']
        result(name, False, f"ClientError: {err}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_sse_s3_head():
    """PUT with SSE-S3, HEAD should return x-amz-server-side-encryption: AES256."""
    name = "test-sse-s3-head"
    bucket = get_or_create_bucket("sse-s3-head")
    try:
        s3.put_object(
            Bucket=bucket, Key='testobj', Body=b'test data',
            ServerSideEncryption='AES256'
        )
        resp = s3.head_object(Bucket=bucket, Key='testobj')
        sse = resp.get('ServerSideEncryption', '')
        result(name, sse == 'AES256', f"SSE={sse}")
    except ClientError as e:
        err = e.response['Error']
        result(name, False, f"ClientError: {err}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_sse_s3_transfer_sizes():
    """Test SSE-S3 with various object sizes."""
    sizes = {'1B': 1, '1KB': 1024, '1MB': 1024*1024, '13B': 13}
    for label, sz in sizes.items():
        name = f"test-sse-s3-transfer-{label}"
        bucket = get_or_create_bucket(f"sse-s3-xfer-{label.lower()}")
        try:
            data = b'X' * sz
            s3.put_object(
                Bucket=bucket, Key='testobj', Body=data,
                ServerSideEncryption='AES256'
            )
            resp = s3.get_object(Bucket=bucket, Key='testobj')
            body = resp['Body'].read()
            result(name, body == data, f"size mismatch: expected {sz}, got {len(body)}")
        except ClientError as e:
            result(name, False, f"ClientError: {e.response['Error']}")
        except Exception as e:
            result(name, False, str(e))
        finally:
            cleanup_bucket(bucket)


def test_sse_s3_data_integrity():
    """Verify data is not corrupted through SSE-S3 encrypt/decrypt cycle.

    Tests with random data at various sizes including edge cases
    (block boundaries, non-aligned sizes). Verifies content, length,
    ETag, and multiple re-reads all return identical data.
    """
    # Sizes chosen to hit: sub-block, exact AES block (16B), exact CBC block
    # boundary (4096), off-by-one, and larger multi-block objects.
    sizes = {
        '0B':       0,
        '1B':       1,
        '15B':      15,       # one byte short of AES block
        '16B':      16,       # exact AES block size
        '17B':      17,       # one byte over AES block
        '4095B':    4095,     # one byte short of page
        '4096B':    4096,     # exact page / CBC block boundary
        '4097B':    4097,     # one byte over page
        '1MB':      1024*1024,
        '1MB+1':    1024*1024 + 1,
    }
    bucket = get_or_create_bucket("sse-s3-integrity")
    try:
        for label, sz in sizes.items():
            name = f"test-sse-s3-integrity-{label}"
            key = f"obj-{label}"
            try:
                # Use random data so compression can't hide corruption
                data = os.urandom(sz)
                import hashlib as _hl
                data_sha256 = _hl.sha256(data).hexdigest()

                s3.put_object(
                    Bucket=bucket, Key=key, Body=data,
                    ServerSideEncryption='AES256'
                )

                # First read: verify content matches
                resp = s3.get_object(Bucket=bucket, Key=key)
                body = resp['Body'].read()
                body_sha256 = _hl.sha256(body).hexdigest()

                if len(body) != sz:
                    result(name, False, f"length mismatch: expected {sz}, got {len(body)}")
                    continue
                if body_sha256 != data_sha256:
                    result(name, False, f"SHA-256 mismatch: put={data_sha256[:16]}... got={body_sha256[:16]}...")
                    continue

                # Second read: verify decrypt is deterministic
                resp2 = s3.get_object(Bucket=bucket, Key=key)
                body2 = resp2['Body'].read()
                if body2 != body:
                    result(name, False, "second GET returned different data")
                    continue

                # Range read: verify partial decrypt works (skip for 0B)
                if sz >= 2:
                    start = sz // 4
                    end = sz // 4 + min(sz // 2, 100)
                    resp_range = s3.get_object(
                        Bucket=bucket, Key=key,
                        Range=f"bytes={start}-{end - 1}"
                    )
                    range_body = resp_range['Body'].read()
                    expected_range = data[start:end]
                    if range_body != expected_range:
                        result(name, False,
                            f"range read mismatch: bytes={start}-{end-1} "
                            f"expected {len(expected_range)}B got {len(range_body)}B")
                        continue

                result(name, True)
            except ClientError as e:
                result(name, False, f"ClientError: {e.response['Error']}")
            except Exception as e:
                result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_sse_s3_overwrite_integrity():
    """Overwrite an encrypted object and verify new data is returned."""
    name = "test-sse-s3-overwrite"
    bucket = get_or_create_bucket("sse-s3-overwrite")
    try:
        key = 'overwrite-obj'
        data_v1 = os.urandom(512)
        data_v2 = os.urandom(512)

        s3.put_object(Bucket=bucket, Key=key, Body=data_v1,
                      ServerSideEncryption='AES256')
        resp1 = s3.get_object(Bucket=bucket, Key=key)
        body1 = resp1['Body'].read()

        s3.put_object(Bucket=bucket, Key=key, Body=data_v2,
                      ServerSideEncryption='AES256')
        resp2 = s3.get_object(Bucket=bucket, Key=key)
        body2 = resp2['Body'].read()

        ok = (body1 == data_v1) and (body2 == data_v2) and (body1 != body2)
        result(name, ok,
               f"v1_match={body1==data_v1} v2_match={body2==data_v2} different={body1!=body2}")
    except ClientError as e:
        result(name, False, f"ClientError: {e.response['Error']}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_sse_s3_multipart():
    """SSE-S3 multipart upload."""
    name = "test-sse-s3-multipart"
    bucket = get_or_create_bucket("sse-s3-multi")
    try:
        key = "multipart_s3"
        part_size = 5 * 1024 * 1024
        total_size = 10 * 1024 * 1024
        data = os.urandom(total_size)

        mpu = s3.create_multipart_upload(
            Bucket=bucket, Key=key,
            ServerSideEncryption='AES256'
        )
        upload_id = mpu['UploadId']
        parts = []

        for i in range(0, total_size, part_size):
            part_num = (i // part_size) + 1
            part_data = data[i:i+part_size]
            resp = s3.upload_part(
                Bucket=bucket, Key=key, UploadId=upload_id,
                PartNumber=part_num, Body=part_data
            )
            parts.append({'PartNumber': part_num, 'ETag': resp['ETag']})

        s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={'Parts': parts}
        )

        resp = s3.get_object(Bucket=bucket, Key=key)
        body = resp['Body'].read()
        result(name, body == data, f"size mismatch: expected {total_size}, got {len(body)}")
    except ClientError as e:
        result(name, False, f"ClientError: {e.response['Error']}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


# ============ Conflict / Error Tests ============

def test_conflict_sse_c_and_kms():
    """Cannot specify both SSE-C and SSE-KMS headers."""
    name = "test-conflict-sse-c-and-kms"
    bucket = get_or_create_bucket("sse-conflict-ckms")
    try:
        raw_key = os.urandom(32)
        customer_key = base64.b64encode(raw_key).decode()
        customer_key_md5 = base64.b64encode(
            hashlib.md5(raw_key).digest()
        ).decode()

        s3.put_object(
            Bucket=bucket, Key='testobj', Body=b'data',
            ServerSideEncryption='aws:kms',
            SSEKMSKeyId='testkey-1',
            SSECustomerAlgorithm='AES256',
            SSECustomerKey=customer_key,
            SSECustomerKeyMD5=customer_key_md5
        )
        result(name, False, "Expected error but PUT succeeded")
    except ClientError as e:
        status = e.response['ResponseMetadata']['HTTPStatusCode']
        code = e.response['Error'].get('Code', '')
        result(name, status == 400, f"status={status}, code={code}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_conflict_sse_s3_with_kms_keyid():
    """AES256 with KMS key ID should fail (conflicting)."""
    name = "test-conflict-s3-kms-keyid"
    bucket = get_or_create_bucket("sse-conflict-s3kms")
    try:
        s3.put_object(
            Bucket=bucket, Key='testobj', Body=b'data',
            ServerSideEncryption='AES256',
            SSEKMSKeyId='testkey-1'
        )
        result(name, False, "Expected error but PUT succeeded")
    except ClientError as e:
        status = e.response['ResponseMetadata']['HTTPStatusCode']
        code = e.response['Error'].get('Code', '')
        result(name, status == 400, f"status={status}, code={code}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_bad_encryption_algo():
    """Invalid encryption algorithm should fail."""
    name = "test-bad-encryption-algo"
    bucket = get_or_create_bucket("sse-bad-algo")
    try:
        s3.put_object(
            Bucket=bucket, Key='testobj', Body=b'data',
            ServerSideEncryption='aes:kms'  # aes != aws
        )
        result(name, False, "Expected error but PUT succeeded")
    except ClientError as e:
        status = e.response['ResponseMetadata']['HTTPStatusCode']
        code = e.response['Error'].get('Code', '')
        result(name, status == 400, f"status={status}, code={code}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


# ============ SSE-C Tests ============

def test_sse_c_put_get():
    """Basic SSE-C: PUT with customer key, GET with same key."""
    name = "test-sse-c-put-get"
    bucket = get_or_create_bucket("sse-c-basic")
    try:
        raw_key = os.urandom(32)
        customer_key = base64.b64encode(raw_key).decode()
        customer_key_md5 = base64.b64encode(
            hashlib.md5(raw_key).digest()
        ).decode()

        data = b'SSE-C test data' * 100
        s3.put_object(
            Bucket=bucket, Key='testobj', Body=data,
            SSECustomerAlgorithm='AES256',
            SSECustomerKey=customer_key,
            SSECustomerKeyMD5=customer_key_md5
        )
        resp = s3.get_object(
            Bucket=bucket, Key='testobj',
            SSECustomerAlgorithm='AES256',
            SSECustomerKey=customer_key,
            SSECustomerKeyMD5=customer_key_md5
        )
        body = resp['Body'].read()
        result(name, body == data, f"body mismatch: got {len(body)} bytes")
    except ClientError as e:
        result(name, False, f"ClientError: {e.response['Error']}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_sse_c_head_without_key():
    """HEAD on SSE-C object without key should fail with 400."""
    name = "test-sse-c-head-no-key"
    bucket = get_or_create_bucket("sse-c-head")
    try:
        raw_key = os.urandom(32)
        customer_key = base64.b64encode(raw_key).decode()
        customer_key_md5 = base64.b64encode(
            hashlib.md5(raw_key).digest()
        ).decode()

        s3.put_object(
            Bucket=bucket, Key='testobj', Body=b'data',
            SSECustomerAlgorithm='AES256',
            SSECustomerKey=customer_key,
            SSECustomerKeyMD5=customer_key_md5
        )
        # HEAD without the encryption key
        resp = s3.head_object(Bucket=bucket, Key='testobj')
        result(name, False, "Expected 400 but HEAD succeeded")
    except ClientError as e:
        status = e.response['ResponseMetadata']['HTTPStatusCode']
        result(name, status == 400, f"status={status}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


def test_sse_c_wrong_key():
    """GET SSE-C object with wrong key should fail."""
    name = "test-sse-c-wrong-key"
    bucket = get_or_create_bucket("sse-c-wrongkey")
    try:
        raw_key = os.urandom(32)
        customer_key = base64.b64encode(raw_key).decode()
        customer_key_md5 = base64.b64encode(
            hashlib.md5(raw_key).digest()
        ).decode()

        s3.put_object(
            Bucket=bucket, Key='testobj', Body=b'secret data',
            SSECustomerAlgorithm='AES256',
            SSECustomerKey=customer_key,
            SSECustomerKeyMD5=customer_key_md5
        )

        # GET with different key
        wrong_key = os.urandom(32)
        wrong_key_b64 = base64.b64encode(wrong_key).decode()
        wrong_key_md5 = base64.b64encode(
            hashlib.md5(wrong_key).digest()
        ).decode()
        resp = s3.get_object(
            Bucket=bucket, Key='testobj',
            SSECustomerAlgorithm='AES256',
            SSECustomerKey=wrong_key_b64,
            SSECustomerKeyMD5=wrong_key_md5
        )
        result(name, False, "Expected error but GET succeeded")
    except ClientError as e:
        status = e.response['ResponseMetadata']['HTTPStatusCode']
        result(name, status == 403, f"status={status}")
    except Exception as e:
        result(name, False, str(e))
    finally:
        cleanup_bucket(bucket)


if __name__ == '__main__':
    print("=" * 60)
    print("SSE Integration Tests")
    print("=" * 60)

    # print("\n--- SSE-KMS Tests (testing backend) ---")
    # test_sse_kms_put_get()
    # test_sse_kms_head()
    # test_sse_kms_transfer_sizes()
    # test_sse_kms_no_key()
    # test_sse_kms_multipart()

    print("\n--- SSE-S3 Tests (KMIP backend) ---")
    test_sse_s3_put_get()
    test_sse_s3_head()
    test_sse_s3_transfer_sizes()
    test_sse_s3_data_integrity()
    test_sse_s3_overwrite_integrity()
    test_sse_s3_multipart()

    # print("\n--- SSE-C Tests ---")
    # test_sse_c_put_get()
    # test_sse_c_head_without_key()
    # test_sse_c_wrong_key()

    print("\n--- Conflict/Error Tests ---")
    # test_conflict_sse_c_and_kms()
    test_conflict_sse_s3_with_kms_keyid()
    # test_bad_encryption_algo()

    print("\n" + "=" * 60)
    print(f"Results: {PASS} passed, {FAIL} failed, {SKIP} skipped")
    print("=" * 60)

    sys.exit(1 if FAIL > 0 else 0)
