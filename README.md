


# ceph-rgw-kmip-sse-s3

 This is a developer guidebook for understanding what is rgw kmip sse-s3, how to
 setup a local `PyKMIP` server, run sanity tests and benchmark performance.

How to navigate this repo:

 - Start by reading `docs/kmip_design_doc.md`
 - Setup a local `PyKMIP` server
 - Run `test_sse.py`
 - Run `bench.py`

### Setting up PyKMIP server

```markdown
```bash
cd docker
./gen_certs.sh                    # generates CA + server + client certs (one-time)
docker compose up -d              # starts PyKMIP on :5696

```

Verify the server is reachable and TLS works:

```bash
openssl s_client \
  -connect 127.0.0.1:5696 \
  -CAfile certs/ca.crt \
  -cert certs/client.crt \
  -key certs/client.key \
  </dev/null 2>&1 | grep -E "Verify return|subject="

```

You should see `Verify return code: 0 (ok)` and the server cert subject. If the server isn't reachable from a separate container, use `host.docker.internal:5696` instead of `127.0.0.1:5696`.


### Configure RGW

Apply the KMIP options from ceph.conf.example to your Ceph cluster's `ceph.conf` under the `[client]` (or `[client.rgw.<name>]`) section. Required options:

```ini
rgw crypt sse s3 backend = kmip
rgw crypt kmip addr = 127.0.0.1:5696
rgw crypt kmip ca path = /path/to/docker/certs/ca.crt
rgw crypt kmip client cert = /path/to/docker/certs/client.crt
rgw crypt kmip client key = /path/to/docker/certs/client.key
rgw crypt kmip socket io timeout sec = 30
rgw crypt kmip worker threads = 4

```

Restart RGW:

```bash
pkill -f 'radosgw.*client.rgw.<name>'
sleep 3
./bin/radosgw -c <ceph.conf> -n client.rgw.<name> --rgw_frontends="beast port=8000"

```

Verify the options were loaded (not silently rejected):

```bash
ceph daemon /path/to/radosgw.<name>.asok config show | grep rgw_crypt_kmip
ceph daemon /path/to/radosgw.<name>.asok config show | grep rgw_crypt_sse_s3_backend

```

The backend should read `kmip`, not `vault`. 

### Run the integration tests

Create an S3 user with the access keys the test script expects:

```bash
radosgw-admin user create --uid=kmiptest --display-name="KMIP Test" \
  --access-key=kmipaccess01 --secret=kmipsecret01

```

Run the suite:

```bash
python3 tests/test_sse.py

```

The suite covers PUT/GET roundtrip, HEAD encryption headers, various object sizes (including AES block boundaries 15/16/17 and CBC boundaries 4095/4096/4097), data integrity via SHA-256, range reads, overwrites, and multipart uploads.

### Benchmark

Pre-warm a bucket so the one-time KEK creation cost isn't part of the measurement:

```bash
python3 -c "
import boto3
from botocore.config import Config
s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:8000',
    aws_access_key_id='kmipaccess01', aws_secret_access_key='kmipsecret01',
    config=Config(signature_version='s3v4'), region_name='us-east-1', verify=False)
s3.create_bucket(Bucket='warp-warm')
s3.put_object(Bucket='warp-warm', Key='_warm', Body=b'x', ServerSideEncryption='AES256')
"

```

Run a mixed workload:

```bash
warp mixed \
  --host=127.0.0.1:8000 \
  --access-key=kmipaccess01 --secret-key=kmipsecret01 \
  --tls=false --bucket=warp-warm \
  --obj.size=64KiB --concurrent=4 --duration=60s \
  --sse-s3-encrypt --noclear
```

To confirm KMIP is actually being exercised, watch the RGW log for `KMIP encrypt succeeded` / `Successfully unwrapped DEK` lines.