## Background

Ceph RGW already supports server-side encryption (SSE) for S3 object storage. The current implementation supports multiple KMS backends: HashiCorp Vault, OpenStack Barbican, and KMIP[ \[1\]](https://github.com/supriti/ceph/blob/main/src/common/options/rgw.yaml.in#L3022C10-L3022C33).

### S3 Encryption Modes

There are three SSE modes defined by the S3 API:

-   **SSE-S3** (`AES256`): Server-managed keys. The client only specifies `x-amz-server-side-encryption: AES256`. RGW handles all key creation, wrapping, and lifecycle on the KMS. 
-   **SSE-KMS** (`aws:kms`): Customer-managed keys. The admin pre-creates a key on the KMS, and the client specifies which key to use via `x-amz-server-side-encryption-aws-kms-key-id`. This gives the client control over which key encrypts their data.
-   **SSE-C**: Customer-provided keys. The client sends the actual encryption key with each request. No KMS is involved, the key is provided and managed entirely by the client.

### What Was Already Supported
 - Vault: SSE-KMS, SSE-S3 , SSE-C
 - Barbican: SSE-KMS, SSE-C
 - KMIP: SSE-KMS, SSE-C

### What Was Missing

SSE-S3 via KMIP was not supported. Customers using enterprise KMIP-compliant key management systems (Thales CipherTrust, Fortanix, OVH OKMS, Entrust, etc.) could use SSE-KMS but had no way to use SSE-S3, which is the simpler and more common encryption mode.

### Why KMIP for SSE-S3

1.  **Enterprise demand**: Large enterprises and regulated industries use KMIP-compliant HSMs and KMS appliances. KMIP is an OASIS/ISO standard, while Vault is proprietary.
    
2.  **Stronger security model**: With Vault SSE-S3, the key material is retrieved from Vault and crypto is done locally in RGW, the key travels over the network. With KMIP SSE-S3, the KEK never leaves the KMIP server. RGW sends the DEK to the KMIP server for wrapping/unwrapping via KMIP Encrypt/Decrypt operations. Only the wrapped (encrypted) DEK travels over the network.
    
3.  **Vendor independence**: KMIP is an open standard supported by multiple vendors. Customers can switch between KMIP servers without changing RGW configuration.
    

## SSE-S3 KMIP: Design 

The design follows a KEK/DEK (Key Encryption Key/ Data Encryption Key) pattern

### Key Concepts
1. KEK: One per bucket. Its created on KMIP server when the first encrypted object is uploaded to a bucket. kEK never leaves KMIP server, only its id is stored in the bucket metadata.
2. DEK: One per object. A random 32-byte (AES-265) key generated locally in RGW for each object upload. The DEK is used to encrypt the object data, then wrapped by the KEK on KMIP server and the wrapped form is stored alongside the object. The plaintext DEK is zeroized from RGW memory immediately after use.

### Encryption (PUT object)

 1. Client sends `PUT /bucket/object` with `x-amz-server-side-encryption: AES256`
 2. RGW checks if KEK already exists for this bucket (stored in bucket attributes) 
	 - If not: RGW asks KMIP server to `Create` a new AES-256 key and `Activate` it. The KMIP server returns a KEK ID (eg. "240". RGW saves this ID in the bucket metadata.
	 - If yes: RGW reuses the existing KEK ID
	 - Note: KEK ID is unique per bucket. all the objects in same bucket share the KEK ID.
3. RGW generates a random 32-byte DEK locally
4. RGW sends the plaintext DEK to the KMIP server and asks it to `Encrypt(wrap)` the DEK using the KEK. The KMIP server performs AES-GCM encryption and returns the wrapped DEK (ciphertext + IV + authentication tag)
5. RGW encrypts the object data locally using the plaintext DEK (AES-256-CBC)
6. RGW stores on the OSD:
	- The encrypted object data
	- The wrapped DEK blob (as an object attr)
	- The KEK ID (as an object attr)
7. RGW zeroizes the plaintext DEK from memory

### Decryption (GET object)

 1. Client sends `GET /bucket/object`
 2. RGW reads the KEK ID and the wrapped DEK blob from the object attrs.
 3. RGW sends the wrapped DEK to the KMIP server and asks it to `Decrypt (unwrap) ` it using the KEK. The KMIP server retursn the plaintext DEK
 4. RGW decrypts the object data locally using the plaintext DEK (AES-256-CBC)
 5. RGW streams the decrypted data to the client
 6. RGW zeroizes the plaintext DEK from memory

### Bucket Deletion
1. RGW reads the KEK ID from the bucket metadata
2. RGW asks the KMIP server to `Revoke` the KEK (marks it as no longer valid)
3. RGW asks the KMIP server to `Destroy` the KEK (permanently deletes it).


## Security Properties
-   The KEK never leaves the KMIP server. Even if an attacker gains access to the Ceph storage, they cannot decrypt any object without access to the KMIP server.
-   Each object has a unique DEK. Compromising one object's DEK does not affect other objects.
-   The wrapped DEK uses AES-GCM with authentication, so any tampering with the wrapped blob is detected during unwrap.
-   The encryption context (bucket/object ARN) is bound to the wrapped DEK as additional authenticated data (AAD). A wrapped DEK from one object cannot be used to decrypt another object.

----------

## Implementation


The implementation spans three areas: libkmip (C library), RGW KMIP client (transport layer), and the SSE-S3 feature itself.

### 1. libkmip Changes
We decided to use OpenKMIP branch as base for feature development, as its more up to date compared to current libkmip in ceph.

The existing libkmip fork (based on OpenKMIP) only supported Create, Get, Destroy, and Query operations. The following were added to support SSE-S3:

-   **Encrypt/Decrypt**: Server-side AES-GCM encryption with AEAD support (AAD, IV, auth tag). This is what wraps and unwraps DEKs on the KMIP server.
-   **Activate**: Transitions a newly created key from Pre-Active to Active state. KMIP keys cannot be used for crypto operations until activated.
-   **Revoke**: Marks a key as no longer valid. Required before Destroy on most KMIP servers.
-   **Locate**: Key lookup by name. Required for SSE-KMS where the client provides a key name that must be resolved to a unique ID on the KMIP server. (This operation existed in the ceph/libkmip fork but was missing in the OpenKMIP fork we use.)
 
 ### 2. RGW KMIP Client Changes (existing code improvements)

The existing KMIP client in RGW was updated for reliability and performance:

-   Multi-threaded worker pool (configurable via  `rgw_crypt_kmip_worker_threads`) replacing the single worker thread
-   TLS connection pool with LIFO reuse and idle connection eviction
-   Socket I/O timeouts to prevent hung connections when KMIP server is unreachable
-   Ordered TLS teardown (SSL_shutdown before BIO_free_all)

### 3. SSE-S3 Feature (new code)

New files:

-   `rgw_kmip_sse_s3.cc/h`  — KEK/DEK lifecycle: create, activate, wrap, unwrap, revoke, destroy
-   `rgw_kmip_sse_s3_backend.h`  — Abstract interface for mock testing
-   `rgw_kmip_wrapped_dek.cc/h`  — Parser for the wrapped DEK binary format

Modified files:

-   `rgw_kms.cc`  — Backend routing: added KMIP alongside Vault for make/reconstitute/create/remove operations
-   `rgw_crypt.cc`  — Bucket key management: uses bucket ID for KEK naming, cleanup on metadata save failure
-   `rgw_kmip_client.cc/h`  — Added lambda-based dispatch (`execute_fn`) for SSE-S3 Encrypt/Decrypt operations, alongside the existing struct-based dispatch used by SSE-KMS Locate/Get
-   `rgw_op.cc`  — Minor wiring

### 4. Testing

-   No support for unit tests
-  TODO: refer to scripts that you wrote 
- also teuthoology 

### 5. Open Items

-   Additional s3-tests may be needed for KMIP-specific edge cases: WIP by kyr 
-   DEK caching in RGW memory (with TTL) could reduce KMIP round-trips for repeated GETs — follow-up optimization
-   Connection health checks for stale pooled connections — follow-up improvement


## Code Architecture

The RGW KMIP code is organized in layers. Each layer has a specific responsibility and only talks to the layer directly below it.

┌─────────────────────────────────────────────────┐
│ S3 API Layer                                    │
│   rgw_crypt.cc — entry point for encryption     │
│   rgw_op.cc — S3 operation handling             │
├─────────────────────────────────────────────────┤
│ Backend Routing Layer                           │
│   rgw_kms.cc — selects Vault or KMIP backend    │
├─────────────────────────────────────────────────┤
│ SSE-S3 Feature Layer                            │
│   rgw_kmip_sse_s3.cc — KEK/DEK lifecycle        │      │
├─────────────────────────────────────────────────┤
│ KMIP Client Layer                               │
│   rgw_kmip_client.cc/h — request dispatch       │
│   rgw_kmip_client_impl.cc/h — workers, pool     │
├─────────────────────────────────────────────────┤
│ libkmip                                         │
│   kmip_bio.c — high-level KMIP operations       │
│   kmip.c — TTLV encode/decode                   │
└─────────────────────────────────────────────────┘

### S3 API Layer (`rgw_crypt.cc`,  `rgw_op.cc`)

This is where S3 requests enter the encryption path. When a client sends a PUT with `x-amz-server-side-encryption: AES256`, `rgw_s3_prepare_encrypt()` is called. It determines the encryption mode (SSE-S3, SSE-KMS, or SSE-C), obtains the encryption key, creates the cipher, and sets the appropriate object attributes. On GET, `rgw_s3_prepare_decrypt()` reads the stored attributes and retrieves the key to create the decryption cipher.

### Backend Routing Layer (`rgw_kms.cc`)

This layer selects the right backend based on configuration. For SSE-S3, it checks `rgw_crypt_sse_s3_backend` and routes to either Vault or KMIP. For SSE-KMS, it checks `rgw_crypt_s3_kms_backend` and routes to Vault, Barbican, KMIP, or the testing backend. The routing functions are:

-   `make_actual_key_from_sse_s3()`  — generates and wraps a DEK (PUT path)
-   `reconstitute_actual_key_from_sse_s3()`  — unwraps a DEK (GET path)
-   `create_sse_s3_bucket_key()`  — creates a KEK on the backend
-   `remove_sse_s3_bucket_key()`  — destroys a KEK on the backend

### SSE-S3 Feature Layer (`rgw_kmip_sse_s3.cc`)

This is the core of the new feature. It implements the `RGWKmipSseS3Backend` interface with four operations:

-   `create_bucket_key()`  — KMIP Create + Activate
-   `destroy_bucket_key()`  — KMIP Revoke + Destroy
-   `generate_and_wrap_dek()`  — generate random DEK + KMIP Encrypt
-   `unwrap_dek()`  — parse wrapped blob + KMIP Decrypt

Each operation uses `execute_fn()` to dispatch a lambda to a KMIP worker thread. The lambda receives a pooled TLS connection and calls the appropriate libkmip function.

The wrapped DEK blob format is defined in `rgw_kmip_wrapped_dek.h` and parsed by `rgw_kmip_wrapped_dek.cc`. The format is: `[iv_len(4B)][tag_len(4B)][iv][tag][ciphertext]`.

The interface (`rgw_kmip_sse_s3_backend.h`) is abstract, allowing unit tests to use a mock implementation without a real KMIP server.

### KMIP Client Layer (`rgw_kmip_client.cc`,  `rgw_kmip_client_impl.cc`)

This layer manages worker threads and TLS connections to the KMIP server. It provides two dispatch mechanisms:

**Struct-based dispatch** (used by SSE-KMS): The caller fills fields on an `RGWKMIPTransceiver` object (operation type, key name, etc.) and calls `process()`. The worker thread builds the KMIP message from these fields using a switch/case in `do_one_entry()`.

**Lambda-based dispatch** (used by SSE-S3): The caller passes a lambda via `execute_fn()`. The lambda is wrapped in an `FnOp` object and dispatched to a worker thread. The worker calls the lambda directly with its pooled KMIP connection, bypassing the struct-based message builder.

Both dispatch mechanisms share the same worker pool and connection pool.

### libkmip

The lowest layer. It handles KMIP protocol encoding/decoding (TTLV binary format) and TLS communication. The high-level API in `kmip_bio.c` provides one function per KMIP operation (e.g., `kmip_bio_encrypt_with_context()`). Each function builds request structs, encodes them to TTLV bytes, sends them over the TLS connection, receives the response, and decodes it back to structs.