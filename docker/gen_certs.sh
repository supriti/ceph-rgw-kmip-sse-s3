#!/usr/bin/env bash
# Generate CA, server cert, and client cert for PyKMIP (RGW uses client cert).
#
# RGW enables SSL_VERIFY_PEER and SSL_set1_host() using the host part of
# rgw_crypt_kmip_addr. If you connect by Docker IP (e.g. 172.18.0.2), the server
# cert must include that IP in Subject Alternative Name, or use hostname pykmip.
#
# Optional: include a bridge IP in the server cert:
#   KMIP_SERVER_SAN_IP=172.18.0.2 ./gen_certs.sh
set -e
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CERTS_DIR="${SCRIPT_DIR}/certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 3650 -nodes -subj "/CN=KMIP-CA"
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/CN=pykmip"

SAN="DNS:pykmip,DNS:localhost,IP:127.0.0.1"
if [[ -n "${KMIP_SERVER_SAN_IP:-}" ]]; then
  SAN="${SAN},IP:${KMIP_SERVER_SAN_IP}"
fi
cat >server.ext <<EOF
[v3_req]
subjectAltName=${SAN}
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 \
  -extfile server.ext -extensions v3_req

openssl req -newkey rsa:2048 -keyout client.key -out client.csr -nodes -subj "/CN=rgw-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650
rm -f server.csr client.csr server.ext
echo "Generated certs in $CERTS_DIR (server SAN: ${SAN})"
