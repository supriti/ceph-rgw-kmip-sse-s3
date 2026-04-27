# PyKMIP server for RGW KMIP testing (SSE-KMS / SSE-S3).
# Expects certs and conf mounted at /certs and /conf.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pykmip

# Default config; overridden by volume mount.
COPY conf/ /conf/

EXPOSE 5696

# Server binds to 0.0.0.0 so it's reachable from host/other containers.
# Config must set hostname=0.0.0.0 and paths to /certs and /conf.
CMD ["pykmip-server", "-f", "/conf/server.conf", "-l", "/dev/stderr"]
