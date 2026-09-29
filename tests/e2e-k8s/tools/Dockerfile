# The e2e client image: curl, plus whatever tests/e2e-k8s/lib.sh stages in
# bin/ (linux mc and MinIO for the multisite test).
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates jq \
 && rm -rf /var/lib/apt/lists/*
COPY bin/ /usr/local/bin/
