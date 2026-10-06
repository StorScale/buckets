# Setup and test runner for the examples: mc (MinIO publishes no images any
# more, so it is built from source), the Trino and Spark Connect Python
# clients, boto3, and openssl for Trino's self-signed certificate.
FROM golang:1.24-bookworm AS mc
RUN CGO_ENABLED=0 go install github.com/minio/mc@v0.0.0-20251106162529-77f82e18b540

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl curl \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir trino==0.340.0 boto3==1.43.108 requests==2.34.2 pyspark-client==4.1.3 websocket-client==1.9.2
COPY --from=mc /go/bin/mc /usr/local/bin/mc
WORKDIR /work
