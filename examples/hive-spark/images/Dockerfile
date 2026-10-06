# Images for the Hive Metastore and Spark example.
#
#   docker compose build      (compose.yaml builds the "metastore" and "spark" targets)

# Spark's Hadoop 3.4.2: its S3A connector and the AWS SDK v2 it is built
# against (2.29.52); the Postgres driver for the metastore; Iceberg for Spark.
FROM debian:trixie-slim AS jars
ARG MAVEN=https://repo1.maven.org/maven2
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /jars
RUN set -e; get() { curl -fsSLo "$(basename "$1")" "$MAVEN/$1"; }; \
    get software/amazon/awssdk/bundle/2.29.52/bundle-2.29.52.jar; \
    get org/postgresql/postgresql/42.7.13/postgresql-42.7.13.jar; \
    get org/apache/hadoop/hadoop-aws/3.4.2/hadoop-aws-3.4.2.jar; \
    get org/apache/iceberg/iceberg-spark-runtime-4.1_2.13/1.12.0/iceberg-spark-runtime-4.1_2.13-1.12.0.jar

# Hive Metastore 4.2.1 (standalone), with Postgres and S3A. It also serves an
# Iceberg REST catalog, which Spark uses for Iceberg tables. The image has
# Hadoop's S3A connector; the AWS SDK it needs is added here.
FROM apache/hive:standalone-metastore-4.2.1 AS metastore
USER root
COPY --from=jars /jars/postgresql-42.7.13.jar /jars/bundle-2.29.52.jar /opt/hive/lib/
RUN cp /opt/hadoop/share/hadoop/tools/lib/hadoop-aws-3.4.1.jar /opt/hive/lib/
USER hive

# Spark 4.1.3 with S3A and Iceberg; runs a Spark Connect server.
FROM apache/spark:4.1.3-python3 AS spark
USER root
# The Hive 4.1 client's jars are kept here (a volume), owned by spark.
RUN mkdir /ivy && chown spark:spark /ivy
USER spark
COPY --from=jars /jars/bundle-2.29.52.jar /jars/hadoop-aws-3.4.2.jar /jars/iceberg-spark-runtime-4.1_2.13-1.12.0.jar /opt/spark/jars/
