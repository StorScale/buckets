# Hive Metastore and Spark example: Buckets, Hive Metastore, Spark, Trino, Apache Ranger, Keycloak

Hive and Iceberg tables in Buckets, with the Hive Metastore as the one catalog for Spark and Trino. Spark writes and transforms tables; Trino queries them, with Apache Ranger deciding who may see what, down to masked columns and filtered rows. Keycloak is the identity provider for Trino, Ranger and Buckets alike.

```bash
docker compose up -d --wait     # build, start and configure
docker compose run --rm test    # the end-to-end checks
docker compose down -v          # stop and delete everything
```

The guide, [docs/integrations/hive-spark.md](../../docs/integrations/hive-spark.md), explains how each piece is set up and what to change for production. Run one example at a time: they use the same ports.

| Path | What it is |
|---|---|
| `compose.yaml` | The stack |
| `.env` | Every password and key: local test values only |
| `images/Dockerfile` | The metastore image (Hive Metastore 4.2.1 with Postgres and S3A) and the Spark image (Spark 4.1.3 with S3A and Iceberg) |
| `hive/` | The metastore's configuration: Postgres, the warehouse in Buckets, the Iceberg REST catalog |
| `spark/spark-defaults.conf` | Spark's configuration: the metastore, Buckets, the Iceberg catalog |
| `trino/catalog/` | Trino's `hive` and `iceberg` catalogs, both on the metastore |
| `tools/setup.py` | Configures Buckets (buckets, policies, service accounts) and Ranger (users, groups, the Trino service, policies) |
| `tools/test.py` | The checks |

Trino's sign-in and Ranger plugin, the Keycloak realm and the tools image are shared with the other examples, in [`../common`](../common).

UIs and endpoints: Ranger at http://localhost:6080 (`admin`, `RANGER_PASSWORD`), Spark Connect at `sc://localhost:15002`, the metastore at `thrift://localhost:9083`, Buckets' S3 API at http://localhost:9000.
