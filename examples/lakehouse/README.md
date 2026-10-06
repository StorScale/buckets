# Lakehouse example: Buckets, Nessie, Trino, Apache Ranger, Keycloak

Iceberg tables in Buckets, Nessie as the catalog, Trino as the SQL engine, and Apache Ranger deciding who may query what, down to masked columns and filtered rows. Keycloak is the identity provider for Trino, Ranger and Buckets alike.

```bash
docker compose up -d --wait     # start and configure
docker compose run --rm test    # the end-to-end checks
docker compose down -v          # stop and delete everything
```

The guide, [docs/integrations/lakehouse.md](../../docs/integrations/lakehouse.md), explains how each piece is set up and what to change for production.

| Path | What it is |
|---|---|
| `compose.yaml` | The stack |
| `.env` | Every password and key: local test values only |
| `keycloak/lakehouse-realm.json` | Users alice, bob and carol; groups `analysts` and `engineers`; client `lakehouse` |
| `trino/` | Trino's configuration: HTTPS and JWT sign-in, the Ranger plugin, the Iceberg catalog |
| `ranger/create-ranger-services.py` | Replaces the Ranger image's bootstrap script (see the guide's troubleshooting) |
| `tools/setup.py` | Configures Buckets (buckets, policies, service accounts) and Ranger (users, groups, the Trino service, policies) |
| `tools/test.py` | The checks |
| `tools/get_token.py` | Prints a user's Keycloak token, for the Trino CLI |

UIs: Ranger at http://localhost:6080 (`admin`, `RANGER_PASSWORD`), Nessie at http://localhost:19120, Buckets' S3 API at http://localhost:9000.
