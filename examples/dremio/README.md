# Dremio example: Dremio on the lakehouse's Nessie catalog

Dremio queries the lakehouse's Iceberg tables through the same Nessie catalog Trino writes them to, including earlier Nessie commits (`AT COMMIT`), and queries raw Parquet files in Buckets. Its Buckets service account may only read, so Buckets refuses Dremio's writes. This example includes the [lakehouse](../lakehouse) stack.

```bash
docker compose up -d --wait     # the lakehouse, plus Dremio
docker compose run --rm test    # the end-to-end checks (waits for Dremio's setup)
docker compose down -v          # stop and delete everything
```

Dremio's UI is at http://localhost:9047 (`admin`, `DREMIO_ADMIN_PASSWORD`). The guide, [docs/integrations/dremio.md](../../docs/integrations/dremio.md), explains how each piece is set up, what Dremio's open-source edition does for identity, and what to change for production. Run one example at a time: they use the same ports.

| Path | What it is |
|---|---|
| `compose.yaml` | Dremio and its setup, and the included lakehouse |
| `.env` | Dremio's passwords and keys (the lakehouse's are in `../lakehouse/.env`): local test values only |
| `tools/dremio.py` | A small client for Dremio's REST API |
| `tools/dremio_setup.py` | The data; Dremio's read-only Buckets account; Dremio's administrator and sources |
| `tools/test.py` | The checks |
