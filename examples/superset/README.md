# Superset example: Apache Superset on the lakehouse, with Keycloak and Ranger

People sign in to Superset with Keycloak, and their Keycloak groups are their Superset roles. Superset runs every query in Trino as the person who asked (impersonation), so Apache Ranger's policies, masks and row filters follow each person into SQL Lab, charts and dashboards. This example includes the [lakehouse](../lakehouse) stack.

```bash
docker compose up -d --wait     # the lakehouse, plus Superset
docker compose run --rm test    # the end-to-end checks
docker compose down -v          # stop and delete everything
```

In a browser: add `127.0.0.1 keycloak superset` to `/etc/hosts` and open http://superset:8088. The guide, [docs/integrations/superset.md](../../docs/integrations/superset.md), explains how each piece is set up and what to change for production. Run one example at a time: they use the same ports.

| Path | What it is |
|---|---|
| `compose.yaml` | Superset, its database and setup, and the included lakehouse |
| `lakehouse-override.yaml` | What changes in the lakehouse: Trino also accepts a password for Superset's service account |
| `.env` | Superset's passwords and keys (the lakehouse's are in `../lakehouse/.env`): local test values only |
| `images/Dockerfile` | Superset 6.1 with the Trino driver, Authlib and the Postgres driver |
| `superset/superset_config.py` | Keycloak sign-in, groups as roles, refusing anyone in neither group |
| `superset/bootstrap.py` | The Trino database, with impersonation, and the `Lakehouse SQL` role |
| `trino/` | Trino's password sign-in, for service accounts |
| `tools/superset_setup.py` | Ranger: impersonation for `superset`, and the system metadata BI tools read; the data |
| `tools/test.py` | The checks: real Keycloak sign-ins, then SQL Lab as each person |
