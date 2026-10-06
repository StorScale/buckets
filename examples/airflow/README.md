# Airflow example: Apache Airflow on the lakehouse, with Keycloak for people and pipelines

People sign in to Airflow with Keycloak, and their groups are their Airflow roles (engineers: Op, analysts: Viewer). Pipelines run as a Keycloak service account of their own: each task gets a short-lived token and uses it in Buckets (through STS, under the `pipelines` policy) and in Trino (under Ranger's policies for the `pipelines` group). Airflow stores no S3 keys and no Trino password. This example includes the [lakehouse](../lakehouse) stack.

```bash
docker compose up -d --wait     # the lakehouse, plus Airflow
docker compose run --rm test    # the end-to-end checks
docker compose down -v          # stop and delete everything
```

In a browser: add `127.0.0.1 keycloak airflow` to `/etc/hosts` and open http://airflow:8090. The guide, [docs/integrations/airflow.md](../../docs/integrations/airflow.md), explains how each piece is set up and what to change for production. Run one example at a time: they use the same ports.

| Path | What it is |
|---|---|
| `compose.yaml` | Airflow (API server, scheduler, DAG processor), its database and setup, and the included lakehouse |
| `lakehouse-override.yaml` | What changes in the lakehouse: Keycloak gets Airflow's client secrets |
| `.env` | Airflow's passwords and keys (the lakehouse's are in `../lakehouse/.env`): local test values only |
| `images/Dockerfile` | Airflow 3.3 with the Trino client |
| `airflow/webserver_config.py` | Keycloak sign-in (FAB auth manager), groups as roles, refusing anyone in neither group |
| `dags/sales_ingest.py` | The pipeline: land a file in Buckets, load it into the lakehouse through Trino |
| `dags/lakehouse_identity.py` | How tasks get their identity: the service account's token, STS, and a Trino connection |
| `tools/airflow_setup.py` | Buckets' `landing` bucket and `pipelines` policy; Ranger's service account and grants; the data |
| `tools/test.py` | The checks: real Keycloak sign-ins, a run through Airflow's API, and where its work landed, as whom |
