# Monitoring example: Buckets, Prometheus, Grafana

A four-drive Buckets server with steady S3 traffic, scraped by Prometheus as [docs/monitoring.md](../../docs/monitoring.md) describes (a metrics-only user's bearer token, the `buckets_cluster`, `scope` and `namespace` labels), with the Helm chart's alert rules loaded and its four Grafana dashboards provisioned. The rules and dashboards are mounted straight from `operator/helm/buckets-operator/monitoring`, so this runs exactly what the chart installs.

```bash
docker compose up -d --wait               # start, and configure
docker compose run --rm test              # the checks: scraping, rules, dashboards, and a drive failure
docker compose run --rm screenshots       # the dashboards as PNGs in ./screenshots
docker compose down -v                    # stop and delete everything
```

Grafana is at http://localhost:3000 (`admin`, `GRAFANA_ADMIN_PASSWORD` in `.env`), under **Dashboards → Buckets**. Prometheus is at http://localhost:9090, with the rules under **Alerts**.

The test makes one drive unreadable under load, as a dying disk looks, and checks that Buckets reports the drive offline and the `BucketsDriveOffline` and `BucketsErasureSetDegraded` alerts start, then that the drive comes back online once it can be read again. (A drive emptied instead, as a disk swapped for a new one looks, is formatted back into its slot and healed within seconds, often before Prometheus would see it offline.) Run `docker compose down -v` to start over.

`screenshots` uses headless Chromium (Playwright) and Grafana's kiosk mode. Set `SHOTS=alerts` while a drive is out for Prometheus's alerts page, `SHOTS=failure` after one for the Overview and Drives dashboards, and `SCREENSHOTS_DIR` to write somewhere other than `./screenshots`.

| Path | What it is |
|---|---|
| `compose.yaml` | Buckets (four drives), Prometheus, Grafana, the traffic, the checks and the screenshots |
| `prometheus/prometheus.yml` | The scrape configuration from docs/monitoring.md, and the chart's rules |
| `grafana/provisioning/` | The Prometheus data source, and the chart's dashboards |
| `tools/setup.py` | The metrics-only user and its token (`mc admin prometheus generate`); buckets with data |
| `tools/traffic.py` | S3 traffic: uploads, downloads, listings, deletes, misses, bad credentials |
| `tools/test.py` | The checks |
| `tools/screenshots.py` | The dashboards as PNGs |
