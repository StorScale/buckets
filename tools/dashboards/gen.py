#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Writes the Grafana dashboards the operator's Helm chart ships
(operator/helm/buckets-operator/monitoring/dashboards/*.json). Edit this file,
then run it; tests/monitoring/check_metrics.py checks every query's metrics.

  python3 tools/dashboards/gen.py"""
import json, os

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "operator", "helm", "buckets-operator", "monitoring", "dashboards")
DS = {"type": "prometheus", "uid": "${datasource}"}
SEL = 'namespace="$namespace", buckets_cluster="$cluster"'


def q(scope, metric, extra=""):
    """metric{namespace, cluster, scope[, extra]}"""
    return f'{metric}{{{SEL}, scope="{scope}"{", " + extra if extra else ""}}}'


class Board:
    def __init__(self, uid, title, description):
        self.uid, self.title, self.description = uid, title, description
        self.panels, self.x, self.y, self.row_h, self.id = [], 0, 0, 0, 0

    def _place(self, w, h):
        if self.x + w > 24:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_h = max(self.row_h, h)
        self.id += 1
        return pos

    def row(self, title):
        if self.x:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        self.id += 1
        self.panels.append({"type": "row", "title": title, "id": self.id, "collapsed": False,
                            "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1}, "panels": []})
        self.y += 1

    def stat(self, title, expr, unit="none", w=4, h=4, thresholds=None, mappings=None, description=""):
        steps = thresholds or [{"color": "green", "value": None}]
        self.panels.append({
            "type": "stat", "title": title, "description": description, "id": self.id + 1, "datasource": DS,
            "gridPos": self._place(w, h),
            "targets": [{"refId": "A", "expr": expr, "datasource": DS, "instant": True}],
            "fieldConfig": {"defaults": {"unit": unit, "mappings": mappings or [],
                                         "thresholds": {"mode": "absolute", "steps": steps}}, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                        "colorMode": "background", "graphMode": "none", "textMode": "auto"},
        })

    def series(self, title, targets, unit="none", w=12, h=8, stack=False, description=""):
        self.panels.append({
            "type": "timeseries", "title": title, "description": description, "id": self.id + 1, "datasource": DS,
            "gridPos": self._place(w, h),
            "targets": [{"refId": chr(65 + i), "expr": e, "legendFormat": l, "datasource": DS} for i, (e, l) in enumerate(targets)],
            "fieldConfig": {"defaults": {"unit": unit, "custom": {"fillOpacity": 10, "showPoints": "never",
                                                                  "stacking": {"mode": "normal" if stack else "none"}}},
                            "overrides": []},
            "options": {"legend": {"displayMode": "table", "placement": "bottom", "calcs": ["lastNotNull", "max"]},
                        "tooltip": {"mode": "multi", "sort": "desc"}},
        })

    def table(self, title, targets, w=24, h=8, description=""):
        self.panels.append({
            "type": "table", "title": title, "description": description, "id": self.id + 1, "datasource": DS,
            "gridPos": self._place(w, h),
            "targets": [{"refId": chr(65 + i), "expr": e, "legendFormat": l, "datasource": DS, "instant": True,
                         "format": "table"} for i, (e, l) in enumerate(targets)],
            "transformations": [{"id": "merge"}, {"id": "organize", "options": {"excludeByName": {"Time": True}}}],
            "fieldConfig": {"defaults": {}, "overrides": []},
            "options": {"showHeader": True},
        })

    def json(self):
        variables = [
            {"name": "datasource", "label": "Prometheus", "type": "datasource", "query": "prometheus", "hide": 0,
             "current": {}},
            {"name": "namespace", "label": "Namespace", "type": "query", "datasource": DS, "refresh": 2, "hide": 0,
             "query": {"query": 'label_values(minio_cluster_drive_total{scope="cluster"}, namespace)', "refId": "ns"},
             "definition": 'label_values(minio_cluster_drive_total{scope="cluster"}, namespace)', "current": {}},
            {"name": "cluster", "label": "Cluster", "type": "query", "datasource": DS, "refresh": 2, "hide": 0,
             "query": {"query": 'label_values(minio_cluster_drive_total{scope="cluster", namespace="$namespace"}, buckets_cluster)',
                       "refId": "cl"},
             "definition": 'label_values(minio_cluster_drive_total{scope="cluster", namespace="$namespace"}, buckets_cluster)',
             "current": {}},
        ]
        return {
            "uid": self.uid, "title": self.title, "description": self.description, "tags": ["buckets"],
            "timezone": "browser", "schemaVersion": 39, "version": 1, "editable": True, "refresh": "30s",
            "time": {"from": "now-6h", "to": "now"}, "templating": {"list": variables},
            "annotations": {"list": []}, "links": [], "panels": self.panels,
        }


def overview():
    b = Board("buckets-overview", "Buckets / Overview", "Health, capacity and traffic of a Buckets cluster.")
    b.row("Health")
    b.stat("Cluster health", f"max({q('cluster', 'minio_cluster_health_status')})",
           mappings=[{"type": "value", "options": {"1": {"text": "Healthy", "color": "green"},
                                                    "0": {"text": "Degraded", "color": "red"}}}],
           thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}])
    b.stat("Drives offline", f"max({q('cluster', 'minio_cluster_drive_offline_total')})",
           thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
    b.stat("Drives online", f"max({q('cluster', 'minio_cluster_drive_online_total')})")
    b.stat("Servers offline", f"max({q('cluster', 'minio_cluster_nodes_offline_total')})",
           thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
    b.stat("Servers online", f"max({q('cluster', 'minio_cluster_nodes_online_total')})")
    b.stat("Drives healing", f"sum(max by (pool, set) ({q('cluster', 'minio_cluster_health_erasure_set_healing_drives')}))",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}])
    b.row("Capacity")
    used = (f"1 - min({q('cluster', 'minio_cluster_capacity_usable_free_bytes')})"
            f" / max({q('cluster', 'minio_cluster_capacity_usable_total_bytes')})")
    b.stat("Usable capacity used", used, unit="percentunit", w=6,
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 0.85}, {"color": "red", "value": 0.95}])
    b.stat("Usable free", f"min({q('cluster', 'minio_cluster_capacity_usable_free_bytes')})", unit="bytes", w=6)
    b.stat("Usable total", f"max({q('cluster', 'minio_cluster_capacity_usable_total_bytes')})", unit="bytes", w=6)
    b.stat("Objects", f"max({q('cluster', 'minio_cluster_usage_object_total')})", unit="short", w=6)
    b.series("Usable capacity", [
        (f"max({q('cluster', 'minio_cluster_capacity_usable_total_bytes')})", "total"),
        (f"max({q('cluster', 'minio_cluster_capacity_usable_total_bytes')}) - min({q('cluster', 'minio_cluster_capacity_usable_free_bytes')})", "used"),
    ], unit="bytes", w=24)
    b.row("Traffic")
    b.series("S3 requests", [
        (f"sum(rate({q('node', 'minio_s3_requests_total')}[5m]))", "requests"),
        (f"sum(rate({q('node', 'minio_s3_requests_4xx_errors_total')}[5m])) or vector(0)", "4xx"),
        (f"sum(rate({q('node', 'minio_s3_requests_5xx_errors_total')}[5m])) or vector(0)", "5xx"),  # absent until one fails
    ], unit="reqps")
    b.series("Time to first byte", [
        (f"histogram_quantile(0.5, sum by (le) (rate({q('node', 'minio_s3_requests_ttfb_seconds_distribution')}[5m])))", "p50"),
        (f"histogram_quantile(0.99, sum by (le) (rate({q('node', 'minio_s3_requests_ttfb_seconds_distribution')}[5m])))", "p99"),
    ], unit="s")
    b.series("Throughput", [
        (f"sum(rate({q('node', 'minio_s3_traffic_received_bytes')}[5m]))", "received"),
        (f"sum(rate({q('node', 'minio_s3_traffic_sent_bytes')}[5m]))", "sent"),
    ], unit="Bps")
    b.series("Requests by API", [(f"sum by (api) (rate({q('node', 'minio_s3_requests_total')}[5m]))", "{{api}}")],
             unit="reqps", stack=True)
    return b


def drives():
    b = Board("buckets-drives", "Buckets / Drives and healing", "Every drive's space, errors and latency; erasure sets and healing.")
    b.row("Erasure sets")
    b.series("Online drives against write quorum", [
        (f"min by (pool, set) ({q('cluster', 'minio_cluster_health_erasure_set_online_drives')})", "pool {{pool}} set {{set}} online"),
        (f"max by (pool, set) ({q('cluster', 'minio_cluster_health_erasure_set_write_quorum')})", "pool {{pool}} set {{set}} write quorum"),
    ], description="When a set's online drives reach its write quorum, one more failure stops writes to it.")
    b.series("Healing drives", [(f"max by (pool, set) ({q('cluster', 'minio_cluster_health_erasure_set_healing_drives')})",
                                 "pool {{pool}} set {{set}}")])
    b.row("Drives")
    b.table("Drives", [
        (f"max by (server, drive) ({q('node', 'minio_node_drive_used_bytes')})", "used"),
        (f"max by (server, drive) ({q('node', 'minio_node_drive_free_bytes')})", "free"),
        (f"max by (server, drive) ({q('node', 'minio_node_drive_total_bytes')})", "total"),
        (f"sum by (server, drive) (increase({q('node', 'minio_node_drive_errors_ioerror')}[1h]))", "I/O errors (1h)"),
        (f"sum by (server, drive) (increase({q('node', 'minio_node_drive_errors_timeout')}[1h]))", "timeouts (1h)"),
    ])
    b.series("Drive space used", [
        (f"max by (server, drive) ({q('node', 'minio_node_drive_used_bytes')}) / max by (server, drive) ({q('node', 'minio_node_drive_total_bytes')})",
         "{{server}} {{drive}}")], unit="percentunit")
    b.series("Drive errors", [
        (f"sum by (server, drive) (rate({q('node', 'minio_node_drive_errors_ioerror')}[5m]))", "{{server}} {{drive}} I/O"),
        (f"sum by (server, drive) (rate({q('node', 'minio_node_drive_errors_timeout')}[5m]))", "{{server}} {{drive}} timeout"),
    ], unit="ops")
    b.series("Drive latency", [(f"max by (server, drive, api) ({q('node', 'minio_node_drive_latency_us')})", "{{server}} {{drive}} {{api}}")],
             unit="µs", w=24)
    b.row("Healing")
    b.series("Objects healed", [
        (f"max(rate({q('cluster', 'minio_heal_objects_heal_total')}[5m]))", "healed"),
        (f"max(rate({q('cluster', 'minio_heal_objects_errors_total')}[5m]))", "errors"),
    ], unit="ops", w=24)
    return b


def buckets():
    b = Board("buckets-buckets", "Buckets / Buckets", "Usage, object counts, quotas and replication per bucket.")
    b.row("Usage")
    b.table("Buckets", [
        (f"max by (bucket) ({q('bucket', 'minio_bucket_usage_total_bytes')})", "size"),
        (f"max by (bucket) ({q('bucket', 'minio_bucket_usage_object_total')})", "objects"),
        (f"max by (bucket) ({q('bucket', 'minio_bucket_usage_version_total')})", "versions"),
        (f"max by (bucket) ({q('bucket', 'minio_bucket_quota_total_bytes')})", "quota"),
    ])
    b.series("Size", [(f"max by (bucket) ({q('bucket', 'minio_bucket_usage_total_bytes')})", "{{bucket}}")], unit="bytes", stack=True)
    b.series("Objects", [(f"max by (bucket) ({q('bucket', 'minio_bucket_usage_object_total')})", "{{bucket}}")], unit="short", stack=True)
    b.row("Replication")
    b.series("Replicated", [
        (f"sum by (bucket) (rate({q('bucket', 'minio_bucket_replication_sent_bytes')}[5m]))", "{{bucket}} sent"),
        (f"sum by (bucket) (rate({q('bucket', 'minio_bucket_replication_received_bytes')}[5m]))", "{{bucket}} received"),
    ], unit="Bps")
    b.series("Failed in the last hour", [
        (f"max by (bucket) ({q('bucket', 'minio_bucket_replication_last_hour_failed_count')})", "{{bucket}}")], unit="short")
    return b


def access():
    b = Board("buckets-access", "Buckets / Access and services", "Sign-ins, rejected requests and the KMS.")
    b.row("Sign-ins")
    b.series("Rejected S3 requests (bad credentials)", [
        (f"sum(rate({q('node', 'minio_s3_requests_rejected_auth_total')}[5m])) or vector(0)", "bad credentials"),
        (f"sum(rate({q('node', 'minio_s3_requests_rejected_timestamp_total')}[5m])) or vector(0)", "clock skew"),
        (f"sum(rate({q('node', 'minio_s3_requests_rejected_invalid_total')}[5m])) or vector(0)", "invalid"),
    ], unit="reqps")
    b.series("Failed console sign-ins", [
        (f'sum by (method) (rate(buckets_console_logins_failed_total{{{SEL}}}[5m]))', "{{method}}")], unit="reqps")
    b.series("Client errors by API", [(f"sum by (api) (rate({q('node', 'minio_s3_requests_4xx_errors_total')}[5m]))", "{{api}}")],
             unit="reqps", w=24)
    b.row("KMS")
    b.series("KMS requests", [
        (f"sum(rate({q('cluster', 'minio_cluster_kms_request_success')}[5m]))", "succeeded"),
        (f"sum(rate({q('cluster', 'minio_cluster_kms_request_error')}[5m]))", "refused"),
        (f"sum(rate({q('cluster', 'minio_cluster_kms_request_failure')}[5m]))", "failed (unreachable)"),
    ], unit="reqps", w=24, description="Only clusters with a KMS have these.")
    return b


def main():
    os.makedirs(OUT, exist_ok=True)
    for board in (overview(), drives(), buckets(), access()):
        with open(os.path.join(OUT, board.uid + ".json"), "w") as f:
            json.dump(board.json(), f, indent=1, ensure_ascii=False)
            f.write("\n")
        print("wrote", board.uid + ".json", len(board.panels), "panels")


if __name__ == "__main__":
    main()
