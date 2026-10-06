"""The Grafana dashboards as PNGs, with headless Chromium (Playwright):

    docker compose run --rm screenshots                    # SHOTS=healthy (default)
    docker compose run --rm -e SHOTS=degraded screenshots  # after a drive fails

Writes ./screenshots/<dashboard>.png (healthy) or <dashboard>-degraded.png,
in Grafana's dark theme, the last 15 minutes, in kiosk mode (no menus).
"""
import base64
import os
import time

import requests
from playwright.sync_api import sync_playwright

GRAFANA = "http://grafana:3000"
PROMETHEUS = "http://prometheus:9090"
AUTH = ("admin", os.environ["GRAFANA_ADMIN_PASSWORD"])
SHOTS = os.environ.get("SHOTS", "healthy")
WANT = {"healthy": ["buckets-overview", "buckets-drives", "buckets-buckets", "buckets-access"],
        "degraded": ["buckets-overview", "buckets-drives"]}[SHOTS]


def main():
    header = "Basic " + base64.b64encode(f"{AUTH[0]}:{AUTH[1]}".encode()).decode()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1,
                                extra_http_headers={"Authorization": header})
        for uid in WANT:
            url = (f"{GRAFANA}/d/{uid}?orgId=1&kiosk&theme=dark&from=now-15m&to=now"
                   "&var-namespace=local&var-cluster=store&refresh=")
            page.set_viewport_size({"width": 1600, "height": 1000})
            page.goto(url, wait_until="networkidle")
            time.sleep(4)
            # Make the window as tall as the dashboard, so kiosk mode's footer
            # sits below it rather than over a panel, then let panels redraw.
            height = page.evaluate("() => Math.max(...[...document.querySelectorAll('*')].map(e => e.scrollHeight))")
            page.set_viewport_size({"width": 1600, "height": min(max(height, 1000), 4000)})
            time.sleep(6)
            name = uid.removeprefix("buckets-") + ("-degraded" if SHOTS == "degraded" else "")
            page.screenshot(path=f"/screenshots/{name}.png")
            print(f"screenshots: {name}.png", flush=True)
        if SHOTS == "degraded":
            page.set_extra_http_headers({})
            # Prometheus's UI keeps polling, so wait for the page itself, not the network.
            page.set_viewport_size({"width": 1600, "height": 900})
            page.goto(f"{PROMETHEUS}/alerts?state=firing", wait_until="load")
            time.sleep(5)
            page.screenshot(path="/screenshots/prometheus-alerts.png")
            print("screenshots: prometheus-alerts.png", flush=True)
        browser.close()


if __name__ == "__main__":
    requests.get(f"{GRAFANA}/api/health", timeout=30).raise_for_status()
    main()
