"""A small client for Dremio's REST API: sign-in, sources, SQL."""
import os
import time

import requests

DREMIO = "http://dremio:9047"


class Dremio:
    def __init__(self, user="admin", password=None):
        r = requests.post(f"{DREMIO}/apiv2/login", timeout=30,
                          json={"userName": user, "password": password or os.environ["DREMIO_ADMIN_PASSWORD"]})
        r.raise_for_status()
        self.h = {"Authorization": f"_dremio{r.json()['token']}", "Content-Type": "application/json"}

    def api(self, method, path, **kw):
        r = requests.request(method, f"{DREMIO}/api/v3{path}", headers=self.h, timeout=60, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"Dremio {method} {path}: {r.status_code} {r.text[:600]}")
        return r.json() if r.text.strip() else None

    def sql(self, statement, timeout=180):
        """Run a statement; returns (rows, error message)."""
        job = self.api("POST", "/sql", json={"sql": statement})["id"]
        deadline = time.time() + timeout
        while True:
            j = self.api("GET", f"/job/{job}")
            if j["jobState"] == "COMPLETED":
                return self.api("GET", f"/job/{job}/results?limit=500")["rows"], None
            if j["jobState"] in ("FAILED", "CANCELED"):
                return None, j.get("errorMessage", j["jobState"])
            if time.time() > deadline:
                raise TimeoutError(f"Dremio job {job}: {statement}")
            time.sleep(1)
