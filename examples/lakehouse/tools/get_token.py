"""Print a Keycloak access token for one of the example's users:

  docker compose run --rm -T test python /work/get_token.py alice
"""
import os
import sys

import requests

r = requests.post("http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token", timeout=10, data={
    "grant_type": "password", "client_id": "lakehouse",
    "username": sys.argv[1], "password": os.environ["LAKEHOUSE_USER_PASSWORD"]})
r.raise_for_status()
print(r.json()["access_token"])
