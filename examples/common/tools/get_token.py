"""Print a Keycloak access token for one of the examples' users:

  docker compose run --rm -T test python /common/get_token.py alice
"""
import sys

from lakekit import token

print(token(sys.argv[1]))
