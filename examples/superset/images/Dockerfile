# Superset 6.1, with what this example needs: the Trino driver (with
# SQLAlchemy), Authlib for Keycloak sign-in, and the Postgres driver for its
# metadata database.
FROM apache/superset:6.1.0
USER root
RUN uv pip install --python /app/.venv/bin/python --no-cache \
      "trino[sqlalchemy]==0.340.0" authlib==1.8.0 psycopg2-binary==2.9.13
USER superset
