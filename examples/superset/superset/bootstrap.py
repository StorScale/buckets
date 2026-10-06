"""Superset's own setup, run by the superset-init service after
`superset db upgrade` and `superset init`:

  - the database "Lakehouse (Trino)": Trino over HTTPS, signed in as the
    superset service user, with impersonation on, so every query runs in
    Trino as the person who asked for it, and Ranger applies their policies;
  - the role "Lakehouse SQL": access to that database.

Safe to run again.
"""
import json
import os

from superset.app import create_app

app = create_app()
with app.app_context():
    from superset import db, security_manager as sm
    from superset.models.core import Database

    name = "Lakehouse (Trino)"
    d = db.session.query(Database).filter_by(database_name=name).one_or_none() or Database(database_name=name)
    d.set_sqlalchemy_uri(f"trino://superset:{os.environ['SUPERSET_TRINO_PASSWORD']}@trino:8443/iceberg")
    d.impersonate_user = True
    d.expose_in_sqllab = True
    d.allow_dml = False
    d.extra = json.dumps({"engine_params": {"connect_args": {"http_scheme": "https", "verify": "/tls/cert.pem"}}})
    db.session.add(d)
    db.session.commit()

    role = sm.find_role("Lakehouse SQL") or sm.add_role("Lakehouse SQL")
    sm.add_permission_role(role, sm.add_permission_view_menu("database_access", d.perm))
    db.session.commit()
    print(f"bootstrap: database {name!r} (id {d.id}, impersonating), role 'Lakehouse SQL'")
