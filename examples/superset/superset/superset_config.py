"""Superset for the Superset example: Keycloak sign-in, Keycloak groups as
Superset roles, and queries to Trino run as the person who signed in."""
import os

from flask_appbuilder.security.manager import AUTH_OAUTH

from superset.security import SupersetSecurityManager

SECRET_KEY = os.environ["SUPERSET_SECRET_KEY"]
SQLALCHEMY_DATABASE_URI = (f"postgresql+psycopg2://superset:{os.environ['SUPERSET_DB_PASSWORD']}"
                           "@superset-db:5432/superset")

# --- Sign-in: Keycloak, through OpenID Connect -----------------------------------------
KEYCLOAK = "http://keycloak:8080/realms/lakehouse"
AUTH_TYPE = AUTH_OAUTH
OAUTH_PROVIDERS = [{
    "name": "keycloak", "icon": "fa-key", "token_key": "access_token",
    "remote_app": {
        "client_id": "superset",
        "client_secret": os.environ["SUPERSET_OAUTH_SECRET"],
        "server_metadata_url": f"{KEYCLOAK}/.well-known/openid-configuration",
        "api_base_url": f"{KEYCLOAK}/protocol/openid-connect/",
        "client_kwargs": {"scope": "openid profile email"},
    },
}]

# Keycloak's groups are Superset's roles, set again at every sign-in. Everyone
# gets SQL Lab and the lakehouse database ("Lakehouse SQL", made by
# bootstrap.py); engineers may also build datasets, charts and dashboards.
ALLOWED_GROUPS = {"analysts", "engineers"}
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Gamma"
AUTH_ROLES_MAPPING = {
    "analysts": ["Gamma", "sql_lab", "Lakehouse SQL"],
    "engineers": ["Alpha", "sql_lab", "Lakehouse SQL"],
}
AUTH_ROLES_SYNC_AT_LOGIN = True


class KeycloakSecurityManager(SupersetSecurityManager):
    def oauth_user_info(self, provider, response=None):
        me = self.appbuilder.sm.oauth_remotes[provider].get("userinfo").json()
        return {"username": me["preferred_username"], "email": me.get("email", ""),
                "first_name": me.get("given_name", ""), "last_name": me.get("family_name", ""),
                "role_keys": me.get("groups", [])}

    def auth_user_oauth(self, userinfo):
        # Only members of the mapped groups get in; anyone else is refused.
        if not ALLOWED_GROUPS & set(userinfo.get("role_keys", [])):
            return None
        return super().auth_user_oauth(userinfo)


CUSTOM_SECURITY_MANAGER = KeycloakSecurityManager

# The example runs on plain HTTP between containers.
TALISMAN_ENABLED = False
WTF_CSRF_ENABLED = True
