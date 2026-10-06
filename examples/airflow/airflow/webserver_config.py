"""Sign-in to Airflow's UI and API (the FAB auth manager): Keycloak, through
OpenID Connect. Keycloak's groups are Airflow's roles, set again at every
sign-in; anyone in neither group is refused."""
import os

from flask_appbuilder.security.manager import AUTH_OAUTH

from airflow.providers.fab.auth_manager.security_manager.override import FabAirflowSecurityManagerOverride

KEYCLOAK = "http://keycloak:8080/realms/lakehouse"
AUTH_TYPE = AUTH_OAUTH
OAUTH_PROVIDERS = [{
    "name": "keycloak", "icon": "fa-key", "token_key": "access_token",
    "remote_app": {
        "client_id": "airflow",
        "client_secret": os.environ["AIRFLOW_OAUTH_SECRET"],
        "server_metadata_url": f"{KEYCLOAK}/.well-known/openid-configuration",
        "api_base_url": f"{KEYCLOAK}/protocol/openid-connect/",
        "client_kwargs": {"scope": "openid profile email"},
    },
}]

# Engineers operate pipelines (trigger, clear, see connections); analysts
# watch them. Nobody gets Admin from Keycloak here.
ALLOWED_GROUPS = {"analysts", "engineers"}
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Viewer"
AUTH_ROLES_MAPPING = {"engineers": ["Op"], "analysts": ["Viewer"]}
AUTH_ROLES_SYNC_AT_LOGIN = True


class KeycloakSecurityManager(FabAirflowSecurityManagerOverride):
    def get_oauth_user_info(self, provider, resp):
        me = self.appbuilder.sm.oauth_remotes[provider].get("userinfo").json()
        return {"username": me["preferred_username"], "email": me.get("email", ""),
                "first_name": me.get("given_name", ""), "last_name": me.get("family_name", ""),
                "role_keys": me.get("groups", [])}

    def auth_user_oauth(self, userinfo):
        if not ALLOWED_GROUPS & set(userinfo.get("role_keys", [])):
            return None
        return super().auth_user_oauth(userinfo)


SECURITY_MANAGER_CLASS = KeycloakSecurityManager
