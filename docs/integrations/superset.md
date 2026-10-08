# Apache Superset on Buckets, with Keycloak sign-in and Ranger per person

This guide puts Apache Superset on the [lakehouse](lakehouse.md) (Buckets, Nessie, Trino, Apache Ranger, Keycloak), with one identity from sign-in to storage:
- People sign in to **Superset** with **Keycloak**. Their Keycloak groups are their Superset roles, set again at every sign-in, and anyone in neither group is refused.
- Superset runs every query in **Trino as the person who asked**: in SQL Lab, charts and dashboards alike. So **Ranger** applies that person's policies, column masks and row filters, and its audit log names them.
- Superset has one service credential, for Trino. It has no access to Buckets, and holds nobody's data.

Everything runs from [`examples/superset`](../../examples/superset), which includes the lakehouse example's Compose file. A test script checks what this guide says the stack does: it signs people in through Keycloak's login form and uses Superset's API as the web UI does. CI runs it on each change to Buckets.

| Component | Version | Role |
|---|---|---|
| Apache Superset | 6.1.0, with Authlib and the Trino driver | Dashboards, charts, SQL Lab |
| Trino | 483 | SQL engine; runs each query as its person |
| Apache Ranger | 2.9.0 | Policies, masks, row filters and audit, per person |
| Keycloak | 26.8 | Users and groups, OpenID Connect |
| Buckets, Nessie | 1.16.0, 0.108.8 | Storage and the Iceberg catalog, as in the lakehouse |

## How it fits together

```mermaid
flowchart LR
  people([People]) -- sign in --> kc[Keycloak]
  people -- browser --> ss[Superset]
  ss -- OpenID Connect: groups --> kc
  ss -- "as superset, for the person" --> trino[Trino]
  trino -- may superset act for them? what may they see? --> ranger[Ranger]
  trino --> nessie[Nessie] --> buckets[(Buckets)]
  trino --> buckets
```

1. **Sign-in.** Superset sends people to Keycloak (OpenID Connect, through Flask-AppBuilder and Authlib), and reads their username and `groups` from Keycloak's userinfo.
2. **Roles.** `AUTH_ROLES_MAPPING` turns groups into Superset roles, and `AUTH_ROLES_SYNC_AT_LOGIN` applies changes at every sign-in. A custom security manager refuses anyone in neither group.
3. **Queries, as the person.** Superset signs in to Trino as its service user, `superset`, with a password over HTTPS. Impersonation is on, so each query's Trino user is the person who ran it.
4. **Ranger, twice.** Trino asks Ranger whether `superset` may act for that person (an `impersonate` policy), then applies the person's own policies: catalogs, tables, columns, masks and row filters. The audit log records the person.

| | `analysts` (alice) | `engineers` (bob) | Neither (carol) |
|---|---|---|---|
| Sign in to Superset | Yes: roles Gamma, sql_lab, Lakehouse SQL | Yes: roles Alpha, sql_lab, Lakehouse SQL | No |
| Build datasets, charts, dashboards | No (view and explore) | Yes | n/a |
| `iceberg.sales.orders` in SQL Lab and charts | EU rows only, card numbers masked | Everything | n/a |
| `iceberg.sales.payroll` | Denied by Ranger | Yes | n/a |

## Run it

You need Docker with Compose 2.24 or later, and about 6 GB of memory for Docker.

```bash
cd examples/superset
docker compose up -d --wait        # the lakehouse, plus Superset; about 45 seconds once built
docker compose run --rm test
```

```
ok   people sign in to Superset with Keycloak, and their groups become roles  (alice ['Gamma', 'Lakehouse SQL', 'sql_lab'], bob ['Alpha', 'Gamma', 'Lakehouse SQL', 'sql_lab'])
ok   people in neither group can't sign in  (carol's session: HTTP 401)
ok   engineers create datasets, and analysts can't  (bob HTTP 201, alice HTTP 403)
ok   SQL Lab runs alice's query as alice: Ranger's row filter (EU only)  (3 rows, regions ['EU'])
ok   ... and Ranger's column mask (card numbers' last four digits)  (XXXXXXXXXXXX1111)
ok   ... and Ranger's denials (no payroll)  ("Access Denied: Cannot select from columns [employee, salary] in table or view payroll")
ok   bob's queries run as bob: every order, unmasked  (6 rows, first card 4111111111111111)
ok   Ranger's audit log records alice's denied query under her own name  (1 denied requests by alice)

all checks passed
```

`docker compose down -v` stops everything and deletes the data. The passwords are in `.env` and `../lakehouse/.env`, and all of them are for local use only. Run one example at a time: they use the same ports.

**In a browser:** add `127.0.0.1 keycloak superset` to your hosts file, open http://superset:8088, and sign in with Keycloak as `alice` or `bob`.

## How each piece is set up

### Keycloak

The shared realm (`examples/common/keycloak/lakehouse-realm.json`) has a confidential client, `superset`, with the redirect URI `http://superset:8088/oauth-authorized/keycloak` and a groups mapper: group names in the `groups` claim of the ID token, the access token and userinfo.

### Superset

`superset/superset_config.py`:

```python
AUTH_TYPE = AUTH_OAUTH
OAUTH_PROVIDERS = [{
    "name": "keycloak", "token_key": "access_token",
    "remote_app": {
        "client_id": "superset", "client_secret": os.environ["SUPERSET_OAUTH_SECRET"],
        "server_metadata_url": "http://keycloak:8080/realms/lakehouse/.well-known/openid-configuration",
        "api_base_url": "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/",
        "client_kwargs": {"scope": "openid profile email"},
    },
}]
AUTH_USER_REGISTRATION = True
AUTH_ROLES_MAPPING = {
    "analysts": ["Gamma", "sql_lab", "Lakehouse SQL"],
    "engineers": ["Alpha", "sql_lab", "Lakehouse SQL"],
}
AUTH_ROLES_SYNC_AT_LOGIN = True
```

The custom security manager, `KeycloakSecurityManager`, does two things:
- **Reads the person from userinfo:** `preferred_username` and `groups` (as `role_keys`, which the mapping uses).
- **Refuses anyone in neither group.** Without it, they'd get the registration role.

`superset/bootstrap.py` runs after `superset db upgrade` and `superset init`. It creates the database and a role:

```python
d.set_sqlalchemy_uri(f"trino://superset:{password}@trino:8443/iceberg")
d.impersonate_user = True          # each query runs in Trino as its person
d.extra = json.dumps({"engine_params": {"connect_args": {"http_scheme": "https", "verify": "/tls/cert.pem"}}})
```

The role, `Lakehouse SQL`, holds `database_access` on that database, and both groups map to it.

### Trino

People sign in to Trino with a Keycloak token, as in the lakehouse. Services sign in with a password, so this example's Trino accepts both (`trino/config.properties`):

```properties
http-server.authentication.type=PASSWORD,JWT
```

`trino/password-authenticator.properties` points at a bcrypt password file. The `trino-passwords` service makes it with `htpasswd -B -C 10`. `lakehouse-override.yaml` mounts both into the lakehouse's Trino and leaves everything else as the lakehouse has it.

### Ranger

`tools/superset_setup.py` adds a user for the service account, `superset`, and four policies to the lakehouse's:

| Policy | Resource | Who | Allows |
|---|---|---|---|
| superset: queries as people | Trino user `*` | user `superset` | `impersonate` |
| BI tools: system catalog | catalog `system` | analysts, engineers | `use`, `show` |
| BI tools: system metadata schemas, tables | `system.jdbc`, `system.metadata`, and their tables | analysts, engineers | `use`, `show`; `select` |

The `system` policies exist because BI tools read table metadata through Trino's drivers: `system.jdbc` and `system.metadata.table_comments`, as the person. Without them, Superset can't add a table as a dataset. Trino filters those tables to what each person may see.

Everything else, from catalogs to masks and row filters, is the lakehouse's policies, unchanged. They apply in Superset because the queries run as the people they're written for.

## Going to production

Everything in the [lakehouse guide's list](lakehouse.md#going-to-production) applies. In addition:
- **HTTPS for Superset,** usually behind a proxy that terminates TLS. Set `ENABLE_PROXY_FIX`, and keep `TALISMAN_ENABLED` on; the example turns it off for plain HTTP.
- **Narrow the impersonation policy.** `superset` may act for anyone (`*`) here. Limit it to the groups that use Superset, so the service can't act for administrators.
- **Secrets:** `SUPERSET_SECRET_KEY`, the OAuth client secret and the Trino service password belong in a secret store.
- **Async queries and caching** need Celery and Redis. Results cached for one person must never be served to another. With impersonation, check every cache you add (query results, chart data, thumbnails) to make sure it's kept per person.
- **Per-person tokens instead of impersonation.** Newer Superset releases can authorize some databases with each person's own OAuth2 token. Check your version's support for Trino. That removes the service credential, at the cost of an authorization step for each person. Impersonation, as here, is simpler, and Ranger's audit still records the person.

## Troubleshooting

| Symptom | Cause |
|---|---|
| A person in a mapped group ends up back on the login page | The `groups` claim is missing from userinfo, so the security manager refuses them. Check the client's groups mapper. |
| Superset: `Table ... could not be found` when adding a dataset; Trino: `Access Denied: Cannot access catalog system` or `Cannot select from columns ... in table or view table_comments` | The metadata queries run as the person. Grant `system.jdbc` and `system.metadata` as above. |
| Trino: `Principal superset cannot become user alice` | There's no Ranger `impersonate` policy for `superset` on Trino users. |
| Superset can't connect to Trino: authentication errors | Trino accepts passwords only over HTTPS: the connection needs `http_scheme: https`. The password must match the bcrypt file. |
| Every query is denied, for everyone | Impersonation is off for the database, so queries run as `superset`, which has no table policies of its own. Turn on `impersonate_user`. |
