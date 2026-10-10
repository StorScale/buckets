# Identity: sign-in with an identity provider and role-based access

People sign in to the console with their organisation account, through OpenID Connect (Microsoft Entra ID, Okta, Keycloak or another provider) or LDAP and Active Directory. The roles or groups they hold in the provider decide what they can do in Buckets. Buckets keeps no copy of the directory: who can sign in, and with which roles, is managed in the provider.

## Set it up in the console

Where buckets-operator runs the cluster, sign-in is set up from the console: **Identity → Sign-in**. It needs the `admin:ConfigUpdate` permission (`consoleAdmin` has it).

1. **Choose the provider.** Turn single sign-on on and pick Microsoft Entra ID, Okta, Keycloak or another OpenID provider. The page lists what to do in the provider, with this console's redirect URI ready to copy (`https://<console host>/oauth_callback`). Turn LDAP on for a directory; both can be on at once.
2. **Fill in the connection.** Entra ID needs the tenant ID, Okta its domain, Keycloak its URL and realm, another provider its discovery URL; all need the client ID and secret. LDAP needs the server, a read-only service account and the user search base. **Advanced** holds the claim naming policies, the scopes, the sign-in button's label and LDAP's filters.
3. **Save.** The settings go to Secret `<cluster>-identity-candidate`. Nothing changes for the cluster yet.
4. **Test.**
   - **OpenID:** **Test sign-in** opens the provider in a window and signs you in with the saved settings. The console checks the ID token exactly as the servers will (signature, audience) and shows the claim's values and the Buckets policies they map to. It is a test: your console session stays as it was. A wrong client secret or redirect URI shows the provider's own error.
   - **LDAP:** **Look up** finds a user with the saved settings and shows their DN, groups and attached policies; with their password, it also checks that they can sign in.
5. **Apply.** Only settings whose every part passed its test apply, and only the very settings tested: an edit means a new test. The console copies them to Secret `<cluster>-identity`, and the operator:
   1. gives them to the servers through the admin API (`config set identity_openid` / `identity_ldap`). Each server checks the provider or the directory before taking them, and a refusal shows on the page in the server's words;
   2. applies OpenID settings at once, without a restart. LDAP is read when the servers start, so an LDAP change restarts them one at a time; S3 stays available;
   3. then gives the console its sign-in settings (Secret `<cluster>-identity-console`, mounted into the console, which takes them up without a restart).

The page shows the result (`status.identity` of the BucketsCluster): **Ready**, or why not.

Secret fields (the client secret, the LDAP service account's password) are never sent back to the browser once saved. Leaving them empty when editing keeps the saved value, for the same provider or directory server only.

The root credentials (`<name>-root` Secret) always sign in with access keys, so settings that turn out wrong cannot lock administrators out.

**Settings elsewhere.** Sign-in settings in `spec.env`, `spec.console.env` or the tenant's `config.env` (an adopted MinIO tenant) would override the page's, so the operator refuses to apply while any is there, and the page names them (**Conflict**). Remove them to manage sign-in from the console. Until settings are applied from the page, the servers keep their own (**Not set up here yet**).

## How OpenID sign-in works

1. Buckets is registered in Entra ID as an app with **app roles**, for example `consoleAdmin`, `readwrite` and `readonly`. Users or groups are assigned to those roles.
2. When someone signs in, Entra ID puts their roles in the ID token's `roles` claim.
3. The console exchanges the token for temporary credentials (STS `AssumeRoleWithWebIdentity`). With `MINIO_IDENTITY_OPENID_CLAIM_NAME=roles`, each role value names a Buckets policy, and the person gets the combined permissions of every policy that exists. Values with no matching policy are ignored.
4. The session lasts an hour. Role changes in Entra ID apply at the next sign-in.

Use app roles rather than Entra security groups: a `groups` claim carries group GUIDs, so policies would have to be named after GUIDs, and people in many groups overflow the token's group limit.

### Roles and policies

Role values can name the built-in policies, so no custom policies are needed to start:

| App role value | Buckets policy | Access |
|---|---|---|
| `consoleAdmin` | built in | Full administration: users, policies, configuration, every bucket |
| `readwrite` | built in | Read and write every bucket |
| `readonly` | built in | List and download from every bucket |

For access to some buckets only, set up a team on the Teams page (below) and give people its roles, such as `team-finance-rw`. Values are matched exactly, including case.

### Teams

**Identity → Teams** gives a group of people their own buckets without writing policies by hand. A team is a name and its buckets: buckets named one by one, and prefixes such as `finance-` that cover every bucket whose name starts with them, including buckets created later. Each access level you choose becomes a policy:

| Level | Policy | Access to the team's buckets |
|---|---|---|
| Read | `team-<name>-ro` | List and download |
| Read and write | `team-<name>-rw` | Read, upload and delete objects |
| Admin | `team-<name>-admin` | Read and write, and the buckets' settings (versioning, lifecycle, encryption, notifications, object lock, replication, tags, CORS); create and delete buckets under the team's prefixes |

None of the levels can reach other buckets or the admin API, and Admin cannot set bucket policies, so a team cannot share its buckets or make them public. Team members see only their team's buckets when they list buckets.

People get a level the way they get any policy: from the identity provider (an Entra app role, an Okta group or a Keycloak realm role named after the policy; the Access dialog shows the step for the provider set up), or as members added on the Teams page (local users and groups, and LDAP users and groups by their DN). Changing a team's buckets applies at once, even to people already signed in.

Teams are stored only as their policies, so they work the same without the operator and survive a move to MinIO and back. A team policy changed by hand (for example with `mc admin policy create`) shows as **edited**, and saving the team asks before replacing the change. Removing a level, or deleting the team, detaches its members and deletes the policies.

## Microsoft Entra ID

In the Microsoft Entra admin center (https://entra.microsoft.com), as an Application Administrator or Cloud Application Administrator:

1. **Register the app.** Identity → Applications → App registrations → New registration:
   - Name: what people see when signing in, for example `Buckets`.
   - Supported account types: this organizational directory only (single tenant).
   - Redirect URI: platform **Web**, `https://<console host>/oauth_callback`.
   - On the app's Overview page, note the **Application (client) ID** and the **Directory (tenant) ID**.
2. **Create a client secret.** Certificates & secrets → Client secrets → New client secret. Copy its **Value** (not the Secret ID) at once; it is shown only once. Note its expiry: sign-in stops working when it expires.
3. **Check Authentication.** The Web redirect URI is listed; under Implicit grant and hybrid flows, leave Access tokens and ID tokens unticked (the console uses the authorization code flow). The default Microsoft Graph `User.Read` permission covers the `openid profile email` scopes; if users cannot consent to apps in your tenant, grant admin consent.
4. **Create the app roles.** App roles → Create app role, once per role: allowed member types **Users/Groups**, and the **Value** exactly as in the table above.
5. **Assign people.** Identity → Applications → Enterprise applications → the app:
   - Properties: set **Assignment required?** to **Yes**, so only assigned people can sign in.
   - Users and groups → Add user/group: pick people or groups and a role. Assigning groups needs Entra ID P1 or P2; members of nested groups are not included.

## Okta

1. In the Okta admin console, Applications → Create App Integration: **OIDC**, **Web Application**.
2. Client authentication: **Client secret**. Sign-in redirect URI: `https://<console host>/oauth_callback`.
3. Security → API → Authorization Servers → **default** → Claims → Add claim: name `groups`, included in the **ID token**, value type **Groups**, with a filter matching the groups named after Buckets policies (for example *Matches regex* `consoleAdmin|readwrite|readonly|team-.*`).
4. Assign people or groups to the app, and copy its client ID and secret.

On the Sign-in page: Okta, the Okta domain (`example.okta.com`), the client ID and secret. The claim (`groups`) and scopes (`openid profile email groups`) are filled in; set the authorization server under Advanced if it is not `default`.

## Keycloak

1. In the realm, Clients → Create client: **OpenID Connect**, client authentication **on**.
2. Valid redirect URIs: `https://<console host>/oauth_callback`. Copy the client secret from the Credentials tab.
3. Client scopes → the client's dedicated scope → Add mapper → **User Realm Role** (or User Client Role): token claim name `roles`, multivalued, added to the **ID token**.
4. Create roles named after Buckets policies, and assign them to people or groups.

On the Sign-in page: Keycloak, its URL (`https://keycloak.example.com`, including `/auth` for Keycloak before version 17), the realm, the client ID and secret.

## LDAP and Active Directory

People sign in with their directory user name and password; the servers bind to the directory as a read-only service account to find the user and their groups (`AssumeRoleWithLDAPIdentity`).

- **Active Directory:** users are found by `sAMAccountName`, groups by `member`.
- **OpenLDAP:** users by `uid` (`inetOrgPerson`), groups by `member` (`groupOfNames`).
- **Other:** your own filters, under Advanced: `%s` is the user name, `%d` the user's DN.

Policies are attached to directory users and groups by DN, for example `mc admin idp ldap policy attach <alias> readwrite --group 'CN=Finance,OU=Groups,DC=corp,DC=example,DC=com'`. Use LDAPS or StartTLS: plain LDAP sends passwords unencrypted.

## Without the console

Outside Kubernetes, or to keep sign-in in Git, set it on the servers and the console instead. Don't mix the two: the operator refuses to apply the Sign-in page's settings while any of these are set.

Keep the client secret in a Kubernetes Secret:

```bash
kubectl -n <namespace> create secret generic entra-oidc --from-literal=client-secret='<secret value>'
```

Then give the servers and the console the provider's settings in the `BucketsCluster`. [operator/examples/cluster-entra.yaml](../operator/examples/cluster-entra.yaml) is a complete example:

| Where | Setting | Value |
|---|---|---|
| `spec.env` (servers) | `MINIO_IDENTITY_OPENID_CONFIG_URL` | `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration` |
| | `MINIO_IDENTITY_OPENID_CLIENT_ID` | the client ID |
| | `MINIO_IDENTITY_OPENID_CLIENT_SECRET` | `valueFrom` the `entra-oidc` Secret |
| | `MINIO_IDENTITY_OPENID_CLAIM_NAME` | `roles` |
| | `MINIO_IDENTITY_OPENID_SCOPES` | `openid,profile,email` |
| `spec.console.env` (console) | `BUCKETS_CONSOLE_OIDC_CONFIG_URL` | the same discovery URL |
| | `BUCKETS_CONSOLE_OIDC_CLIENT_ID` | the client ID |
| | `BUCKETS_CONSOLE_OIDC_CLIENT_SECRET` | `valueFrom` the `entra-oidc` Secret |
| | `BUCKETS_CONSOLE_OIDC_REDIRECT_URI` | `https://<console host>/oauth_callback`, exactly as registered |
| | `BUCKETS_CONSOLE_OIDC_DISPLAY_NAME` | the sign-in button's label, for example `Entra ID` |

Changing `spec.env` restarts the servers one at a time, so S3 stays available. Each server logs `identity_openid: OpenID configured` when it has loaded the provider. The servers and the console must reach `login.microsoftonline.com` over HTTPS.

The console's login page then shows **Sign in with Entra ID**. The root credentials (`<name>-root` Secret) still sign in with access keys, as a fallback.

## Access review

**Identity → Access review** answers who can reach a bucket, and why. It is also one click from every bucket: **Access** on the Buckets page, or **Who has access** in a bucket's settings.

- **Who can reach a bucket.** Pick a bucket and what to check: read, write, delete, manage settings, or any of these. The page lists every route to that access: local users and groups (with their members), LDAP users and groups, OpenID roles, access keys with a policy of their own, the bucket policy (including "everyone, signed in or not"), and the root user. Each row shows whether the access is full, limited to some objects (`only reports/*`) or depends on conditions, and the policy statements that grant it. **Export CSV** saves the list, one line per principal and action, with the time of the review.
- **Would this be allowed?** Pick a user, group, LDAP DN, access key, a set of OpenID roles or "anyone, without signing in", an action, a bucket and an object. The answer is Allowed or Denied, with the statements that decided it: the Allow that grants it, or the Deny that wins over it. A statement with a condition (a source IP, TLS, object tags) decides the answer only when you give its value; otherwise the answer is "depends on conditions".
- **Local users while sign-in uses a provider.** When OpenID or LDAP sign-in is on, the page lists the local users that remain, with their policies and access keys, so the ones nobody needs can be disabled or deleted on the Users page.

The review uses the servers' own policy evaluator, so its answers are the servers' answers. It reads the policies, users, groups and access keys as the person signed in; anything that account may not read is named on the page, as the answer could leave out access that comes through it.

Buckets cannot list everyone your identity provider gives a role. An OpenID role's row says "anyone with the role", followed by the people Buckets has seen signing in with it; check the role's assignments in the provider (in Entra: Enterprise applications → the app → Users and groups).

## The Users page and access keys

- **Users** lists the provider's people that Buckets knows of: everyone signed in now, and anyone holding access keys, with their name, sign-in name and roles. People who have never signed in do not appear.
- **Create user** is hidden while OpenID sign-in is on, so every person signs in through the provider. Local users that already exist are still listed and can be disabled or deleted. Set `BUCKETS_CONSOLE_LOCAL_USERS=on` in `spec.console.env` to offer it again.
- People who need keys for S3 tools (`mc`, the AWS CLI, SDKs) create access keys from the console after signing in. The keys carry the person's roles.

## People who leave

With Entra ID, Keycloak or Okta, Buckets can take away the access of people who
leave. Turning someone off in the provider stops them signing in, but access
keys they made keep working. With **People who leave** on, the servers ask the
provider every hour (**Check every**) about each person holding Buckets
credentials:

- **Deleted or disabled** (in Okta: deactivated or suspended): their temporary
  credentials (and console sessions) end at once. Their access keys are turned
  off at once, and deleted after 30 days (**Delete their access keys after**).
- **Back within those days:** their keys come back on. A key its owner had
  turned off stays off.
- **Shown as such:** the Users page, the Access Keys page and the access review
  say when a key's owner left and when the key will be deleted. The access
  review counts a key that is off as reaching nothing.
- **The provider can't be reached, or answers an error:** whoever it didn't
  answer for is left as they are, and the `BucketsIdentitySyncFailing` alert
  says so.
- **More people leaving at once than the limit** (10 unless set): nobody is
  removed until someone confirms by raising it. This guards against a directory
  that answers wrongly. The `BucketsIdentitySyncHeld` alert says so.

To set it up, on **Identity → Sign-in**, in the single sign-on card, give the
servers a way to read the directory:

| Provider | What to do |
| --- | --- |
| Entra ID | In the app registration, under **API permissions**, add **Microsoft Graph → Application permissions → User.Read.All**, then **Grant admin consent**. The sync signs in as the same app, with its client secret. |
| Keycloak | In the client, under **Settings → Capability config**, turn on **Service accounts roles**. Under **Service accounts roles**, assign **realm-management: view-users**. The sync signs in as the client, with its secret. |
| Okta | As an administrator who may read users (**Read-only Administrator** is enough), create a token under **Security → API → Tokens**, and paste it into **Okta API token**. Okta tokens expire after 30 days unused; the hourly sync keeps it in use. |

Then turn on **Remove the access of people who leave**, save, and **Look up a
person**: the console asks the provider about them as the sync will (an Entra
sign-in name, a Keycloak user name, an Okta login, or an ID). Apply needs this
to pass. The sync only reads users.

Applying restarts the servers one at a time, as LDAP settings do. Each step is
in the log of the server leading the first erasure set (`identity sync:`), and
the counts are in its metrics (`buckets_node_identity_sync_*`). People are
matched by the IDs in their sign-in tokens: Entra's `tid` and `oid`, and the
issuer and `sub` for Keycloak and Okta. Entra ID and Okta can also push changes
through SCIM ([below](#scim)).

Without the console, set `BUCKETS_OPENID_SYNC_PROVIDER` on the servers, and:

- **entra:** `BUCKETS_OPENID_SYNC_TENANT_ID`, `_CLIENT_ID` and `_CLIENT_SECRET`.
- **keycloak:** `BUCKETS_OPENID_SYNC_URL` (Keycloak's base URL), `_REALM`,
  `_CLIENT_ID` and `_CLIENT_SECRET`.
- **okta:** `BUCKETS_OPENID_SYNC_URL` (`https://<your domain>`), `_API_TOKEN`
  and `_ISSUER` (the authorization server's, such as
  `https://<your domain>/oauth2/default`).

`BUCKETS_OPENID_SYNC_INTERVAL` (seconds), `BUCKETS_OPENID_REMOVE_AFTER` (days)
and `BUCKETS_OPENID_REMOVE_MAX` change the defaults. LDAP needs none of this:
users removed from the directory lose their credentials at the hourly LDAP
sync, as with MinIO.

### Roles kept current

A sign-in token's roles or groups are copied into every credential the person
makes: their temporary credentials, and their access keys, which can live for
years. So someone moved out of a role in the provider would keep it through a
script's key. With **Keep their roles current** (beside **People who leave**),
each sync also reads what each person holds now, and where it differs, their
credentials follow:

- **Access keys are updated in place:** the same key and secret, expiry and
  session policy, now carrying the new roles. Scripts keep working with what
  the person is allowed now. The stored form is MinIO's, so MinIO reads it
  after a rollback.
- **Sessions** (console sessions and other temporary credentials) follow at
  their next request, with the credentials they already hold.
- **Someone left with no roles** keeps their access keys, which then allow
  nothing until a role is given back; their sessions end, and signing in again
  gives nothing. Leaving is what removes access.
- **More people losing roles at once than the limit** (the same limit as for
  leaving): no roles are taken that run, and `BucketsIdentitySyncHeld` fires.
  Roles given are not held.
- **The provider can't answer for someone:** their credentials are left as they
  are.
- Each change is in the log (`identity sync: roles of <person> changed`), in
  the audit log (`IdentitySyncRoles`), and counted in
  `buckets_node_identity_sync_actions_total{action="roles"}`.

It is on for settings made now, and off for settings saved before 1.18.0 until
turned on, since it changes what existing keys allow. **Roles come from** says
what the token's claim carries:

| Provider | Roles come from | Read with |
| --- | --- | --- |
| Entra ID | App roles (`roles` claim) | **Application.Read.All** as well as User.Read.All: the app's role assignments, to people and to the groups they are direct members of, as Entra issues the claim. Reading each user's own assignments would need Directory.Read.All instead. |
| Entra ID | Groups (`groups` claim) | User.Read.All: their groups, nested ones included, by object ID |
| Keycloak | Realm roles, the client's roles, or groups | view-users |
| Okta | Groups | the API token |

**Look up a person** then also shows their roles now and the Buckets policies
those name.

Without the console: `BUCKETS_OPENID_SYNC_ROLES=on`, and
`BUCKETS_OPENID_SYNC_ROLES_FROM` (`app-roles`, `groups`, `realm-roles` or
`client-roles`; Entra ID's default is `app-roles`, Keycloak's `realm-roles`,
Okta's `groups`). Entra's app roles are those of the sign-in app
(`BUCKETS_OPENID_SYNC_CLIENT_ID`) unless `BUCKETS_OPENID_SYNC_APP_ID` names
another, as do Keycloak's client roles.

## SCIM

With SCIM, Entra ID or Okta tells Buckets when someone is turned off, deleted or
taken out of the app, instead of waiting for the next sync. Okta pushes changes
at once; Entra ID pushes on its provisioning cycle, every 40 minutes, or at once
with **Provision on demand**. The design is in [design/scim.md](design/scim.md).

**What happens is the sync's:**
- temporary credentials go at once;
- access keys are turned off at once, and deleted after the grace period;
- someone turned on again in time gets their keys back;
- more people at once than the safety limit are held, and `BucketsIdentitySyncHeld` fires.

A push is acted on within seconds by the server leading the first erasure set.
SCIM never removes someone it hasn't named.

**Two ways to use it**, chosen under **People who leave**:
- **SCIM:** the provider tells Buckets; no API credentials are needed. For
  organisations that won't let an app read their directory.
- **Both:** pushed changes act within seconds, and the hourly sync is the
  backstop for anything a push missed. For the people SCIM names, what it says
  wins.

Keycloak has no SCIM client; use the sync.

### Set it up

1. Under **Identity → Sign-in → People who leave**, choose **SCIM** or **Both**,
   and **Make a token**. It is shown once: copy it now. The servers keep only its
   SHA-256.
2. Save and apply, as for the other settings.
3. In the provider:
   - **Entra ID:** in the enterprise app, **Provisioning → Automatic**. The
     **Tenant URL** is `https://<host>/minio/scim/v2` and the **Secret Token** is
     the token. Under **Mappings → Provision Microsoft Entra ID Users**, map
     **objectId** to **externalId** (it is `mailNickname` by default), then turn
     provisioning on.
   - **Okta:** in the app integration, turn on **SCIM provisioning**. The
     connector base URL is `https://<host>/minio/scim/v2`, the unique identifier
     is `userName`, and authentication is **HTTP Header** with the token. Under
     **To App**, turn on Create Users, Update User Attributes and Deactivate
     Users. Okta's `externalId` is already the ID in its tokens.
4. Back under **People who leave**, the console lists the people SCIM has sent.
   It says whether you are among them, and warns if none of them match a sign-in
   token, which usually means the Entra mapping is missing.

People are matched by `externalId` only. That is the ID in their sign-in token:
Entra's `oid`, or Okta's user ID, its tokens' `sub`. User names aren't used,
because a new hire can be given a leaver's address.

**Groups** keep roles current ([above](#roles-kept-current)) where SCIM is the
only source. Provision them only then; otherwise turn group provisioning off.
- **Entra ID:** under **Mappings → Provision Microsoft Entra ID Groups**, turn
  it on and map **objectId** to **externalId**, as the `groups` claim names
  groups by object ID. Assign the groups to the app.
- **Okta:** under **Push Groups**, push the groups whose names are Buckets
  policies or teams. Okta's groups claim names groups by name.

Under **SCIM** alone, a person's roles are then the groups SCIM says they are
in; someone in no group has none. Push the groups before turning roles on, or
the safety limit holds everything back. With **Both**, the provider's API is
asked instead.

### Reaching it

The provider's cloud calls `https://<host>/minio/scim/v2` on the servers.
- With the operator, `spec.scim.ingress` (a host, an ingress class, a TLS
  Secret) makes an Ingress that routes **only `/minio/scim/`**. You can open that
  path to the provider while S3 and the console stay private.
- Entra's provisioning agent and Okta's On-Prem Provisioning agent deliver SCIM
  inside a network the cloud can't reach.

```yaml
spec:
  scim:
    ingress:
      host: scim.buckets.example.com
      ingressClassName: nginx
      tlsSecret: {name: scim-tls}
```

### A new token

**Make a new token** replaces the token. The old one keeps working until the
next new one, so the provider can be updated without a gap.

### Without the console

Set these on the servers:
- **SCIM beside the sync's settings:** `BUCKETS_SCIM=on`.
- **SCIM only:** `BUCKETS_OPENID_SYNC_PROVIDER=scim`, with
  `BUCKETS_OPENID_SYNC_TENANT_ID` (Entra) or `BUCKETS_OPENID_SYNC_ISSUER` (Okta).
- **The token:** `BUCKETS_SCIM_TOKEN_SHA256` (the token's SHA-256 in hex, or
  `_FILE`), and `BUCKETS_SCIM_TOKEN_SHA256_PREVIOUS` while a new one rolls out.

### Watching it

- **Changes** are in the audit log as `SCIMCreateUser`, `SCIMUpdateUser` and
  `SCIMDeleteUser`, with the person's IDs. Refused tokens appear as
  `SCIMUnauthorized`, and are logged with their source address.
- **Metrics:** `buckets_scim_requests_total{op, result}` and
  `buckets_scim_people{state}`.
- **The admin API:** `GET /minio/admin/v3/buckets/scim` (`admin:ListUsers`)
  returns what the console shows.

## Troubleshooting

| What happens | Likely cause |
|---|---|
| The Sign-in page says **Conflict** | Sign-in is also set in `spec.env`, `spec.console.env` or `config.env`; the message names the entries to remove |
| The test says the provider did not issue a token (`invalid_client`, `invalid_grant`) | A wrong client secret, or the redirect URI is not registered exactly as shown on the page |
| The test signs in but says the token has no claim, or no role names a policy | No role or group assigned in the provider, a mapper or claim missing (Okta's `groups`, Keycloak's `roles`), or the values differ from the policy names (case-sensitive) |
| **Apply** stays disabled | The saved settings changed since the test, or a part that is on has not passed its test |
| The page says the servers refused the settings | The servers cannot reach the provider or bind to the directory; the server's words follow |
| Microsoft shows an AADSTS error before signing in | The redirect URI or client ID does not match the app registration, or the person is not assigned to the app while Assignment required is on |
| Back on the login page with "None of the given policies ... are defined" | The person's role values match no Buckets policy: check the app role Value (case-sensitive) |
| Back on the login page with an error about the policy claim | The token has no `roles` claim: the person holds no app role |
| Back on the login page with no error | The session cookie did not reach the browser. Consoles older than ab8bdae cut response headers at 1 KB, and Entra ID sessions make a ~2 KB cookie; upgrade the console |
| "The identity provider cannot be reached" | The console cannot reach `login.microsoftonline.com` (network policy, proxy, or DNS) |
| **Look up a person** says the app needs User.Read.All | Add Microsoft Graph's User.Read.All **application** permission (not delegated) and grant admin consent; it can take a few minutes to apply |
| **Look up a person** shows an AADSTS error | The client secret is wrong or has expired: create a new one in the app registration |
| **Look up a person** with Keycloak says the client needs view-users | Turn on **Service accounts roles** for the client, and assign it **realm-management: view-users** |
| **Look up a person** with Okta says `E0000011` (invalid token) | The API token was revoked, or expired after 30 days unused: create a new one and save it |

To see what a sign-in did on the server side, stream the server trace (`mc admin trace -a <alias>`, or the console's Trace page) while signing in: the `AssumeRoleWithWebIdentity` call shows whether credentials were issued, or why not.
