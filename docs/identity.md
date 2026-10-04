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

## The Users page and access keys

- **Users** lists the provider's people that Buckets knows of: everyone signed in now, and anyone holding access keys, with their name, sign-in name and roles. People who have never signed in do not appear.
- **Create user** is hidden while OpenID sign-in is on, so every person signs in through the provider. Local users that already exist are still listed and can be disabled or deleted. Set `BUCKETS_CONSOLE_LOCAL_USERS=on` in `spec.console.env` to offer it again.
- People who need keys for S3 tools (`mc`, the AWS CLI, SDKs) create access keys from the console after signing in. The keys carry the person's roles.

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

To see what a sign-in did on the server side, stream the server trace (`mc admin trace -a <alias>`, or the console's Trace page) while signing in: the `AssumeRoleWithWebIdentity` call shows whether credentials were issued, or why not.
