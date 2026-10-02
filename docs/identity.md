# Identity: sign-in with Microsoft Entra ID and role-based access

People sign in to the console with their Microsoft Entra ID account, and the app roles they hold in Entra decide what they can do in Buckets. Buckets keeps no copy of the directory: who can sign in, and with which roles, is managed in Entra ID. The same setup works with any OpenID Connect provider that puts roles in a token claim.

## How it works

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

For finer access, create a policy (for example `team-finance-rw`, limited to the team's buckets) and an app role with the same value. Values are matched exactly, including case.

## Set up Entra ID

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

## Configure Buckets

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

## In the console

- **Users** lists the provider's people that Buckets knows of: everyone signed in now, and anyone holding access keys, with their name, sign-in name and roles. People who have never signed in do not appear.
- **Create user** is hidden while OpenID sign-in is on, so every person signs in through the provider. Local users that already exist are still listed and can be disabled or deleted. Set `BUCKETS_CONSOLE_LOCAL_USERS=on` in `spec.console.env` to offer it again.
- People who need keys for S3 tools (`mc`, the AWS CLI, SDKs) create access keys from the console after signing in. The keys carry the person's roles.

## Troubleshooting

| What happens | Likely cause |
|---|---|
| Microsoft shows an AADSTS error before signing in | The redirect URI or client ID does not match the app registration, or the person is not assigned to the app while Assignment required is on |
| Back on the login page with "None of the given policies ... are defined" | The person's role values match no Buckets policy: check the app role Value (case-sensitive) |
| Back on the login page with an error about the policy claim | The token has no `roles` claim: the person holds no app role |
| Back on the login page with no error | The session cookie did not reach the browser. Consoles older than ab8bdae cut response headers at 1 KB, and Entra ID sessions make a ~2 KB cookie; upgrade the console |
| "The identity provider cannot be reached" | The console cannot reach `login.microsoftonline.com` (network policy, proxy, or DNS) |

To see what a sign-in did on the server side, stream the server trace (`mc admin trace -a <alias>`, or the console's Trace page) while signing in: the `AssumeRoleWithWebIdentity` call shows whether credentials were issued, or why not.
