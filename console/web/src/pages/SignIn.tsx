import { ReactNode, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  identityApply,
  IdentityConfig,
  identityConfig,
  identityLdapTest,
  identitySaveCandidate,
  IdentitySettings,
  identityTestSignIn,
  LdapSettings,
  LdapTest,
  OidcProvider,
  OidcSettings,
  OidcTest,
} from "../api";
import { ErrorBanner, Spinner } from "../components";

// The OpenID providers, as people know them, and what each needs.
const PROVIDERS: { id: OidcProvider; title: string; blurb: string }[] = [
  { id: "entra", title: "Microsoft Entra ID", blurb: "An app registration with app roles named after Buckets policies." },
  { id: "okta", title: "Okta", blurb: "An OIDC web app, with a groups claim naming Buckets policies." },
  { id: "keycloak", title: "Keycloak", blurb: "A confidential client, with a mapper putting roles in the token." },
  { id: "generic", title: "Another OpenID provider", blurb: "Any OpenID Connect provider with a discovery document." },
];

const DEFAULT_CLAIM: Record<OidcProvider, string> = { entra: "roles", okta: "groups", keycloak: "roles", generic: "policy" };

const LDAP_FILTERS: Record<LdapSettings["preset"], { user: string; group: string }> = {
  ad: { user: "(&(objectCategory=user)(sAMAccountName=%s))", group: "(&(objectClass=group)(member=%d))" },
  openldap: { user: "(&(objectClass=inetOrgPerson)(uid=%s))", group: "(&(objectClass=groupOfNames)(member=%d))" },
  custom: { user: "", group: "" },
};

function blankOidc(p: OidcProvider): OidcSettings {
  return { provider: p, clientId: "", clientSecret: "" };
}

function blankLdap(): LdapSettings {
  return { preset: "ad", serverAddr: "", tls: "ldaps", lookupBindDn: "", lookupBindPassword: "", userSearchBase: "", groupSearchBase: "" };
}

// What still has to be filled in, in words.
function missing(s: IdentitySettings, saved: Set<string>): string[] {
  const m: string[] = [];
  const o = s.openid;
  if (o) {
    if (o.provider === "entra" && !o.tenantId) m.push("the directory (tenant) ID");
    if (o.provider === "okta" && !o.domain) m.push("the Okta domain");
    if (o.provider === "keycloak") {
      if (!/^https?:\/\//.test(o.url ?? "")) m.push("Keycloak's URL");
      if (!o.realm) m.push("the realm");
    }
    if (o.provider === "generic" && !/^https?:\/\//.test(o.configUrl ?? "")) m.push("the discovery URL");
    if (!o.clientId) m.push("the client ID");
    if (!o.clientSecret && !saved.has("openid.clientSecret")) m.push("the client secret");
  }
  const l = s.ldap;
  if (l) {
    if (!l.serverAddr) m.push("the directory server");
    if (!l.lookupBindDn) m.push("the service account's DN");
    if (!l.lookupBindPassword && !saved.has("ldap.lookupBindPassword")) m.push("the service account's password");
    if (!l.userSearchBase) m.push("the user search base");
    if (l.preset === "custom" && !(l.userSearchFilter ?? "").includes("%s")) m.push("a user filter with %s");
  }
  return m;
}

export default function SignInSetup() {
  const [cfg, setCfg] = useState<IdentityConfig | null | undefined>(undefined);
  const [error, setError] = useState<unknown>();
  const [draft, setDraft] = useState<IdentitySettings>({});
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState("");
  const [applied, setApplied] = useState(false);

  const load = async (takeDraft: boolean) => {
    try {
      const c = await identityConfig();
      setCfg(c);
      if (takeDraft && c?.managed) setDraft(c.candidate ?? c.settings ?? {});
      return c;
    } catch (e) {
      setError(e);
      setCfg(null);
      return null;
    }
  };
  useEffect(() => {
    load(true);
  }, []);
  // follow the operator applying the settings
  useEffect(() => {
    if (!applied) return;
    const t = setInterval(() => load(false), 2000);
    return () => clearInterval(t);
  }, [applied]);

  const saved = useMemo(() => new Set(draft.secretsSet ?? []), [draft]);
  if (cfg === undefined) return <Spinner />;
  if (cfg === null)
    return (
      <div>
        <h1>Sign-in</h1>
        <ErrorBanner error={error} />
        {!error && <div className="banner error">Setting up sign-in needs the admin:ConfigUpdate permission.</div>}
      </div>
    );
  if (!cfg.managed)
    return (
      <div>
        <h1>Sign-in</h1>
        <div className="card">
          <p>
            This console does not run under buckets-operator, so sign-in is set on the servers and the console instead: <span className="mono">MINIO_IDENTITY_OPENID_*</span> or{" "}
            <span className="mono">MINIO_IDENTITY_LDAP_*</span> for the servers, and <span className="mono">BUCKETS_CONSOLE_OIDC_*</span> for the console. See docs/identity.md.
          </p>
        </div>
      </div>
    );

  const change = (s: IdentitySettings) => {
    setDraft(s);
    setDirty(true);
    setApplied(false);
  };
  const todo = missing(draft, saved);
  const fresh = !dirty && !!cfg.candidateHash; // the draft is the saved candidate
  const test = fresh ? cfg.test : undefined;
  const needOidc = !!draft.openid, needLdap = !!draft.ldap;
  const ready = fresh && (!needOidc || test?.openid?.passed) && (!needLdap || test?.ldap?.passed);

  const save = async () => {
    setError(undefined);
    setBusy("save");
    try {
      const body: IdentitySettings = { openid: draft.openid ?? null, ldap: draft.ldap ?? null };
      const r = await identitySaveCandidate(body);
      setDraft(r.candidate);
      setDirty(false);
      await load(false);
    } catch (e) {
      setError(e);
    } finally {
      setBusy("");
    }
  };
  const testSignIn = async () => {
    setError(undefined);
    setBusy("oidc");
    await identityTestSignIn();
    await load(false);
    setBusy("");
  };
  const apply = async () => {
    if (!cfg.candidateHash) return;
    setError(undefined);
    setBusy("apply");
    try {
      await identityApply(cfg.candidateHash);
      setApplied(true);
      await load(false);
    } catch (e) {
      setError(e);
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="signin-setup">
      <div className="page-head">
        <h1>Sign-in</h1>
      </div>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      <Status cfg={cfg} />

      <div className="card section" data-testid="oidc-card">
        <h2>Single sign-on (OpenID Connect)</h2>
        <p className="muted">People sign in with their organisation account. The roles the provider puts in their token name the Buckets policies they get.</p>
        <OnOff on={needOidc} onChange={(on) => change({ ...draft, openid: on ? (cfg.settings?.openid ?? blankOidc("entra")) : null })} testId="oidc-on" />
        {draft.openid && (
          <>
            <div className="choices" role="radiogroup">
              {PROVIDERS.map((p) => (
                <button
                  key={p.id}
                  role="radio"
                  aria-checked={draft.openid!.provider === p.id}
                  className={`choice ${draft.openid!.provider === p.id ? "selected" : ""}`}
                  data-testid={`oidc-provider-${p.id}`}
                  onClick={() => change({ ...draft, openid: draft.openid!.provider === p.id ? draft.openid : blankOidc(p.id) })}
                >
                  <strong>{p.title}</strong>
                  <span>{p.blurb}</span>
                </button>
              ))}
            </div>
            <ProviderSteps provider={draft.openid.provider} redirectUri={draft.openid.redirectUri || cfg.redirectUri || ""} cluster={cfg.cluster ?? "buckets"} />
            <OidcForm o={draft.openid} saved={saved} onChange={(openid) => change({ ...draft, openid })} />
          </>
        )}
      </div>

      <div className="card section" data-testid="ldap-card">
        <h2>LDAP or Active Directory</h2>
        <p className="muted">People sign in with their directory user name and password. Policies are attached to directory users and groups.</p>
        <OnOff on={needLdap} onChange={(on) => change({ ...draft, ldap: on ? (cfg.settings?.ldap ?? blankLdap()) : null })} testId="ldap-on" />
        {draft.ldap && (
          <>
            <LdapForm l={draft.ldap} saved={saved} onChange={(ldap) => change({ ...draft, ldap })} />
            <LdapCheck enabled={fresh} result={test?.ldap} onDone={() => load(false)} />
          </>
        )}
      </div>

      <div className="card section" data-testid="apply-card">
        <h2>Test and apply</h2>
        {todo.length > 0 && (
          <p className="hint" data-testid="signin-missing">
            Still needed: {todo.join(", ")}.
          </p>
        )}
        <ol className="checklist">
          <li className={fresh ? "done" : ""}>
            Save the settings. Nothing changes for the cluster yet.{" "}
            <button onClick={save} disabled={todo.length > 0 || busy !== "" || fresh} data-testid="signin-save">
              {busy === "save" ? "Saving…" : fresh ? "Saved" : "Save"}
            </button>
          </li>
          {needOidc && (
            <li className={test?.openid?.passed ? "done" : ""}>
              Sign in once with them. A window opens at the provider; it is a test and does not change your session.{" "}
              <button onClick={testSignIn} disabled={!fresh || busy !== ""} data-testid="signin-test">
                {busy === "oidc" ? "Waiting for the sign-in…" : test?.openid ? "Test again" : "Test sign-in"}
              </button>
              {test?.openid && <OidcResult r={test.openid} />}
            </li>
          )}
          {needLdap && <li className={test?.ldap?.passed ? "done" : ""}>Look up a directory user (above).</li>}
          <li className={applied ? "done" : ""}>
            Apply. The servers take the settings at once{needLdap ? "; LDAP is read when they start, so they restart one at a time" : ""}, then the console.{" "}
            <button className="primary" onClick={apply} disabled={!ready || busy !== "" || applied} data-testid="signin-apply">
              {busy === "apply" ? "Applying…" : applied ? "Applied" : "Apply"}
            </button>
          </li>
        </ol>
        {!needOidc && !needLdap && <p className="muted">With both off, people sign in with access keys only.</p>}
      </div>
    </div>
  );
}

// ---- status ------------------------------------------------------------------------

function Status({ cfg }: { cfg: IdentityConfig }) {
  const st = cfg.status ?? {};
  const phase = st.phase ?? "NotManaged";
  const tone = phase === "Ready" ? "ok" : phase === "Error" || phase === "Conflict" ? "error" : "";
  const words: Record<string, string> = {
    Ready: cfg.description ? `People sign in with ${cfg.description}.` : "Applied.",
    NotManaged: "Not set up here yet: the servers' own settings apply.",
    Conflict: "Not applied.",
    Error: "Not applied.",
  };
  return (
    <div className={`banner ${tone}`} data-testid="signin-status">
      <strong>{words[phase] ?? phase}</strong> {st.message && <span>{st.message}</span>}
    </div>
  );
}

function OnOff({ on, onChange, testId }: { on: boolean; onChange: (on: boolean) => void; testId: string }) {
  return (
    <div className="segmented" role="radiogroup" data-testid={testId}>
      <button role="radio" aria-checked={!on} className={!on ? "selected" : ""} onClick={() => onChange(false)}>
        Off
      </button>
      <button role="radio" aria-checked={on} className={on ? "selected" : ""} onClick={() => onChange(true)}>
        On
      </button>
    </div>
  );
}

// ---- OpenID ------------------------------------------------------------------------

function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <span className="copy-inline">
      <span className="mono">{text}</span>{" "}
      <button
        className="link"
        onClick={() => {
          navigator.clipboard?.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        }}
      >
        {done ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

function ProviderSteps({ provider, redirectUri, cluster }: { provider: OidcProvider; redirectUri: string; cluster: string }) {
  const ru = <Copy text={redirectUri} />;
  const roles = (
    <>
      named after Buckets policies, such as <span className="mono">consoleAdmin</span>, <span className="mono">readwrite</span> and <span className="mono">readonly</span>
    </>
  );
  const steps: Record<OidcProvider, ReactNode[]> = {
    entra: [
      <>In the Entra admin center, open App registrations and register a new app (for example "Buckets {cluster}").</>,
      <>Under Authentication, add the Web platform with this redirect URI: {ru}</>,
      <>Under Certificates &amp; secrets, create a client secret and copy its value.</>,
      <>Under App roles, create a role for each policy you grant, its value {roles}.</>,
      <>In Enterprise applications, open the app and assign people or groups to those roles.</>,
      <>Copy the directory (tenant) ID and the application (client) ID from the app's Overview.</>,
    ],
    okta: [
      <>In the Okta admin console, create an app integration: OIDC, Web Application.</>,
      <>Use a client secret for client authentication, and set the sign-in redirect URI to {ru}</>,
      <>In the default authorization server, add a groups claim to the ID token, matching the groups {roles}.</>,
      <>Assign people or groups to the app, and copy its client ID and secret.</>,
    ],
    keycloak: [
      <>In the realm, create a client: OpenID Connect, with client authentication on.</>,
      <>Copy the client secret from its Credentials tab, and add this to its valid redirect URIs: {ru}</>,
      <>In the client's dedicated scope, add a role mapper with token claim name "roles", added to the ID token.</>,
      <>Create roles {roles}, and assign them to people or groups.</>,
    ],
    generic: [
      <>Register a confidential web client, copy its client ID and secret, and register this redirect URI: {ru}</>,
      <>Have the provider put a claim in the ID token whose values are policy names, such as <span className="mono">consoleAdmin</span> or <span className="mono">readwrite</span>.</>,
    ],
  };
  return (
    <div className="subsection" data-testid="provider-steps">
      <h3>In {provider === "generic" ? "your provider" : PROVIDERS.find((p) => p.id === provider)?.title}</h3>
      <ol className="steps-list">
        {steps[provider].map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
    </div>
  );
}

function Field({ label, help, children }: { label: string; help?: ReactNode; children: ReactNode }) {
  return (
    <label>
      <span className="field-label">{label}</span>
      {children}
      {help && <span className="field-help">{help}</span>}
    </label>
  );
}

function Secret({ value, field, saved, onChange, testId }: { value?: string; field: string; saved: Set<string>; onChange: (v: string) => void; testId: string }) {
  return (
    <input
      type="password"
      autoComplete="new-password"
      value={value ?? ""}
      placeholder={saved.has(field) ? "•••••••• saved — leave empty to keep" : ""}
      onChange={(e) => onChange(e.target.value)}
      data-testid={testId}
    />
  );
}

function OidcForm({ o, saved, onChange }: { o: OidcSettings; saved: Set<string>; onChange: (o: OidcSettings) => void }) {
  const set = (k: keyof OidcSettings) => (e: { target: { value: string } }) => onChange({ ...o, [k]: e.target.value });
  return (
    <div className="form-grid">
      {o.provider === "entra" && (
        <Field label="Directory (tenant) ID">
          <input value={o.tenantId ?? ""} onChange={set("tenantId")} data-testid="oidc-tenant" />
        </Field>
      )}
      {o.provider === "okta" && (
        <>
          <Field label="Okta domain" help="For example example.okta.com.">
            <input value={o.domain ?? ""} onChange={set("domain")} data-testid="oidc-domain" />
          </Field>
          <Field label="Authorization server" help='Leave empty for "default".'>
            <input value={o.authServer ?? ""} onChange={set("authServer")} />
          </Field>
        </>
      )}
      {o.provider === "keycloak" && (
        <>
          <Field label="Keycloak URL" help="For example https://keycloak.example.com.">
            <input value={o.url ?? ""} onChange={set("url")} data-testid="oidc-url" />
          </Field>
          <Field label="Realm">
            <input value={o.realm ?? ""} onChange={set("realm")} data-testid="oidc-realm" />
          </Field>
        </>
      )}
      {o.provider === "generic" && (
        <Field label="Discovery URL" help="Ends in /.well-known/openid-configuration.">
          <input value={o.configUrl ?? ""} onChange={set("configUrl")} data-testid="oidc-config-url" />
        </Field>
      )}
      <Field label="Client ID">
        <input value={o.clientId} onChange={set("clientId")} data-testid="oidc-client-id" />
      </Field>
      <Field label="Client secret">
        <Secret value={o.clientSecret} field="openid.clientSecret" saved={saved} onChange={(v) => onChange({ ...o, clientSecret: v })} testId="oidc-client-secret" />
      </Field>
      <details className="advanced">
        <summary>Advanced</summary>
        <Field label="Sign-in button label">
          <input value={o.displayName ?? ""} placeholder={PROVIDERS.find((p) => p.id === o.provider)?.title} onChange={set("displayName")} />
        </Field>
        <Field label="Claim naming policies" help="The token claim whose values are policy names.">
          <input value={o.claimName ?? ""} placeholder={DEFAULT_CLAIM[o.provider]} onChange={set("claimName")} />
        </Field>
        <Field label="Scopes">
          <input value={o.scopes ?? ""} placeholder={o.provider === "okta" ? "openid profile email groups" : "openid profile email"} onChange={set("scopes")} />
        </Field>
        <Field label="Policies for everyone who signs in" help="Instead of a claim: a comma-separated list of policies.">
          <input value={o.rolePolicy ?? ""} onChange={set("rolePolicy")} />
        </Field>
        <Field label="Redirect URI" help="Only if the console is reached at another address than this one.">
          <input value={o.redirectUri ?? ""} onChange={set("redirectUri")} />
        </Field>
        <label className="check">
          <input type="checkbox" checked={!!o.claimUserinfo} onChange={(e) => onChange({ ...o, claimUserinfo: e.target.checked })} />
          Also read claims from the provider's UserInfo endpoint
        </label>
      </details>
    </div>
  );
}

function OidcResult({ r }: { r: OidcTest }) {
  return (
    <div className={`test-result ${r.passed ? "ok" : "failed"}`} data-testid="oidc-result">
      {r.passed ? (
        <p>
          Signed in as <strong>{r.user}</strong>.
        </p>
      ) : (
        <p>{r.error ?? "The test failed."}</p>
      )}
      {r.roles && (
        <dl>
          <dt>{r.claimName ? `"${r.claimName}" in the token` : "Policies"}</dt>
          <dd>{r.roles.length ? r.roles.join(", ") : "none"}</dd>
          <dt>Policies they get</dt>
          <dd>{r.policies?.length ? r.policies.join(", ") : "none"}</dd>
          {!!r.unmatched?.length && (
            <>
              <dt>Not policies (ignored)</dt>
              <dd>{r.unmatched.join(", ")}</dd>
            </>
          )}
        </dl>
      )}
    </div>
  );
}

// ---- LDAP ----------------------------------------------------------------------------

function LdapForm({ l, saved, onChange }: { l: LdapSettings; saved: Set<string>; onChange: (l: LdapSettings) => void }) {
  const set = (k: keyof LdapSettings) => (e: { target: { value: string } }) => onChange({ ...l, [k]: e.target.value });
  const f = LDAP_FILTERS[l.preset];
  return (
    <div className="form-grid">
      <Field label="Directory">
        <select value={l.preset} onChange={(e) => onChange({ ...l, preset: e.target.value as LdapSettings["preset"] })} data-testid="ldap-preset">
          <option value="ad">Active Directory</option>
          <option value="openldap">OpenLDAP</option>
          <option value="custom">Other (my own filters)</option>
        </select>
      </Field>
      <Field label="Server" help="host or host:port, for example dc1.corp.example.com:636.">
        <input value={l.serverAddr} onChange={set("serverAddr")} data-testid="ldap-server" />
      </Field>
      <Field label="Connection">
        <select value={l.tls ?? "ldaps"} onChange={(e) => onChange({ ...l, tls: e.target.value as LdapSettings["tls"] })}>
          <option value="ldaps">LDAPS</option>
          <option value="starttls">StartTLS</option>
          <option value="plain">Plain LDAP (no encryption)</option>
        </select>
      </Field>
      <Field label="Service account DN" help="A read-only account that looks up users and groups.">
        <input value={l.lookupBindDn} onChange={set("lookupBindDn")} data-testid="ldap-bind-dn" />
      </Field>
      <Field label="Service account password">
        <Secret value={l.lookupBindPassword} field="ldap.lookupBindPassword" saved={saved} onChange={(v) => onChange({ ...l, lookupBindPassword: v })} testId="ldap-bind-password" />
      </Field>
      <Field label="User search base" help="For example OU=Staff,DC=corp,DC=example,DC=com.">
        <input value={l.userSearchBase} onChange={set("userSearchBase")} data-testid="ldap-user-base" />
      </Field>
      <Field label="Group search base" help="Leave empty not to look up groups.">
        <input value={l.groupSearchBase ?? ""} onChange={set("groupSearchBase")} data-testid="ldap-group-base" />
      </Field>
      <details className="advanced" open={l.preset === "custom"}>
        <summary>Advanced</summary>
        <Field label="User filter" help="%s is the user name.">
          <input value={l.userSearchFilter ?? ""} placeholder={f.user} onChange={set("userSearchFilter")} data-testid="ldap-user-filter" />
        </Field>
        <Field label="Group filter" help="%d is the user's DN, %s the user name.">
          <input value={l.groupSearchFilter ?? ""} placeholder={f.group} onChange={set("groupSearchFilter")} />
        </Field>
        <label className="check">
          <input type="checkbox" checked={!!l.skipVerify} onChange={(e) => onChange({ ...l, skipVerify: e.target.checked })} />
          Trust the server's certificate without checking it (testing only)
        </label>
      </details>
    </div>
  );
}

function LdapCheck({ enabled, result, onDone }: { enabled: boolean; result?: LdapTest; onDone: () => void }) {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const run = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await identityLdapTest(user.trim(), pass || undefined);
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="subsection" data-testid="ldap-check">
      <h3>Look up a user</h3>
      <p className="muted">{enabled ? "Finds the user with the saved settings, and their groups. With a password, also checks that they can sign in." : "Save the settings first (below)."}</p>
      <div className="inline-form">
        <input placeholder="user name" value={user} onChange={(e) => setUser(e.target.value)} disabled={!enabled} data-testid="ldap-test-user" />
        <input type="password" placeholder="password (optional)" value={pass} onChange={(e) => setPass(e.target.value)} disabled={!enabled} autoComplete="new-password" />
        <button onClick={run} disabled={!enabled || !user.trim() || busy} data-testid="ldap-test">
          {busy ? "Looking up…" : "Look up"}
        </button>
      </div>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      {result && (
        <div className={`test-result ${result.passed ? "ok" : "failed"}`} data-testid="ldap-result">
          {result.passed ? (
            <dl>
              <dt>DN</dt>
              <dd className="mono">{result.dn}</dd>
              <dt>Groups</dt>
              <dd>{result.groups?.length ? result.groups.join("; ") : "none"}</dd>
              <dt>Policies</dt>
              <dd>{result.policies?.length ? result.policies.join(", ") : "none yet"}</dd>
            </dl>
          ) : (
            <p>{result.error}</p>
          )}
          {result.note && <p className="muted">{result.note}</p>}
        </div>
      )}
      <p className="muted">
        Policies for directory users and groups are attached by DN, for example with <span className="mono">mc admin idp ldap policy attach</span>. <Link to="/identity/policies">Policies</Link>
      </p>
    </div>
  );
}
