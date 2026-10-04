import { FormEvent, ReactNode, useState } from "react";
import {
  ApiError,
  deleteTeam,
  identityConfig,
  listBuckets,
  listTeams,
  loginMethods,
  OidcProvider,
  saveTeam,
  Team,
  TeamInfo,
  TeamLevel,
  TEAM_LEVELS,
  teamMember,
  teamPolicy,
} from "../api";
import { ConfirmButton, Copy, ErrorBanner, Modal, Spinner, useLoad } from "../components";

const LEVEL_TEXT: Record<TeamLevel, string> = {
  ro: "Read: list and download",
  rw: "Read and write objects",
  admin: "Read and write, and the buckets' settings; create and delete buckets under the prefixes",
};

// The team's buckets in words: named ones, then each prefix as "prefix*".
const bucketsText = (t: Team) => [...t.buckets, ...t.prefixes.map((p) => `${p}*`)].join(", ") || "—";
const splitList = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

export default function Teams() {
  const { data, error, loading, reload, setError } = useLoad(listTeams, []);
  // how people sign in decides what the setup steps say
  const signin = useLoad(async () => {
    const [methods, cfg] = await Promise.all([loginMethods(), identityConfig().catch(() => null)]);
    const openid = cfg?.settings?.openid;
    return {
      oidc: methods.oidc,
      provider: (openid?.provider ?? (methods.oidc ? "generic" : undefined)) as OidcProvider | undefined,
      claim: openid?.claimName,
    };
  }, []);
  const [editing, setEditing] = useState<TeamInfo | "new" | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const shown = data?.teams.find((t) => t.name === open);
  return (
    <div>
      <div className="page-head">
        <h1>Teams</h1>
        <button className="primary" onClick={() => setEditing("new")} data-testid="create-team">
          Create team
        </button>
      </div>
      <p className="muted">
        A team is a set of buckets. Each access level becomes a policy, <span className="mono">team-&lt;name&gt;-&lt;level&gt;</span>, that people get from your
        identity provider or as members here.
      </p>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      {loading && !data && <Spinner />}
      {data && data.teams.length === 0 && <p className="muted">No teams yet.</p>}
      {data && data.teams.length > 0 && (
        <table data-testid="team-table">
          <thead>
            <tr>
              <th>Team</th>
              <th>Buckets</th>
              <th>Levels</th>
              <th>Members</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.teams.map((t) => (
              <tr key={t.name} data-testid={`team-${t.name}`}>
                <td>{t.name}</td>
                <td className="mono">{bucketsText(t)}</td>
                <td>
                  {t.levels.map((l) => (
                    <span
                      key={l}
                      className={`pill ${t.edited.includes(l) ? "bad" : "ok"}`}
                      title={t.edited.includes(l) ? "Changed outside the Teams page" : undefined}
                    >
                      {l}
                      {t.edited.includes(l) && " (edited)"}
                    </span>
                  ))}
                </td>
                <td>{memberCount(t) || "—"}</td>
                <td className="row-actions">
                  <button onClick={() => setOpen(t.name)} data-testid={`team-setup-${t.name}`}>
                    Access
                  </button>
                  <button onClick={() => setEditing(t)} data-testid={`team-edit-${t.name}`}>
                    Edit
                  </button>
                  <ConfirmButton
                    label="Delete"
                    confirm={`Delete ${t.name}? Its members lose access.`}
                    testId={`team-delete-${t.name}`}
                    onConfirm={() => deleteTeam(t.name).then(reload).catch(setError)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {editing && (
        <TeamEditor
          team={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onDone={(name) => {
            setEditing(null);
            reload();
            setOpen(name);
          }}
        />
      )}
      {shown && data && <TeamAccess team={shown} ldap={data.ldap} signin={signin.data} onClose={() => setOpen(null)} onChanged={reload} />}
    </div>
  );
}

function memberCount(t: TeamInfo): number {
  return Object.values(t.members).reduce((n, m) => n + (m?.users.length ?? 0) + (m?.groups.length ?? 0), 0);
}

function TeamEditor({ team, onClose, onDone }: { team: TeamInfo | null; onClose: () => void; onDone: (name: string) => void }) {
  const existing = useLoad(listBuckets, []);
  const [name, setName] = useState(team?.name ?? "");
  const [buckets, setBuckets] = useState<string[]>(team?.buckets ?? []);
  const [more, setMore] = useState("");
  const [prefixes, setPrefixes] = useState((team?.prefixes ?? []).join(", "));
  const [levels, setLevels] = useState<TeamLevel[]>(team?.levels ?? ["ro", "rw"]);
  const [error, setError] = useState<unknown>();
  const [edited, setEdited] = useState<string[] | null>(null);
  const names = Array.from(new Set([...(existing.data ?? []).map((b) => b.name), ...buckets])).sort();
  const submit = async (e: FormEvent | null, overwrite = false) => {
    e?.preventDefault();
    const t: Team = {
      name,
      buckets: Array.from(new Set([...buckets, ...splitList(more)])),
      prefixes: splitList(prefixes),
      levels: TEAM_LEVELS.filter((l) => levels.includes(l)),
    };
    try {
      await saveTeam(t, overwrite);
      onDone(name);
    } catch (err) {
      if (err instanceof ApiError && err.code === "Edited") setEdited(team?.edited ?? []);
      else setError(err);
    }
  };
  const dropped = team ? team.levels.filter((l) => !levels.includes(l)) : [];
  return (
    <Modal title={team ? `Edit ${team.name}` : "Create team"} onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBanner error={error} onClose={() => setError(undefined)} />
        <label>
          Name
          <input
            value={name}
            disabled={!!team}
            onChange={(e) => setName(e.target.value.trim().toLowerCase())}
            placeholder="finance"
            autoFocus
            data-testid="team-name"
          />
          <span className="muted">Lower-case letters, digits and hyphens. It becomes part of the policy and role names.</span>
        </label>
        <fieldset>
          <legend>Buckets</legend>
          {existing.loading && <Spinner />}
          <div className="check-grid">
            {names.map((b) => (
              <label key={b} className="check">
                <input
                  type="checkbox"
                  checked={buckets.includes(b)}
                  onChange={(e) => setBuckets(e.target.checked ? [...buckets, b] : buckets.filter((x) => x !== b))}
                  data-testid={`team-bucket-${b}`}
                />{" "}
                {b}
              </label>
            ))}
          </div>
          {!existing.loading && names.length === 0 && <p className="muted">No buckets yet: name them below.</p>}
        </fieldset>
        <label>
          Other bucket names <span className="muted">(not created yet)</span>
          <input value={more} onChange={(e) => setMore(e.target.value)} placeholder="finance-archive" data-testid="team-more-buckets" />
        </label>
        <label>
          Prefixes <span className="muted">— every bucket whose name starts with one, now and later</span>
          <input value={prefixes} onChange={(e) => setPrefixes(e.target.value)} placeholder="finance-" data-testid="team-prefixes" />
        </label>
        <fieldset>
          <legend>Access levels</legend>
          {TEAM_LEVELS.map((l) => (
            <label key={l} className="check">
              <input
                type="checkbox"
                checked={levels.includes(l)}
                onChange={(e) => setLevels(e.target.checked ? [...levels, l] : levels.filter((x) => x !== l))}
                data-testid={`team-level-${l}`}
              />{" "}
              <span className="mono">{name ? teamPolicy(name, l) : `team-…-${l}`}</span> — {LEVEL_TEXT[l]}
            </label>
          ))}
          {dropped.length > 0 && (
            <p className="banner error" role="alert">
              Removing {dropped.join(", ")} deletes {dropped.length > 1 ? "those policies" : "that policy"}, and {dropped.length > 1 ? "their" : "its"} members
              lose that access.
            </p>
          )}
        </fieldset>
        {edited && (
          <div className="banner error" role="alert" data-testid="team-edited">
            <span>
              {edited.length ? `The ${edited.join(", ")} polic${edited.length > 1 ? "ies were" : "y was"}` : "Some of this team's policies were"} changed
              outside the Teams page. Saving replaces those changes.
            </span>{" "}
            <button type="button" className="danger" onClick={() => submit(null, true)} data-testid="team-overwrite">
              Replace them
            </button>
          </div>
        )}
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={!name || !levels.length} data-testid="team-save">
            Save
          </button>
        </div>
      </form>
    </Modal>
  );
}

type SignIn = { oidc: boolean; provider?: OidcProvider; claim?: string } | undefined;

// What to set up in the identity provider so people get a level's policy.
function providerStep(signin: SignIn, policy: string): ReactNode {
  const v = <Copy text={policy} />;
  switch (signin?.provider) {
    case "entra":
      return (
        <>In the Entra app registration, add an app role with the value {v}, then assign it to a group under Enterprise applications → Users and groups.</>
      );
    case "okta":
      return <>In Okta, create a group named {v}, add people to it, and include it in the app's groups claim.</>;
    case "keycloak":
      return <>In Keycloak, create a realm role {v} and assign it to users or groups.</>;
    case "generic":
      return (
        <>
          Have your provider put {v} in the <span className="mono">{signin.claim || "policy"}</span> claim of the people who need it.
        </>
      );
    default:
      return <>Add people or groups below, or set up sign-in with an identity provider and give them the role {v}.</>;
  }
}

function TeamAccess({ team, ldap, signin, onClose, onChanged }: { team: TeamInfo; ldap: boolean; signin: SignIn; onClose: () => void; onChanged: () => void }) {
  const [error, setError] = useState<unknown>();
  const [level, setLevel] = useState<TeamLevel>(team.levels[0]);
  const [kind, setKind] = useState<"user" | "group">("group");
  const [who, setWho] = useState("");
  const add = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await teamMember(team.name, level, { [kind]: who.trim() });
      setWho("");
      onChanged();
    } catch (err) {
      setError(err);
    }
  };
  const remove = (l: TeamLevel, k: "user" | "group", name: string) =>
    teamMember(team.name, l, { [k]: name }, true)
      .then(onChanged)
      .catch(setError);
  return (
    <Modal title={`Access to ${team.name}`} onClose={onClose}>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      <p className="muted">Buckets: {bucketsText(team)}</p>
      {team.levels.map((l) => {
        const m = team.members[l] ?? { users: [], groups: [] };
        const policy = teamPolicy(team.name, l);
        return (
          <section key={l} className="team-level" data-testid={`team-access-${l}`}>
            <h3>
              {l} <span className="muted">— {LEVEL_TEXT[l]}</span>
            </h3>
            {signin?.oidc && <p>{providerStep(signin, policy)}</p>}
            {!signin?.oidc && (
              <p>
                Policy: <Copy text={policy} />
              </p>
            )}
            {m.users.length + m.groups.length > 0 ? (
              <ul className="members">
                {m.groups.map((g) => (
                  <li key={`g:${g}`}>
                    group <span className="mono">{g}</span>{" "}
                    <button className="link" onClick={() => remove(l, "group", g)} data-testid={`team-remove-${l}-${g}`}>
                      Remove
                    </button>
                  </li>
                ))}
                {m.users.map((u) => (
                  <li key={`u:${u}`}>
                    user <span className="mono">{u}</span>{" "}
                    <button className="link" onClick={() => remove(l, "user", u)} data-testid={`team-remove-${l}-${u}`}>
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">
                No members added here
                {signin?.oidc ? ": people get this level from the identity provider" : ""}.
              </p>
            )}
          </section>
        );
      })}
      <form onSubmit={add} className="inline-form">
        <h3>Add a member</h3>
        <div className="row">
          <select value={level} onChange={(e) => setLevel(e.target.value as TeamLevel)} data-testid="team-member-level">
            {team.levels.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
          <select value={kind} onChange={(e) => setKind(e.target.value as "user" | "group")} data-testid="team-member-kind">
            <option value="group">group</option>
            <option value="user">user</option>
          </select>
          <input
            value={who}
            onChange={(e) => setWho(e.target.value)}
            placeholder={
              ldap
                ? kind === "group"
                  ? "cn=finance,ou=groups,dc=example,dc=com or a local group"
                  : "uid=alice,ou=people,… or a local user"
                : kind === "group"
                  ? "a local group"
                  : "a local user"
            }
            data-testid="team-member-name"
          />
          <button className="primary" disabled={!who.trim()} data-testid="team-member-add">
            Add
          </button>
        </div>
        {ldap && <p className="muted">LDAP users and groups are added by their distinguished name.</p>}
      </form>
    </Modal>
  );
}
