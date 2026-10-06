# JupyterHub example: Buckets, JupyterHub, Keycloak

People sign in to JupyterHub with Keycloak, each gets a notebook server in a container of their own, and their notebooks reach Buckets as them: their Keycloak token, exchanged through Buckets' STS for temporary credentials. Keycloak's groups decide who may sign in, who administers the hub, and what each person may read and write. Everyone has a private `home/<username>/`.

```bash
docker compose up -d --wait     # build, start and configure
docker compose run --rm test    # the end-to-end checks
docker compose down -v          # stop and delete everything (see the guide for the notebook containers)
```

With rootless Docker (Lima, for example), set `DOCKER_SOCK=/run/user/$(id -u)/docker.sock` first. To use it in a browser, add `127.0.0.1 keycloak jupyterhub` to `/etc/hosts` and open http://jupyterhub:8000.

The guide, [docs/integrations/jupyterhub.md](../../docs/integrations/jupyterhub.md), explains how each piece is set up and what to change for production. Run one example at a time: they use the same ports.

| Path | What it is |
|---|---|
| `compose.yaml` | The stack |
| `.env` | Every password and key: local test values only |
| `jupyterhub/jupyterhub_config.py` | Keycloak sign-in, groups, kept tokens, roles, DockerSpawner |
| `images/Dockerfile` | The hub image (JupyterHub 6 with OAuthenticator and DockerSpawner) and the notebook image |
| `images/buckets_lake.py` | In notebooks: `buckets_lake.s3()`, Buckets as the person who signed in |
| `tools/setup.py` | Buckets' buckets (`home`, `datasets`), the group policies, a sample dataset |
| `tools/test.py` | The checks: real Keycloak sign-ins, and code run in each person's notebook |

The Keycloak realm (with its `jupyterhub` client) and the tools image are shared with the other examples, in [`../common`](../common).
