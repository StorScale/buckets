# Images for the JupyterHub example.
#
#   docker compose build      (compose.yaml builds the "hub" and "notebook" targets)

# JupyterHub 6, signing people in with Keycloak (OAuthenticator) and starting
# each person's notebook server in a container of its own (DockerSpawner).
FROM quay.io/jupyterhub/jupyterhub:6.0.1 AS hub
RUN pip install --no-cache-dir oauthenticator==17.4.0 dockerspawner==14.0.0

# The notebook server people get: JupyterLab, boto3, and buckets_lake, which
# turns the person's own Keycloak sign-in into Buckets credentials.
FROM quay.io/jupyter/base-notebook:hub-6.0.1 AS notebook
RUN pip install --no-cache-dir boto3==1.43.108 requests==2.34.2 pandas==3.0.6 pyarrow==25.0.1
COPY buckets_lake.py /opt/buckets/buckets_lake.py
RUN echo /opt/buckets > "$(python -c 'import site; print(site.getsitepackages()[0])')/buckets.pth"
