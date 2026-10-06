# Airflow 3.3 with the Trino client, for the pipelines' queries. The image
# already has the FAB auth manager (Keycloak sign-in through Authlib) and boto3.
FROM apache/airflow:3.3.2
RUN pip install --no-cache-dir trino==0.340.0
