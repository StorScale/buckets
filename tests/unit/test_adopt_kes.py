# SPDX-License-Identifier: AGPL-3.0-or-later
"""scripts/adopt_kes.py: a MinIO tenant's KES, turned into a BucketsCluster's KMS settings."""
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts"))
import adopt_kes  # noqa: E402

try:
    import yaml
    load_yaml = yaml.safe_load
except ImportError:  # the configurations below are JSON, which is YAML too
    load_yaml = json.loads

# KES's configuration as the MinIO Operator's tenants carry it: ${VAR} from the pod's environment
VAULT_CONF = json.dumps({
    "address": "0.0.0.0:7373",
    "admin": {"identity": "${MINIO_KES_IDENTITY}"},
    "tls": {"key": "/tmp/kes/server.key", "cert": "/tmp/kes/server.crt"},
    "keystore": {"vault": {"endpoint": "http://vault.example:8200", "prefix": "minio",
                           "approle": {"id": "${ROLE_ID}", "secret": "${SECRET_ID}"}}},
})


def kes_sts(conf=VAULT_CONF, sa=None, env=None, args=None):
    """<tenant>-kes as the MinIO Operator lays it out."""
    tmpl = {
        "volumes": [{"name": "minio-kes", "projected": {"sources": [
            {"secret": {"name": "kes-config", "items": [{"key": "server-config.yaml", "path": "server-config.yaml"}]}},
            {"secret": {"name": "minio-kes-tls", "items": [{"key": "tls.crt", "path": "server.crt"},
                                                           {"key": "tls.key", "path": "server.key"}]}},
            {"secret": {"name": "vault-ca"}}]}}],
        "containers": [{"name": "kes", "image": "minio/kes",
                        "args": args or ["server", "--config=/tmp/kes/server-config.yaml", "--auth=off"],
                        "env": env if env is not None else [
                            {"name": "MINIO_KES_IDENTITY", "value": "abc"},
                            {"name": "ROLE_ID", "valueFrom": {"secretKeyRef": {"name": "vault-approle", "key": "id"}}},
                            {"name": "SECRET_ID", "valueFrom": {"secretKeyRef": {"name": "vault-approle", "key": "secret"}}}],
                        "volumeMounts": [{"name": "minio-kes", "mountPath": "/tmp/kes"}]}],
        "tolerations": [{"key": "dedicated", "operator": "Equal", "value": "storage", "effect": "NoSchedule"}],
        "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
            {"matchExpressions": [{"key": "role", "operator": "In", "values": ["storage"]}]}]}}},
    }
    if sa:
        tmpl["serviceAccountName"] = sa
    return {"metadata": {"name": "minio-kes"}, "spec": {"template": {"spec": tmpl}}}


SECRETS = {
    "kes-config": {"server-config.yaml": VAULT_CONF},
    "minio-kes-tls": {"tls.crt": "CERT", "tls.key": "KEY"},
    "vault-ca": {"ca.crt": "VAULTCA"},
    "vault-approle": {"id": "role-1", "secret": "s3cret"},
}


def carry(sts, key="minio-key", image="buckets-kes:1", secrets=None):
    secrets = SECRETS if secrets is None else secrets
    return adopt_kes.carry("minio", sts, key, image, secrets.get, lambda n: None, load_yaml)


class Vault(unittest.TestCase):
    def test_approle_from_the_environment(self):
        r = carry(kes_sts())
        self.assertEqual(r["problems"], [])
        self.assertEqual(r["settings"], {"backend": "vault", "vault": {
            "endpoint": "http://vault.example:8200", "engine": "kv", "version": "v1", "prefix": "minio",
            "auth": "approle", "approle": {"engine": "approle", "id": "role-1", "secret": "s3cret"}}})
        self.assertEqual(r["summary"], "Vault at http://vault.example:8200 (kv v1, prefix minio, AppRole)")

    def test_spec(self):
        r = carry(kes_sts())
        kes = r["kes"]
        self.assertEqual(kes["keyName"], "minio-key")
        self.assertIs(kes["createKey"], False)
        self.assertEqual(kes["serviceAccountName"], "default")  # the operator sets none
        self.assertEqual(kes["image"], "buckets-kes:1")
        self.assertEqual(kes["name"], "minio-buckets-kes")  # minio-kes, minio-kes-tls stay the tenant's
        self.assertEqual(kes["tolerations"][0]["key"], "dedicated")
        self.assertIn("nodeAffinity", kes["affinity"])
        self.assertNotIn("nodeSelector", kes)
        self.assertEqual(carry(kes_sts(sa="kes-sa"))["kes"]["serviceAccountName"], "kes-sa")

    def test_check_pod(self):
        pod = carry(kes_sts(sa="kes-sa"))["checkPod"]
        self.assertEqual(pod["metadata"]["name"], "minio-buckets-kes-check")
        self.assertNotIn("labels", pod["metadata"])  # never picked up by the tenant's KES Service
        spec = pod["spec"]
        self.assertEqual(spec["restartPolicy"], "Never")
        self.assertEqual(spec["serviceAccountName"], "kes-sa")
        c = spec["containers"][0]
        self.assertEqual(c["image"], "buckets-kes:1")
        self.assertEqual(c["args"], ["check", "--config", "/tmp/kes/server-config.yaml", "--key", "minio-key"])
        self.assertEqual([e["name"] for e in c["env"]], ["MINIO_KES_IDENTITY", "ROLE_ID", "SECRET_ID"])
        self.assertEqual(c["volumeMounts"], [{"name": "minio-kes", "mountPath": "/tmp/kes"}])
        self.assertEqual(spec["volumes"][0]["name"], "minio-kes")
        self.assertNotIn("s3cret", json.dumps(pod))  # references only, never values

    def test_kubernetes_engine_transit_ca(self):
        conf = json.dumps({"keystore": {"vault": {
            "endpoint": "https://vault:8200", "engine": "secret", "version": "v2", "namespace": "ns1",
            "kubernetes": {"role": "kes", "jwt": "/var/run/secrets/kubernetes.io/serviceaccount/token", "namespace": "/"},
            "transit": {"key": "wrap"}, "tls": {"ca": "/tmp/kes/ca.crt"}}}})
        r = carry(kes_sts(conf), secrets=dict(SECRETS, **{"kes-config": {"server-config.yaml": conf}}))
        self.assertEqual(r["problems"], [])
        self.assertEqual(r["settings"]["vault"], {
            "endpoint": "https://vault:8200", "engine": "secret", "version": "v2", "namespace": "ns1",
            "auth": "kubernetes", "kubernetes": {"engine": "kubernetes", "role": "kes", "namespace": "/"},
            "transit": {"engine": "transit", "key": "wrap"}, "caCert": "VAULTCA"})

    def test_refused(self):
        def problems(vault):
            conf = json.dumps({"keystore": {"vault": dict({"endpoint": "http://v"}, **vault)}})
            return " ".join(carry(kes_sts(conf), secrets=dict(SECRETS, **{"kes-config": {"server-config.yaml": conf}}))["problems"])
        self.assertIn("client certificate", problems({"approle": {"id": "a", "secret": "b"}, "tls": {"key": "/k", "cert": "/c"}}))
        self.assertIn("JWT written into", problems({"kubernetes": {"role": "r", "jwt": "eyJhbGciOi"}}))
        self.assertIn("no AppRole", problems({}))
        self.assertIn("not in a Secret", problems({"approle": {"id": "a", "secret": "b"}, "tls": {"ca": "/nowhere/ca.crt"}}))

    def test_unresolved_environment(self):
        secrets = dict(SECRETS)
        del secrets["vault-approle"]
        r = carry(kes_sts(), secrets=secrets)
        self.assertTrue(any("ROLE_ID, SECRET_ID" in p for p in r["problems"]), r["problems"])


class Shapes(unittest.TestCase):
    def test_no_statefulset(self):
        self.assertIn("no KES StatefulSet", carry(None)["problems"][0])

    def test_config_not_mounted(self):
        r = carry(kes_sts(args=["server", "--config", "/etc/kes/config.yaml"]))
        self.assertIn("not in a Secret it mounts", r["problems"][0])

    def test_no_key_name(self):
        self.assertTrue(any("names no default key" in p for p in carry(kes_sts(), key=None)["problems"]))

    def test_fs_and_unknown(self):
        for ks, want in (({"fs": {"path": "/keys"}}, "fs keystore"), ({"entrust": {}}, "not one buckets-kes supports")):
            conf = json.dumps({"keystore": ks})
            r = carry(kes_sts(conf), secrets=dict(SECRETS, **{"kes-config": {"server-config.yaml": conf}}))
            self.assertIn(want, " ".join(r["problems"]))


class Clouds(unittest.TestCase):
    def settings(self, ks):
        s, problems = adopt_kes.keystore_settings(ks, {})
        return s, problems

    def test_aws(self):
        s, p = self.settings({"aws": {"secretsmanager": {"region": "us-east-1", "kmskey": "alias/k",
                                                         "credentials": {"accesskey": "AK", "secretkey": "SK"}}}})
        self.assertEqual(p, [])
        self.assertEqual(s, {"backend": "aws", "aws": {"region": "us-east-1", "kmsKey": "alias/k",
                                                       "accessKey": "AK", "secretKey": "SK"}})
        self.assertIn("no region", self.settings({"aws": {"secretsmanager": {}}})[1][0])

    def test_azure(self):
        s, p = self.settings({"azure": {"keyvault": {"endpoint": "https://v.vault.azure.net", "credentials": {
            "tenant_id": "t", "client_id": "c", "client_secret": "x"}}}})
        self.assertEqual(p, [])
        self.assertEqual(s["azure"], {"endpoint": "https://v.vault.azure.net", "auth": "secret",
                                      "tenantId": "t", "clientId": "c", "clientSecret": "x"})
        s, p = self.settings({"azure": {"keyvault": {"endpoint": "e", "managed_identity": {"client_id": "m"}}}})
        self.assertEqual(s["azure"], {"endpoint": "e", "auth": "managedIdentity", "managedIdentityClientId": "m"})

    def test_gcp(self):
        s, p = self.settings({"gcp": {"secretmanager": {"project_id": "p", "credentials": {
            "client_email": "kes@p.iam", "client_id": "1", "private_key_id": "k1", "private_key": "PEM"}}}})
        self.assertEqual(p, [])
        cred = json.loads(s["gcp"]["credentials"])
        self.assertEqual((cred["type"], cred["client_email"], cred["private_key"]), ("service_account", "kes@p.iam", "PEM"))
        self.assertIn("workload identity", self.settings({"gcp": {"secretmanager": {"project_id": "p"}}})[1][0])


class Names(unittest.TestCase):
    def test_collisions(self):
        def obj(kind, name, cluster=None):
            return {"kind": kind, "metadata": dict({"name": name}, **({"labels": {"buckets.io/cluster": cluster}} if cluster else {}))}
        existing = [obj("Secret", "minio-kes-tls"), obj("StatefulSet", "minio-kes"), obj("Service", "minio-kes"),
                    obj("Secret", "minio-kms", "minio"),             # a previous run's
                    obj("Secret", "minio-buckets-config"),           # someone else's
                    obj("Deployment", "minio-buckets-kes", "other")]
        self.assertEqual(adopt_kes.collisions("minio", existing),
                         ["Secret minio-buckets-config", "Deployment minio-buckets-kes"])
        self.assertEqual(adopt_kes.collisions("minio", []), [])


class ConfigEnv(unittest.TestCase):
    def test_without_kms_lines(self):
        env = ("export MINIO_ROOT_USER=a\nexport MINIO_KMS_KES_ENDPOINT=https://minio-kes:7373\n"
               "MINIO_KMS_KES_KEY_NAME=minio-key\nexport MINIO_ROOT_PASSWORD=b\n")
        clean, gone = adopt_kes.without_kms_lines(env)
        self.assertTrue(gone)
        self.assertEqual(clean, "export MINIO_ROOT_USER=a\nexport MINIO_ROOT_PASSWORD=b\n")
        self.assertEqual(adopt_kes.without_kms_lines("A=1"), ("A=1", False))


if __name__ == "__main__":
    unittest.main()
