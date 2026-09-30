#!/usr/bin/env python3
"""SFTP sessions against MinIO's SFTP server and bucketsd's (see sftp.sh).

usage: sftp_cases.py BASE_PORT ACCESS SECRET WORK

MinIO serves S3 on BASE and SFTP on BASE+2; bucketsd on BASE+1 and BASE+3.
Each case runs the same commands (tests/integration/sftpclient) against both
and compares the results, modification times aside.
"""
import json
import os
import re
import subprocess
import sys

from adminlib import Score, compare, curl, setup

BASE, AK, SK, WORK = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
setup(AK, SK)
S3 = (f"http://127.0.0.1:{BASE}", f"http://127.0.0.1:{BASE + 1}")
SFTP = (BASE + 2, BASE + 3)
CLIENT = os.environ["SFTPCLIENT"]
MC = os.environ.get("MC", "mc")
MC_CFG = os.path.join(WORK, "mc")


def norm(v):
    """Modification times differ by nature; so do the ports."""
    if isinstance(v, dict):
        return {k: ("<mtime>" if k == "mtime" and x > 315532800 else norm(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [norm(x) for x in v]
    if isinstance(v, str):
        return re.sub(r"127\.0\.0\.1:\d+", "<addr>", v)
    return v


def session(i, user, auth, commands):
    p = subprocess.run([CLIENT, f"127.0.0.1:{SFTP[i]}", user, *auth], input="\n".join(commands) + "\n",
                       capture_output=True, text=True, timeout=120)
    out = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
    return norm(out) or [p.stderr[-300:]]


def run(name, user, auth, commands):
    compare(name, session(0, user, auth, commands), session(1, user, auth, commands))


def mc(*args):
    return subprocess.run([MC, "--config-dir", MC_CFG, *args], capture_output=True, text=True)


def ssh_keygen(*args):
    subprocess.run(["ssh-keygen", "-q", *args], check=True, capture_output=True)


# users: read-write, read-only, none; a service account
for i, base in enumerate(S3):
    mc("alias", "set", f"a{i}", base, AK, SK)
    mc("admin", "user", "add", f"a{i}", "sftpuser", "sftpsecret123")
    mc("admin", "policy", "attach", f"a{i}", "readwrite", "--user", "sftpuser")
    mc("admin", "user", "add", f"a{i}", "sftpreader", "readersecret123")
    mc("admin", "policy", "attach", f"a{i}", "readonly", "--user", "sftpreader")
    mc("admin", "user", "add", f"a{i}", "certuser", "certsecret123")
    mc("admin", "policy", "attach", f"a{i}", "readwrite", "--user", "certuser")
    mc("admin", "user", "svcacct", "add", f"a{i}", "sftpuser", "--access-key", "sftpsvcacct1",
       "--secret-key", "sftpsvcsecret123")

ROOT = ["password=" + SK]
USER = ["password=sftpsecret123"]

# ---- logins ------------------------------------------------------------------------------------------------

run("root login", AK, ROOT, ["realpath ."])
run("wrong password", "sftpuser", ["password=nope"], [])
run("unknown user", "nosuchuser", ["password=whatever"], [])
run("service account", "sftpsvcacct1", ["password=sftpsvcsecret123"], ["realpath /"])
run("service account, =svc", "sftpsvcacct1=svc", ["password=sftpsvcsecret123"], ["realpath /"])
run("=ldap without LDAP", "sftpuser=ldap", USER, [])

# ---- paths, directories and files ---------------------------------------------------------------------------

run("paths", "sftpuser", USER, ["realpath .", "realpath ..", "realpath /a/b/../c", "realpath a//b/", "realpath /",
                                 "stat /", "lstat /", "stat .", "stat /nosuchbucket", "stat /ab", "readlink /"])
run("directories and files", "sftpuser", USER, [
    "mkdir /sftpb", "mkdir /sftpb", "mkdir /sftpb/dir1", "mkdir /sftpb/dir1/sub", "mkdir /x", "mkdir /nosuchb/dir",
    "put /sftpb/dir1/small.txt 1000", "put /sftpb/big.bin 3000000", "put /sftpb/empty.json 0",
    "put /nosuchbucket/f.txt 10", "put / 10",
    "ls /", "ls /sftpb", "ls /sftpb/dir1", "ls /sftpb/dir1/small.txt", "ls /nosuchbucket",
    "stat /sftpb/big.bin", "stat /sftpb/dir1", "stat /sftpb/nothere", "lstat /sftpb/dir1/small.txt",
    "get /sftpb/dir1/small.txt", "get /sftpb/big.bin", "get /sftpb/nothere", "get /sftpb",
    "getat /sftpb/big.bin 0 1000", "getat /sftpb/big.bin 2999000 5000", "getat /sftpb/big.bin 1500000 32768",
    "getat /sftpb/big.bin 3000000 10", "getat /sftpb/dir1/small.txt 10 10",
    "writeoff /sftpb/reordered.bin 100000", "get /sftpb/reordered.bin",
    "openflags /sftpb/dir1/small.txt r", "openflags /sftpb/nothere r", "openflags /sftpb/c.txt c",
    "openflags /sftpb/w.txt w", "openflags /sftpb/rw.txt rw", "openflags /nosuchbucket/x rw",
    "rename /sftpb/big.bin /sftpb/moved.bin", "posixrename /sftpb/big.bin /sftpb/moved.bin",
    "symlink /sftpb/big.bin /sftpb/link", "link /sftpb/big.bin /sftpb/hard", "chmod /sftpb/big.bin",
    "statvfs /sftpb", "readlink /sftpb/big.bin",
])


def objects(i):
    """What SFTP stored, as S3 clients see it."""
    out = {}
    for key in ("dir1/small.txt", "big.bin", "empty.json", "reordered.bin", "w.txt", "rw.txt", "dir1/", "dir1/sub/"):
        c, h, b = curl(f"{S3[i]}/sftpb/{key}", "HEAD", headers=("x-amz-checksum-mode: ENABLED",))
        out[key] = (c, h.get("content-type"), h.get("content-length"), h.get("x-amz-checksum-crc32c"),
                    h.get("x-amz-checksum-type"), re.sub(r"[0-9a-f]{32}", "<md5>", h.get("etag", "")))
    return out


compare("objects written over SFTP", objects(0), objects(1))

# a directory of 250 entries: READDIR's pages of 100
for i, base in enumerate(S3):
    curl(f"{base}/manyb", "PUT")
    for k in range(250):
        curl(f"{base}/manyb/f{k:03d}", "PUT", b"x")
run("a directory in pages", "sftpuser", USER, ["ls /manyb"])

run("removing", "sftpuser", USER, [
    "remove /sftpb/nothere", "remove /sftpb", "remove /sftpb/empty.json", "rmdir /sftpb/dir1", "ls /sftpb",
    "rmdir /sftpb", "rmdir /", "rmdir /nosuchbucket", "remove /sftpb/big.bin", "remove /sftpb/reordered.bin",
    "remove /sftpb/c.txt", "remove /sftpb/w.txt", "remove /sftpb/rw.txt", "rmdir /sftpb", "ls /",
])

# ---- permissions -------------------------------------------------------------------------------------------

for i, base in enumerate(S3):
    curl(f"{base}/permb", "PUT")
    curl(f"{base}/permb/r.txt", "PUT", b"readable")
run("a read-only user", "sftpreader", ["password=readersecret123"], [
    "get /permb/r.txt", "put /permb/w.txt 10", "mkdir /permb/d", "remove /permb/r.txt", "mkdir /newbucketx",
    "rmdir /permb", "ls /permb", "ls /"])

# ---- certificates of the trusted user CA ---------------------------------------------------------------------

ssh_keygen("-t", "ed25519", "-N", "", "-f", f"{WORK}/user")
ssh_keygen("-s", f"{WORK}/ca", "-I", "certuser", "-n", "certuser", "-V", "-5m:+1h", f"{WORK}/user.pub")
ssh_keygen("-t", "ecdsa", "-N", "", "-f", f"{WORK}/other")
ssh_keygen("-s", f"{WORK}/ca", "-I", "other", "-n", "someoneelse", "-V", "-5m:+1h", f"{WORK}/other.pub")
ssh_keygen("-t", "rsa", "-b", "2048", "-N", "", "-f", f"{WORK}/old")
ssh_keygen("-s", f"{WORK}/ca", "-I", "old", "-n", "certuser", "-V", "-2h:-1h", f"{WORK}/old.pub")
ssh_keygen("-t", "ed25519", "-N", "", "-f", f"{WORK}/forced")
ssh_keygen("-s", f"{WORK}/ca", "-I", "forced", "-n", "certuser", "-O", "force-command=/bin/false", "-V", "-5m:+1h",
           f"{WORK}/forced.pub")
ssh_keygen("-t", "ed25519", "-N", "", "-f", f"{WORK}/rogueca")
ssh_keygen("-t", "ed25519", "-N", "", "-f", f"{WORK}/rogue")
ssh_keygen("-s", f"{WORK}/rogueca", "-I", "rogue", "-n", "certuser", "-V", "-5m:+1h", f"{WORK}/rogue.pub")

run("a certificate of the trusted CA", "certuser", [f"key={WORK}/user", f"cert={WORK}/user-cert.pub"],
    ["mkdir /certb", "put /certb/c.txt 100", "ls /certb"])
run("a certificate for another principal", "certuser", [f"key={WORK}/other", f"cert={WORK}/other-cert.pub"], [])
run("an expired certificate", "certuser", [f"key={WORK}/old", f"cert={WORK}/old-cert.pub"], [])
run("a certificate with a critical option", "certuser", [f"key={WORK}/forced", f"cert={WORK}/forced-cert.pub"], [])
run("a certificate of another CA", "certuser", [f"key={WORK}/rogue", f"cert={WORK}/rogue-cert.pub"], [])
run("a key without a certificate", "certuser", [f"key={WORK}/user"], [])

print(f"sftp: {Score.passed} passed, {Score.failed} failed")
sys.exit(1 if Score.failed else 0)
