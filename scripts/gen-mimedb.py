#!/usr/bin/env python3
"""Generate src/core/mimedb.inc from minio/pkg's mimedb (mimedb.TypeByExtension).

usage: scripts/gen-mimedb.py $GOPATH/pkg/mod/github.com/minio/pkg/v3@v3.1.3/mimedb/db.go
"""
import re
import sys

s = open(sys.argv[1]).read()
ents = sorted(re.findall(r'"([^"]+)":\s*\{\s*ContentType:\s*"([^"]*)"', s))
out = ["/* SPDX-License-Identifier: AGPL-3.0-or-later */",
       "/* Generated from github.com/minio/pkg/v3 mimedb/db.go (scripts/gen-mimedb.py): extension -> type, sorted. */"]
out += ['{"%s", "%s"},' % (k, v) for k, v in ents]
open("src/core/mimedb.inc", "w").write("\n".join(out) + "\n")
