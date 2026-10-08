#!/usr/bin/env python3
"""S3 Select, differentially: every case runs against MinIO and bucketsd, and
the responses must agree (HTTP status and error, the Records payload, error
events). Cases where Buckets deliberately differs carry `buckets`: what
Buckets answers instead (see docs/parity.md).

usage: select_cases.py MINIO_URL BUCKETS_URL ACCESS SECRET [filter]
"""
import binascii
import bz2
import gzip
import io
import os
import random
import re
import struct
import subprocess
import sys
import tempfile

MINIO, BUCKETS, AK, SK = sys.argv[1:5]
FILTER = sys.argv[5] if len(sys.argv) > 5 else ""
BUCKET = "selecttest"


def curl(url, method="GET", data=None, headers=()):
    args = ["curl", "-s", "-X", method, "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", f"{AK}:{SK}",
            "-o", "-", "-w", "\n%{http_code}"]
    for h in headers:
        args += ["-H", h]
    if data is not None:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(data)
        f.close()
        args += ["--data-binary", "@" + f.name]
    out = subprocess.run(args + [url], capture_output=True).stdout
    body, _, code = out.rpartition(b"\n")
    return int(code or 0), body


def decode(stream):
    """The event stream as (records, [(type, value)]); CRCs checked."""
    records, events, pos = b"", [], 0
    while pos < len(stream):
        total, hlen = struct.unpack(">II", stream[pos:pos + 8])
        assert binascii.crc32(stream[pos:pos + 8]) == struct.unpack(">I", stream[pos + 8:pos + 12])[0], "prelude crc"
        msg = stream[pos:pos + total]
        assert binascii.crc32(msg[:-4]) == struct.unpack(">I", msg[-4:])[0], "message crc"
        hdrs, h = {}, msg[12:12 + hlen]
        i = 0
        while i < len(h):
            n = h[i]
            name = h[i + 1:i + 1 + n].decode()
            vl = struct.unpack(">H", h[i + 2 + n:i + 4 + n])[0]
            hdrs[name] = h[i + 4 + n:i + 4 + n + vl].decode()
            i += 4 + n + vl
        payload = msg[12 + hlen:-4]
        if hdrs.get(":message-type") == "error":
            events.append(("error", hdrs.get(":error-code"), hdrs.get(":error-message")))
        elif hdrs.get(":event-type") == "Records":
            records += payload
        elif hdrs.get(":event-type") == "Stats":
            events.append(("Stats", payload.decode()))
        elif hdrs.get(":event-type") == "End":
            events.append(("End",))
        pos += total
    return records, events


def summarize(code, body, stats=True):
    if code != 200:
        m = re.search(rb"<Code>(.*?)</Code>.*?<Message>(.*?)</Message>", body, re.S)
        if m and m.group(1) == b"ParseSelectFailure":
            # participle's messages (the expected tokens and where it gave up) are not reproduced
            return ("http", code, "ParseSelectFailure")
        return ("http", code) + ((m.group(1).decode(), m.group(2).decode()) if m else (body[:200],))
    try:
        records, events = decode(body)
    except Exception as e:  # noqa: BLE001
        return ("undecodable", str(e))
    if not stats:  # read-ahead makes the counts of a LIMIT query MinIO's own
        events = [ev[:1] if ev[0] == "Stats" else ev for ev in events]
    return ("ok", records.decode("utf-8", "replace"), tuple(events))


def request(query, inp, out, extra=""):
    q = query.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (f'<?xml version="1.0" encoding="UTF-8"?><SelectObjectContentRequest><Expression>{q}</Expression>'
            f"<ExpressionType>SQL</ExpressionType><InputSerialization>{inp}</InputSerialization>"
            f"<OutputSerialization>{out}</OutputSerialization><RequestProgress><Enabled>FALSE</Enabled>"
            f"</RequestProgress>{extra}</SelectObjectContentRequest>").encode()


CSV_USE = "<CompressionType>NONE</CompressionType><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>"
CSV_NONE = "<CompressionType>NONE</CompressionType><CSV><FileHeaderInfo>NONE</FileHeaderInfo></CSV>"
JSON_DOC = "<CompressionType>NONE</CompressionType><JSON><Type>DOCUMENT</Type></JSON>"
JSON_LINES = "<CompressionType>NONE</CompressionType><JSON><Type>LINES</Type></JSON>"
OUT_JSON = "<JSON></JSON>"
OUT_CSV = "<CSV></CSV>"

J1 = b'''{"id": 0,"title": "Test Record","desc": "Some text","synonyms": ["foo", "bar", "whatever"]}
{"id": 1,"title": "Second Record","desc": "another text","synonyms": ["some", "synonym", "value"]}
{"id": 2,"title": "Second Record","desc": "another text","numbers": [2, 3.0, 4]}
{"id": 3,"title": "Second Record","desc": "another text","nested": [[2, 3.0, 4], [7, 8.5, 9]]}'''
UA = b'{"request":{"uri":"/1","header":{"User-Agent":"test"}}}\n{"request":{"uri":"/2","header":{}}}'
ELEMS = b'''{"name": "small_pdf1.pdf", "elements": [
  {"element_type": "__elem__image", "element_id": "859d", "attributes": {"dpi": 300, "size": [2550, 3299], "data": null}},
  {"element_type": "__elem__merfu", "element_id": "d868", "attributes": {"dpi": 300, "size": [2550, 3299], "data": null}}],
  "data": "asdascasdc1234e123erdasdas"}'''
C2 = b'''id,time,num,num2,text
1,2010-01-01T,7867786,4565.908123,"a text, with comma"
2,2017-01-02T03:04Z,-5, 0.765111,
'''
C3 = b'''na.me,qty,CAST
apple,1,true
mango,3,false
'''
CIN = b'''one,two,three
-1,foo,true
,bar,false
2.5,baz,true
'''
CRIME = (b'index,ID,CaseNumber,Date,Day,Month,Year,Block,IUCR,PrimaryType,Description,LocationDescription,Arrest,'
         b'Domestic,Beat,District,Ward,CommunityArea,FBI Code,XCoordinate,YCoordinate,UpdatedOn,Latitude,Longitude,'
         b'Location\n2700763,7732229,,2010-05-26 00:00:00,26,May,2010,113XX S HALSTED ST,1150,,CREDIT CARD FRAUD,,'
         b'False,False,2233,22.0,34.0,,11,,,,41.688043288,-87.6422444,"(41.688043288, -87.6422444)"')
NUMS = b'''a,b,c,d
1,2,3.5,x
10,-4,1e3,y
7,0,0.000001,z
100000000,123456789,1234567.5,w
'''
TIMES = b'''t
2017-01-02T03:04:05.123456789+05:30
2010T
2010-05T
2010-05-06T
2010-05-06T07:08Z
'''

CASES = []


def case(name, data, inp, query, out=OUT_JSON, extra="", buckets=None, xml=None, suffix="", put=(), simd=False):
    """simd: MinIO answers differently when it reads JSON lines with simdjson, which it does on CPUs with AVX2 and
    CLMUL (integers kept as integers, <&> unescaped, simdjson's error words); Buckets answers as MinIO does
    elsewhere (encoding/json), so on such a CPU a difference is a note, not a failure."""
    CASES.append(dict(name=name, data=data, inp=inp, query=query, out=out, extra=extra, buckets=buckets, xml=xml,
                      suffix=suffix, put=put, simd=simd))


def minio_uses_simdjson():
    try:
        flags = open("/proc/cpuinfo").read()
    except OSError:
        return False
    return " avx2" in flags and " pclmulqdq" in flags


# ---- MinIO's TestJSONQueries ----
for i, q in enumerate([
    "SELECT * from s3object s WHERE 'bar' IN s.synonyms[*]",
    "SELECT * from s3object s WHERE s.id IN (1,3)",
    "SELECT synonyms from s3object s WHERE 'bar' IN s.synonyms[*] ",
    "SELECT * from s3object s WHERE 'bar' in s.synonyms",
    "select * from s3object s where 'bar' in s.synonyms and s.id = 0",
    "select * from s3object s where 'some' in ('somex', s.synonyms[0]) and s.id = 1",
    "select SUM(s.id) from s3object s Where 2 in s.numbers[*] or 'some' in s.synonyms[*]",
    "SELECT id from s3object s WHERE s.id <= 9223372036854775807",
    "SELECT id from s3object s WHERE s.id >= -9223372036854775808",
    "SELECT * from s3object s WHERE 'value' IN s.synonyms[*]",
    "SELECT * from s3object s WHERE 4 in s.numbers[*]",
    "SELECT * from s3object s WHERE 3.0 in s.numbers[*]",
    "SELECT * from s3object s WHERE (2,3,4) IN s.nested[*]",
    "SELECT s.nested from s3object s WHERE 8.5 IN s.nested[*][*]",
    "SELECT s.nested from s3object s WHERE (8.5 IN s.nested[*][*]) AND (s.id > 0)",
    "SELECT s.nested from s3object s WHERE 8.5 IN s.nested[*]",
    "SELECT * from s3object s WHERE s.nested[0][0] = 2",
    "SELECT * from s3object s WHERE s.nested[1][0] != 7",
    "SELECT * from s3object s WHERE (7,8.5,9) IN s.nested[1]",
    "SELECT * from s3object s WHERE (7,8.5,9) = s.nested[1]",
    "SELECT s.* from s3object s WHERE (7,8.5,9) = s.nested[1]",
    "SELECT s.nested[1], s.nested[0] from s3object s WHERE (7,8.5,9) = s.nested[1]",
    "SELECT * from s3object s WHERE (7,8.5,9) != s.nested[1]",
    "SELECT * from s3object s WHERE [7,8.5,9] = s.nested[1]",
    "SELECT * from s3object s WHERE [7,8.5,9] IN s.nested",
    "SELECT * from s3object s WHERE id IN [3,2]",
    "SELECT * from s3object s WHERE (8.5) IN s.nested[1][*]",
    "SELECT * from s3object s WHERE (8.0+0.5) IN s.nested[1][*]",
    "SELECT * from s3object s WHERE title = 'Test Record'",
    "SELECT date_diff(MONTH, '2019-10-20T', '2020-01-20T') FROM S3Object LIMIT 1",
    "SELECT date_diff(MONTH, '2020-01-20T', '2019-10-20T') FROM S3Object LIMIT 1",
    "SELECT date_diff(year, '2010-01-01T', '2011-01-01T') FROM S3Object LIMIT 1",
    "SELECT date_diff(month, '2010-01-01T', '2010-05T') FROM S3Object LIMIT 1",
    "SELECT date_diff(month, '2010T', '2011T') FROM S3Object LIMIT 1",
    "SELECT date_diff(day, '2010-01-01T23:00:00Z', '2010-01-02T01:00:00Z') FROM S3Object LIMIT 1",
    "SELECT date_diff(day, '2010-01-01T23:00:00Z', '2010-01-02T23:00:00Z') FROM S3Object LIMIT 1",
    "SELECT cast(1 as float) FROM S3Object LIMIT 1",
    "SELECT cast(1.0 as float) FROM S3Object LIMIT 1",
    "SELECT 1 / 2 FROM S3Object LIMIT 1",
    "SELECT 1.0 / 2.0 * .3 FROM S3Object LIMIT 1",
    "SELECT 3.0 / 2, 5 / 2.0 FROM S3Object LIMIT 1",
    "SELECT s.id, s.title FROM S3Object s LIMIT 2",
    "SELECT COUNT(*), MIN(s.id), MAX(s.id), AVG(s.id), SUM(s.id) FROM S3Object s",
]):
    case(f"json-{i}", J1, JSON_LINES, q)
    case(f"json-doc-{i}", J1, JSON_DOC, q)
case("json-false", b'{"id":0, "value": false}\n{"id":1, "value": true}', JSON_LINES,
     "SELECT id from s3object s WHERE value = true")
case("json-count-alias", b'{"id":0, "value": false}\n{"id":1, "value": true}', JSON_LINES,
     "SELECT COUNT(id) as n from s3object s WHERE value != true")
case("json-to-csv", J1, JSON_DOC, "SELECT s.synonyms from s3object s WHERE 'whatever' IN s.synonyms", out=OUT_CSV)
case("json-elements", ELEMS, JSON_DOC, "select * from s3object[*].elements[*] s where s.element_type = '__elem__merfu'")
case("json-elements-limit", ELEMS, JSON_DOC, "SELECT * FROM S3Object[*].elements[*] LIMIT 1")
case("json-person", b'{ "person": [ { "Id": 1, "Name": "Anshu" }, { "Id": 2, "Name": "Ben" } ] }', JSON_DOC,
     "select * from s3object[*].person[*] limit 1")
for i, q in enumerate([
    "select * from s3object[*] as s where s.request.header['User-Agent'] is not null",
    "select * from s3object[*] as s where s.request.header['User-Agent'] is not missing",
    "select * from s3object[*] as s where s.request.header is not missing",
    "select * from s3object[*] as s where s.request.header['User-Agent'] is missing",
    "select * from s3object[*] as s where s.request.header is missing",
    "select * from s3object[*] as s where s.request.header['User-Agent'] = missing",
    "select s.request.header['User-Agent'] as h from s3object[*] as s",
    "select s.request.uri from s3object[*] as s",
    "select s.request from s3object s",
    "select s.request.header.* from s3object s",
]):
    case(f"json-ua-{i}", UA, JSON_LINES, q)

# ---- MinIO's CSV tests ----
case("crime", CRIME, CSV_USE, "SELECT index FROM s3Object s WHERE \"Month\"='May'", out=OUT_CSV)
case("crime-json", CRIME, CSV_USE, "SELECT * FROM s3Object s", out=OUT_JSON)
for i, q in enumerate([
    "SELECT * from s3object AS s WHERE id = '1'",
    "SELECT * from s3object s WHERE id = 2",
    "SELECT CAST(text AS STRING) AS text from s3object s WHERE id = 1",
    "SELECT text from s3object s WHERE id = 1",
    "SELECT time from s3object s WHERE id = 2",
    "SELECT num from s3object s WHERE id = 2",
    "SELECT num2 from s3object s WHERE id = 2",
    "select id from S3Object s WHERE id in [1,3]",
    "select id from S3Object s WHERE s.id in [4,3]",
    "SELECT num2 from s3object s WHERE num2 = 0.765111",
    "SELECT _1 as first, s._100 from s3object s LIMIT 1",
    "select _2 from S3object where _2 IS NULL",
    "select _2 from S3object WHERE _100 IS NULL",
    "select _2 from S3object where _2 IS NOT NULL",
    "select _2 from S3object WHERE _100 IS NOT NULL",
    "SELECT num * 2, num2 + 1, num / 3, num % 7 from s3object",
    "SELECT EXTRACT(YEAR FROM time), EXTRACT(MONTH FROM time), EXTRACT(HOUR FROM CAST(time AS TIMESTAMP)) from s3object s",
    "SELECT DATE_ADD(DAY, 40, time), DATE_ADD(MONTH, -2, time), DATE_ADD(HOUR, 30, time) from s3object s",
    "SELECT text LIKE 'a%', text NOT LIKE '%comma', UPPER(text), LOWER(text), CHAR_LENGTH(text) from s3object s WHERE id = 1",
    "SELECT SUBSTRING(text, 3), SUBSTRING(text FROM 3 FOR 4), SUBSTRING(text, -1, 3), SUBSTRING(text, 100) from s3object s WHERE id = 1",
    "SELECT TRIM(num2), TRIM(LEADING FROM num2), TRIM(BOTH 'a' FROM text) from s3object s",
    "SELECT COALESCE(text, 'none'), COALESCE(NULL, NULL, 'x') from s3object s",
    "SELECT num BETWEEN -10 AND 0, num NOT BETWEEN 0 AND 10 from s3object s",
    "SELECT COUNT(*), SUM(num), AVG(num2), MIN(num2), MAX(time) from s3object s",
    "SELECT COUNT(text), COUNT(*) from s3object",
    "SELECT * FROM s3object LIMIT 0",
    "SELECT id FROM s3object WHERE id > 1 OR id < 1",
    "SELECT id FROM s3object WHERE NOT id = 1",
    "SELECT CAST(num AS INT), CAST(num2 AS INT), CAST(num2 AS FLOAT), CAST(id AS BOOL) FROM s3object",
    "SELECT CAST('true' AS BOOL), CAST('x' AS INT) FROM s3object",
    "SELECT nosuch FROM s3object",
    "SELECT s.id FROM s3object s WHERE s.id",
]):
    case(f"csv2-{i}", C2, CSV_USE, q)
    case(f"csv2-csv-{i}", C2, CSV_USE, q, out=OUT_CSV)
case("csv-is-not-empty", b"c1,c2,c3\n1,2,3\n1,,3", CSV_USE, "select * from S3object where _2 IS NOT ''")
case("csv-ne-and", b"c1,c2,c3\n1,2,3\n1,,3", CSV_USE, "select * from S3object where _2 != '' AND _2 > 1")
for i, q in enumerate([
    'select "na.me" from S3Object s',
    'select count(S3Object."na.me") from S3Object',
    'select s."na.me" from S3Object as s',
    "select qty from S3Object",
    "select S3Object.qty from S3Object",
    "select s.qty from S3Object s",
    'select "CAST"  from s3object',
    'select S3Object."CAST" from s3object',
    'select s."CAST"  from s3object s',
    'select NOT CAST(s."CAST" AS Bool)  from s3object s',
]):
    case(f"csv3-{i}", C3, CSV_USE, q, out=OUT_CSV)
for i, (q, out) in enumerate([
    ("SELECT one, two, three from S3Object", OUT_CSV),
    ("SELECT COUNT(*) AS total_record_count from S3Object", OUT_JSON),
    ("SELECT * from S3Object", OUT_JSON),
    ("SELECT one from S3Object limit 1", OUT_CSV),
]):
    case(f"csvin-{i}", CIN, CSV_USE, q, out=out)

# ---- numbers, times, formatting ----
for i, q in enumerate([
    "SELECT * FROM s3object",
    "SELECT a + b, a - b, a * b, a / b, a % b, c * 2, c / 3, -a, -c FROM s3object",
    "SELECT CAST(c AS FLOAT), CAST(c AS INT), CAST(a AS STRING), CAST(c AS STRING) FROM s3object",
    "SELECT SUM(a), SUM(c), AVG(a), MIN(c), MAX(c), MIN(a), MAX(a) FROM s3object",
    "SELECT a FROM s3object WHERE a > 5",
    "SELECT a FROM s3object WHERE c > 5",
    "SELECT a FROM s3object WHERE a = '10'",
    "SELECT a FROM s3object WHERE d > 'x'",
    "SELECT a FROM s3object WHERE b IN (0, 2, -4)",
    "SELECT 1e3 FROM s3object",
    "SELECT 12345678901234567890 FROM s3object LIMIT 1",
    "SELECT d + 1 FROM s3object",
    "SELECT a / 0 FROM s3object",
    "SELECT a FROM s3object WHERE d LIKE '_'",
]):
    case(f"nums-{i}", NUMS, CSV_USE, q)
    case(f"nums-csv-{i}", NUMS, CSV_USE, q, out=OUT_CSV)
case("nums-json", b'{"a": 1, "b": 2.5, "c": 1e21, "d": 1e7, "e": 100000000, "f": 0.000123, "g": -0.0}\n',
     JSON_LINES, "SELECT * FROM s3object")
case("nums-json-csv", b'{"a": 1, "b": 2.5, "c": 1e21, "d": 1e7, "e": 100000000, "f": 0.000123}\n',
     JSON_LINES, "SELECT * FROM s3object", out=OUT_CSV)
case("nums-json-cols", b'{"a": 1, "b": 2.5, "c": 1e21, "d": 1e7, "e": 100000000, "f": 0.000123, "g": 1.5e9}\n',
     JSON_LINES, "SELECT s.a, s.b, s.c, s.d, s.e, s.f, s.g FROM s3object s", out=OUT_CSV, simd=True)
for i, q in enumerate([
    "SELECT * FROM s3object",
    "SELECT CAST(t AS TIMESTAMP) FROM s3object",
    "SELECT EXTRACT(TIMEZONE_HOUR FROM t), EXTRACT(TIMEZONE_MINUTE FROM t), EXTRACT(SECOND FROM t), EXTRACT(DAY FROM t) FROM s3object",
    "SELECT DATE_ADD(YEAR, 1, t), DATE_ADD(SECOND, 90, t), DATE_ADD(MINUTE, 1.9, t) FROM s3object",
    "SELECT DATE_DIFF(HOUR, t, '2020-01-01T'), DATE_DIFF(MINUTE, '2020-01-01T', t) FROM s3object",
    "SELECT t FROM s3object WHERE CAST(t AS TIMESTAMP) > CAST('2011T' AS TIMESTAMP)",
    "SELECT MAX(CAST(t AS TIMESTAMP)) FROM s3object",
]):
    case(f"times-{i}", TIMES, CSV_USE, q)
case("times-json", b'{"t": "2017-01-02T03:04:05Z"}', JSON_LINES, "SELECT DATE_ADD(DAY, 1, s.t) AS x FROM s3object s")

# ---- CSV options ----
SEMI = b"a;b;c\r\n1;\"x;y\";3\r\n# comment\r\n\r\n4;5;6\r\n"
case("csv-semicolon", SEMI, "<CSV><FileHeaderInfo>USE</FileHeaderInfo><FieldDelimiter>;</FieldDelimiter></CSV>",
     "SELECT * FROM s3object")
case("csv-semicolon-csvout", SEMI, "<CSV><FileHeaderInfo>USE</FileHeaderInfo><FieldDelimiter>;</FieldDelimiter></CSV>",
     "SELECT * FROM s3object", out="<CSV><FieldDelimiter>|</FieldDelimiter><RecordDelimiter>;;</RecordDelimiter></CSV>")
case("csv-ignore", C2, "<CSV><FileHeaderInfo>IGNORE</FileHeaderInfo></CSV>", "SELECT _1, _5 FROM s3object")
case("csv-none", C2, CSV_NONE, "SELECT * FROM s3object")
case("csv-quotefields", C2, CSV_USE, "SELECT * FROM s3object", out="<CSV><QuoteFields>ALWAYS</QuoteFields></CSV>")
case("csv-quote-out", b"a,b\n\"he said \"\"hi\"\"\", x\n", CSV_USE, "SELECT * FROM s3object",
     out="<CSV><QuoteCharacter>'</QuoteCharacter><QuoteEscapeCharacter>\\</QuoteEscapeCharacter></CSV>")
case("csv-escape-in", b"a,b\n'it\\'s','x'\n", "<CSV><FileHeaderInfo>USE</FileHeaderInfo><QuoteCharacter>'</QuoteCharacter>"
     "<QuoteEscapeCharacter>\\</QuoteEscapeCharacter></CSV>", "SELECT * FROM s3object")
case("csv-rdelim", b"a,b|1,2|3,4|", "<CSV><FileHeaderInfo>USE</FileHeaderInfo><RecordDelimiter>|</RecordDelimiter></CSV>",
     "SELECT * FROM s3object")
case("csv-rdelim2", b"a,b::1,2::3,4", "<CSV><FileHeaderInfo>USE</FileHeaderInfo><RecordDelimiter>::</RecordDelimiter></CSV>",
     "SELECT * FROM s3object")
case("csv-noquote", b'a,b\n"x",y\n', "<CSV><FileHeaderInfo>USE</FileHeaderInfo><QuoteCharacter></QuoteCharacter></CSV>",
     "SELECT * FROM s3object")
case("csv-comment", b"a,b\n!1,2\n3,4\n", "<CSV><FileHeaderInfo>USE</FileHeaderInfo><Comments>!</Comments></CSV>",
     "SELECT * FROM s3object")
case("csv-dup-names", b"a,a,b\n1,2,3\n", CSV_USE, "SELECT a, b FROM s3object")
case("csv-ragged", b"a,b\n1\n2,3,4\n", CSV_USE, "SELECT * FROM s3object")
case("csv-ragged-csv", b"a,b\n1\n2,3,4\n", CSV_USE, "SELECT * FROM s3object", out=OUT_CSV)
case("csv-quoted-newline", b'a,b\n"x\ny",2\n', CSV_USE, "SELECT * FROM s3object")
case("csv-lazy-quote", b'a,b\nx"y,"p"q"\n', CSV_USE, "SELECT * FROM s3object")
case("csv-html", b"a\n<b>&amp;</b>\n", CSV_USE, "SELECT * FROM s3object")
case("csv-unicode", "a,b\nÄpfel,ωμέγα\nstraße,ПРИВЕТ\n".encode(), CSV_USE,
     "SELECT UPPER(a), LOWER(b), CHAR_LENGTH(a), SUBSTRING(b, 2, 2) FROM s3object")
case("csv-bad-utf8", b"a\n\xff\xfe\n", CSV_USE, "SELECT * FROM s3object")
case("csv-bad-delim", b"a\n1\n", '<CSV><FileHeaderInfo>USE</FileHeaderInfo><FieldDelimiter>"</FieldDelimiter></CSV>',
     "SELECT * FROM s3object")
case("csv-leading-space", b"a,b\n x,y\n", CSV_USE, "SELECT * FROM s3object", out=OUT_CSV)
case("csv-trailing-comma", b"a,b\n1,\n", CSV_USE, "SELECT * FROM s3object")
case("csv-crlf-end", b"a,b\r\n1,2\r", CSV_USE, "SELECT * FROM s3object")

# ---- scan ranges (MinIO's TestCSVRanges) ----
for i, rng in enumerate(["<Start>76</Start><End>109</End>", "<Start>76</Start>", "<End>35</End>",
                         "<Start>56</Start><End>76</End>", "<Start>2</Start><End>1</End>", "<Start>1000</Start>"]):
    case(f"range-{i}", C2, CSV_NONE, "SELECT * from s3object AS s", extra=f"<ScanRange>{rng}</ScanRange>")
case("range-empty", C2, CSV_NONE, "SELECT * from s3object AS s", extra="<ScanRange></ScanRange>")

# ---- compression ----
for name, data in [("gzip", gzip.compress(C2)), ("bzip2", bz2.compress(C2)), ("gzip-multi", gzip.compress(C2[:30]) + gzip.compress(C2[30:]))]:
    ct = "BZIP2" if name == "bzip2" else "GZIP"
    case(f"comp-{name}", data, f"<CompressionType>{ct}</CompressionType><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>",
         "SELECT * FROM s3object")
    case(f"comp-{name}-json", gzip.compress(J1) if ct == "GZIP" else bz2.compress(J1),
         f"<CompressionType>{ct}</CompressionType><JSON><Type>LINES</Type></JSON>", "SELECT s.id FROM s3object s")
case("comp-not-gzip", C2, "<CompressionType>GZIP</CompressionType><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>",
     "SELECT * FROM s3object")
case("comp-not-gzip-json", J1, "<CompressionType>GZIP</CompressionType><JSON><Type>LINES</Type></JSON>",
     "SELECT * FROM s3object")
case("comp-truncated", gzip.compress(C2 * 50)[:200],
     "<CompressionType>GZIP</CompressionType><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>", "SELECT * FROM s3object")
case("comp-bad-type", C2, "<CompressionType>RAR</CompressionType><CSV/>", "SELECT * FROM s3object")

SELGEN = os.environ.get("SELGEN")
if SELGEN:
    for ct in ("zstd", "lz4", "s2", "snappy"):
        for name, data, inp in (("csv", C2, "<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>"),
                                ("json", J1, "<JSON><Type>LINES</Type></JSON>")):
            comp = subprocess.run([SELGEN, ct], input=data, capture_output=True).stdout
            case(f"comp-{ct}-{name}", comp, f"<CompressionType>{ct.upper()}</CompressionType>{inp}",
                 "SELECT * FROM s3object")
        case(f"comp-{ct}-not", C2, f"<CompressionType>{ct.upper()}</CompressionType><CSV/>", "SELECT * FROM s3object")

# ---- Parquet (MINIO_API_SELECT_PARQUET=on) ----
PQ = "<CompressionType>NONE</CompressionType><Parquet/>"
HERE = os.path.dirname(os.path.abspath(__file__))
for f in ("testdata.parquet", "lineitem_shipdate.parquet"):
    data = open(os.path.join(HERE, "testdata", f), "rb").read()
    for i, q in enumerate(["SELECT * FROM S3Object", "SELECT COUNT(*) FROM S3Object",
                           "SELECT * FROM S3Object LIMIT 5", "SELECT DATE_ADD(day, 2, shipdate) as shipdate FROM S3Object LIMIT 5"]):
        case(f"pq-{f}-{i}", data, PQ, q)
        case(f"pq-{f}-csv-{i}", data, PQ, q, out=OUT_CSV)
case("pq-range", open(os.path.join(HERE, "testdata", "testdata.parquet"), "rb").read(), PQ, "SELECT * FROM S3Object",
     extra="<ScanRange><Start>0</Start><End>10</End></ScanRange>")
case("pq-garbage", b"not a parquet file at all", PQ, "SELECT * FROM S3Object")
if SELGEN:
    for codec in ("none", "snappy", "gzip", "zstd"):
        for pv in ("v1", "v2"):
            data = subprocess.run([SELGEN, "parquet", codec, pv, "10000"], capture_output=True).stdout
            case(f"pqgen-{codec}-{pv}", data, PQ, "SELECT * FROM S3Object s WHERE s.id % 997 < 3")
            case(f"pqgen-{codec}-{pv}-csv", data, PQ, "SELECT s.id, s.name, s.\"day\", s.ts_ms, s.ts_us, s.ts_ns, "
                 "s.ts_local, s.score, s.ratio, s.flag, s.small, s.code, s.legacy FROM S3Object s WHERE s.id < 12", out=OUT_CSV)
            case(f"pqgen-{codec}-{pv}-agg", data, PQ, "SELECT COUNT(*), SUM(s.score), MAX(s.small), MIN(s.ts_ns), "
                 "COUNT(s.name), AVG(s.small), MAX(s.\"day\") FROM S3Object s")
    data = subprocess.run([SELGEN, "parquet", "snappy", "v1", "50"], capture_output=True).stdout
    case("pqgen-where", data, PQ, "SELECT s.id, s.name FROM S3Object s WHERE s.name LIKE 'name-1%' AND s.flag")
    case("pqgen-dates", data, PQ, 'SELECT s.id, EXTRACT(YEAR FROM s."day"), DATE_DIFF(DAY, s."day", s.ts_ms) FROM S3Object s LIMIT 7')
    case("pqgen-path", data, PQ, "SELECT * FROM S3Object[*].id")
    # MinIO fails on a repeated column used in an expression ("Unhandled value type: []int64") or written as CSV
    case("dev-pq-repeated-csv", data, PQ, "SELECT s.id, s.tags FROM S3Object s WHERE s.id < 2", out=OUT_CSV,
         buckets=("ok", '0,\n1,"[1,2]"\n', (("Stats",), ("End",))))
    case("dev-pq-repeated", data, PQ, "SELECT s.tags FROM S3Object s WHERE 2 IN s.tags",
         buckets=("ok", '{"tags":[1,2]}\n{"tags":[2,4]}\n', (("Stats",), ("End",))))

# ---- big inputs: many blocks and Records messages ----
rnd = random.Random(7)
BIG = b"id,name,score,when\n" + b"".join(
    f"{i},name {rnd.randrange(1000)},{rnd.random() * 1000:.3f},2020-0{1 + i % 9}-1{i % 9}T\n".encode() for i in range(120000))
case("big-count", BIG, CSV_USE, "SELECT COUNT(*), SUM(score), MIN(id), MAX(name) FROM s3object")
case("big-all", BIG, CSV_USE, "SELECT * FROM s3object", out=OUT_CSV)
case("big-json", BIG, CSV_USE, "SELECT id, score FROM s3object WHERE CAST(score AS FLOAT) > 900")
case("big-gzip", gzip.compress(BIG), "<CompressionType>GZIP</CompressionType><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>",
     "SELECT COUNT(*) FROM s3object WHERE name LIKE '%99%'")
case("big-range", BIG, CSV_NONE, "SELECT * FROM s3object", extra="<ScanRange><Start>1000000</Start><End>1400000</End></ScanRange>")
BIGJ = b"".join(f'{{"id":{i},"tags":["t{i % 7}","x"],"n":{{"v":{i * 3}}}}}\n'.encode() for i in range(60000))
case("bigj-lines", BIGJ, JSON_LINES, "SELECT s.id, s.n.v FROM s3object s WHERE 't3' IN s.tags[*]")
case("bigj-doc", BIGJ, JSON_DOC, "SELECT COUNT(*) FROM s3object s")
case("big-record", b"a\n" + b"x" * (1 << 20) + b"\n", CSV_USE, "SELECT * FROM s3object")

# ---- objects stored encrypted or compressed ----
case("sse-s3", C2, CSV_USE, "SELECT * FROM s3object", put=("X-Amz-Server-Side-Encryption: AES256",))
case("sse-s3-big", BIG, CSV_USE, "SELECT COUNT(*) FROM s3object WHERE id > 5",
     put=("X-Amz-Server-Side-Encryption: AES256",))
case("stored-compressed", BIG, CSV_USE, "SELECT COUNT(*), MAX(score) FROM s3object", suffix=".csv")
case("stored-compressed-range", BIG, CSV_NONE, "SELECT * FROM s3object", suffix=".csv",
     extra="<ScanRange><Start>2000000</Start><End>2100000</End></ScanRange>")
case("stored-both", BIG, CSV_USE, "SELECT COUNT(*) FROM s3object", suffix=".csv",
     put=("X-Amz-Server-Side-Encryption: AES256",))

# ---- JSON input edges ----
case("json-scalars", b'1 "two" [3] true null {"a":{"b":[1,{"c":2}]}}', JSON_DOC, "SELECT * FROM s3object")
case("json-scalars-csv", b'1 "two" true null', JSON_DOC, "SELECT * FROM s3object", out=OUT_CSV)
case("json-escapes", b'{"s":"a\\"b\\\\c\\n\\u00e9\\ud83d\\ude00<&>\'"}', JSON_LINES, "SELECT * FROM s3object", simd=True)
case("json-bad", b'{"a":1}\n{"a":', JSON_LINES, "SELECT * FROM s3object", simd=True)
case("json-bad-doc", b'{"a":1}\n{"a":', JSON_DOC, "SELECT * FROM s3object")
case("json-dup-keys", b'{"a":1,"a":2}', JSON_LINES, "SELECT s.a FROM s3object s")
case("json-nested-out", b'{"a":{"b":1,"c":[1,2,{"d":null}]}}', JSON_LINES, "SELECT s.a, s.a.c, s.a.c[2] FROM s3object s")
case("json-nested-csv", b'{"a":{"b":1,"c":[1,2,{"d":null}]}}', JSON_LINES, "SELECT s.a.c, s.a.b FROM s3object s", out=OUT_CSV)
case("json-where-str", J1, JSON_LINES, "SELECT s.title FROM s3object s WHERE s.title LIKE 'Sec%' LIMIT 1")
case("json-bool", b'{"a":true,"b":"true"}', JSON_LINES, "SELECT s.a = true, s.b = 'true', NOT s.a FROM s3object s")
case("json-null-cmp", b'{"a":null}', JSON_LINES, "SELECT s.a IS NULL, s.b IS MISSING, s.b IS NULL, s.a = NULL FROM s3object s")
case("json-array-idx", b'{"a":[10,20,30]}', JSON_LINES, "SELECT s.a[0], s.a[5], s.a[*] FROM s3object s")
case("json-coalesce", b'{"a":null,"b":2}', JSON_LINES, "SELECT COALESCE(s.a, s.b) AS c FROM s3object s")
case("json-agg-strings", b'{"a":"1"}\n{"a":"2"}', JSON_LINES, "SELECT SUM(s.a) FROM s3object s")
case("json-lines-output-delim", J1, JSON_LINES, "SELECT s.id FROM s3object s",
     out="<JSON><RecordDelimiter>;</RecordDelimiter></JSON>")

# ---- request errors ----
case("err-parse", C2, CSV_USE, "SELEC * FROM s3object")
case("err-table", C2, CSV_USE, "SELECT * FROM mytable")
case("err-table-path", C2, CSV_USE, "SELECT * FROM s3object.a")
case("err-limit", C2, CSV_USE, "SELECT * FROM s3object LIMIT 1.5")
case("err-nested-agg", C2, CSV_USE, "SELECT COUNT(*), id FROM s3object")
case("err-where-agg", C2, CSV_USE, "SELECT id FROM s3object WHERE COUNT(*) > 1")
case("err-keypath", J1, JSON_LINES, "SELECT x.a.b FROM s3object s")
case("err-sum-args", C2, CSV_USE, "SELECT SUM(id, id) FROM s3object")
case("err-nullif-args", C2, CSV_USE, "SELECT NULLIF(id) FROM s3object")
case("err-utcnow-args", C2, CSV_USE, "SELECT UTCNOW(1) FROM s3object")
case("err-decimal", C2, CSV_USE, "SELECT CAST(id AS DECIMAL) FROM s3object")
case("err-lex", C2, CSV_USE, "SELECT id FROM s3object WHERE id ; 1")
case("err-json-type", J1, "<JSON><Type>XML</Type></JSON>", "SELECT * FROM s3object")
case("err-json-no-type", J1, "<JSON></JSON>", "SELECT * FROM s3object")
case("err-two-formats", J1, "<JSON><Type>LINES</Type></JSON><CSV/>", "SELECT * FROM s3object")
case("err-no-format", J1, "<CompressionType>NONE</CompressionType>", "SELECT * FROM s3object")
case("err-two-outputs", J1, JSON_LINES, "SELECT * FROM s3object", out="<CSV/><JSON/>")
case("err-no-output-format", J1, JSON_LINES, "SELECT * FROM s3object", out="")
case("err-csv-option", J1, "<CSV><Nope>1</Nope></CSV>", "SELECT * FROM s3object")
case("err-header-info", J1, "<CSV><FileHeaderInfo>MAYBE</FileHeaderInfo></CSV>", "SELECT * FROM s3object")
case("err-quote-char", J1, "<CSV><QuoteCharacter>ab</QuoteCharacter></CSV>", "SELECT * FROM s3object")
case("err-parquet-comp", J1, "<CompressionType>GZIP</CompressionType><Parquet/>", "SELECT * FROM s3object")
case("err-parquet-off", J1, "<Parquet/>", "SELECT * FROM s3object")
case("err-expr-type", J1, JSON_LINES, "", xml=b'<SelectRequest><Expression>SELECT * FROM s3object</Expression>'
     b'<ExpressionType>JS</ExpressionType><InputSerialization><JSON><Type>LINES</Type></JSON></InputSerialization>'
     b'<OutputSerialization><JSON/></OutputSerialization></SelectRequest>')
case("err-no-input", J1, JSON_LINES, "", xml=b'<SelectRequest><Expression>SELECT * FROM s3object</Expression>'
     b'<ExpressionType>SQL</ExpressionType><OutputSerialization><JSON/></OutputSerialization></SelectRequest>')
case("err-root", J1, JSON_LINES, "", xml=b'<Other><Expression>SELECT * FROM s3object</Expression></Other>')
case("err-progress", J1, JSON_LINES, "", xml=b'<SelectRequest><Expression>SELECT * FROM s3object</Expression>'
     b'<ExpressionType>SQL</ExpressionType><InputSerialization><JSON><Type>LINES</Type></JSON></InputSerialization>'
     b'<OutputSerialization><JSON/></OutputSerialization><RequestProgress><Enabled>maybe</Enabled></RequestProgress>'
     b'</SelectRequest>')
case("ok-legacy-root", J1, JSON_LINES, "", xml=b'<SelectObjectContentRequest><Expression>SELECT s.id FROM s3object s'
     b'</Expression><ExpressionType>sql</ExpressionType><InputSerialization><JSON><Type>lines</Type></JSON>'
     b'</InputSerialization><OutputSerialization><JSON/></OutputSerialization></SelectObjectContentRequest>')

# ---- evaluation errors (error events) ----
case("ev-where-not-bool", C2, CSV_USE, "SELECT id FROM s3object WHERE num")
case("ev-arith-string", C2, CSV_USE, "SELECT text + 1 FROM s3object")
case("ev-sum-string", C2, CSV_USE, "SELECT SUM(text) FROM s3object")
case("ev-bad-time", C2, CSV_USE, "SELECT CAST(text AS TIMESTAMP) FROM s3object")
case("ev-index-on-object", UA, JSON_LINES, "SELECT s.request[0] FROM s3object s")

# ---- deliberate differences (MinIO's behaviour in the comment) ----
# MinIO rejects <> at evaluation ("invalid arithmetic operator")
case("dev-ne", C2, CSV_USE, "SELECT id FROM s3object WHERE id <> 1",
     buckets=("ok", '{"id":"2"}\n', (("Stats",), ("End",))))
# MinIO's NULLIF always returns its first argument
case("dev-nullif", C2, CSV_USE, "SELECT NULLIF(id, 1) AS x FROM s3object",
     buckets=("ok", '{"x":null}\n{"x":"2"}\n', (("Stats",), ("End",))))
# MinIO's LIKE matches the first occurrence greedily
case("dev-like", b"a\nabXabY\n", CSV_USE, "SELECT a FROM s3object WHERE a LIKE '%ab_'",
     buckets=("ok", '{"a":"abXabY"}\n', (("Stats",), ("End",))))
# MinIO ignores ESCAPE
case("dev-like-escape", b"a\n5%\n5x\n", CSV_USE, "SELECT a FROM s3object WHERE a LIKE '5!%' ESCAPE '!'",
     buckets=("ok", '{"a":"5%"}\n', (("Stats",), ("End",))))
case("json-missing-nested", UA, JSON_LINES, "SELECT s.nope.deeper AS x FROM s3object s")
case("json-key-under-scalar", UA, JSON_LINES, "SELECT s.request.uri.x AS x FROM s3object s")
# MinIO does not implement TO_STRING and TO_TIMESTAMP
case("dev-to-timestamp", b"t\n2010-05-06T07:08Z\n", CSV_USE,
     "SELECT TO_STRING(TO_TIMESTAMP(t), 'yyyy/MM/dd HH:mm X') AS x FROM s3object",
     buckets=("ok", '{"x":"2010/05/06 07:08 Z"}\n', (("Stats",), ("End",))))
# MinIO's JSON reader doubles an exponent's first digit after its sign (1e-7 reads as 1e-77)
case("dev-exponent", b'{"d": 1e-7, "e": 2E+3}\n', JSON_LINES, "SELECT * FROM s3object",
     buckets=("ok", '{"d":1e-7,"e":2000}\n', (("Stats",), ("End",))))
# MinIO cannot cast a timestamp to a string
case("dev-cast-ts-string", b"t\n2010-05-06T07:08Z\n", CSV_USE, "SELECT CAST(CAST(t AS TIMESTAMP) AS STRING) AS x FROM s3object",
     buckets=("ok", '{"x":"2010-05-06T07:08Z"}\n', (("Stats",), ("End",))))
# MinIO fails selecting from an empty object
case("dev-empty", b"", CSV_USE, "SELECT * FROM s3object", buckets=("ok", "", (("Stats",), ("End",))))


def main():
    for base in (MINIO, BUCKETS):
        curl(f"{base}/{BUCKET}", "PUT")
    passed = failed = 0
    for i, c in enumerate(CASES):
        if FILTER and FILTER not in c["name"]:
            continue
        key = f"obj{i}{c['suffix']}"
        body = c["xml"] or request(c["query"], c["inp"], c["out"], c["extra"])
        res = []
        for base in (MINIO, BUCKETS):
            code, _ = curl(f"{base}/{BUCKET}/{key}", "PUT", c["data"], c["put"])
            assert code == 200, (base, code)
            code, out = curl(f"{base}/{BUCKET}/{key}?select&select-type=2", "POST", body)
            res.append(summarize(code, out, stats="LIMIT" not in c["query"].upper() and c["buckets"] is None))
        want = res[0]
        if c["buckets"] is not None:
            want = c["buckets"]
            if res[0] == want:
                print(f"  note  {c['name']}: MinIO now agrees with Buckets' answer")
        if res[1] == want:
            passed += 1
        elif c["simd"] and minio_uses_simdjson():
            passed += 1
            print(f"  note  {c['name']}: MinIO read it with simdjson (this CPU), and answers differently")
        else:
            failed += 1
            print(f"  FAIL  {c['name']}\n        query:   {c['query']}\n        minio:   {res[0]!r}\n        buckets: {res[1]!r}")
            if c["buckets"] is not None:
                print(f"        want:    {want!r}")
    print(f"select: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


main()
