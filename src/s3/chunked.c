/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/chunked.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "crypto/hex.h"
#include "crypto/sha256.h"

#define MAX_CHUNK (16 * 1024 * 1024) /* MinIO maxChunkSize */
#define MAX_LINE 4096                /* MinIO maxLineLength */
#define MAX_TRAILERS 8

struct buckets_chunked {
  buckets_http_body_cursor cur;
  bool signed_chunks;
  bool trailer;
  buckets_sigv4_result sig;
  char prev_sig[65];

  uint8_t in[64 * 1024]; /* raw body read-ahead */
  size_t in_pos, in_len;

  uint8_t *chunk; /* current verified chunk */
  size_t chunk_len, chunk_pos;
  bool done;
  buckets_s3_error err;

  char *tnames[MAX_TRAILERS];
  char *tvalues[MAX_TRAILERS];
  size_t ntrailers;
};

buckets_chunked *buckets_chunked_new(const buckets_http_request *req, buckets_str mode,
                                     const buckets_sigv4_result *sig) {
  bool signed_chunks, trailer;
  if (buckets_str_eq_c(mode, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")) {
    signed_chunks = true, trailer = false;
  } else if (buckets_str_eq_c(mode, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")) {
    signed_chunks = true, trailer = true;
  } else if (buckets_str_eq_c(mode, "STREAMING-UNSIGNED-PAYLOAD-TRAILER")) {
    signed_chunks = false, trailer = true;
  } else {
    return NULL;
  }
  if (signed_chunks && !sig) return NULL;
  buckets_chunked *ch = buckets_xcalloc(1, sizeof(*ch));
  ch->cur = (buckets_http_body_cursor){req, 0};
  ch->signed_chunks = signed_chunks;
  ch->trailer = trailer;
  if (sig) {
    ch->sig = *sig;
    memcpy(ch->prev_sig, sig->seed_signature, 65);
  }
  ch->chunk = buckets_xmalloc(MAX_CHUNK);
  return ch;
}

void buckets_chunked_free(buckets_chunked *ch) {
  if (!ch) return;
  for (size_t i = 0; i < ch->ntrailers; i++) {
    free(ch->tnames[i]);
    free(ch->tvalues[i]);
  }
  free(ch->chunk);
  free(ch);
}

buckets_s3_error buckets_chunked_error(const buckets_chunked *ch) { return ch->err; }

const char *buckets_chunked_trailer(const buckets_chunked *ch, const char *name) {
  for (size_t i = 0; i < ch->ntrailers; i++) {
    if (strcasecmp(ch->tnames[i], name) == 0) return ch->tvalues[i];
  }
  return NULL;
}

/* ---- raw input ------------------------------------------------------------ */

static int next_byte(buckets_chunked *ch) {
  if (ch->in_pos == ch->in_len) {
    long n = buckets_http_body_read(&ch->cur, ch->in, sizeof(ch->in));
    if (n <= 0) return -1;
    ch->in_len = (size_t)n;
    ch->in_pos = 0;
  }
  return ch->in[ch->in_pos++];
}

static bool read_exact(buckets_chunked *ch, uint8_t *dst, size_t n) {
  while (n) {
    if (ch->in_pos == ch->in_len) {
      long r = buckets_http_body_read(&ch->cur, ch->in, sizeof(ch->in));
      if (r <= 0) return false;
      ch->in_len = (size_t)r;
      ch->in_pos = 0;
    }
    size_t take = BUCKETS_MIN(n, ch->in_len - ch->in_pos);
    memcpy(dst, ch->in + ch->in_pos, take);
    ch->in_pos += take;
    dst += take;
    n -= take;
  }
  return true;
}

/* Reads a CRLF-terminated line (without the CRLF). */
static bool read_line(buckets_chunked *ch, char *line, size_t cap, size_t *len) {
  size_t n = 0;
  for (;;) {
    int c = next_byte(ch);
    if (c < 0) return false;
    if (c == '\r') {
      if (next_byte(ch) != '\n') return false;
      line[n] = '\0';
      *len = n;
      return true;
    }
    if (n + 1 >= cap) return false;
    line[n++] = (char)c;
  }
}

static bool fail(buckets_chunked *ch, buckets_s3_error e) {
  ch->err = e;
  return false;
}

/* ---- signatures ----------------------------------------------------------- */

static void sign(const buckets_chunked *ch, const char *kind, const char *hashes, char out[65]) {
  char sts[512];
  int n = snprintf(sts, sizeof(sts), "%s\n%s\n%s\n%s\n%s", kind, ch->sig.amz_date, ch->sig.scope, ch->prev_sig,
                   hashes);
  uint8_t mac[32];
  buckets_hmac_sha256(ch->sig.signing_key, 32, sts, (size_t)n, mac);
  buckets_hex_encode(mac, 32, out);
}

static bool verify_chunk(buckets_chunked *ch, const char *provided) {
  uint8_t sum[32];
  char hashes[140];
  char data_hex[65];
  buckets_sha256(ch->chunk, ch->chunk_len, sum);
  buckets_hex_encode(sum, 32, data_hex);
  snprintf(hashes, sizeof(hashes), "%s\n%s", BUCKETS_EMPTY_SHA256, data_hex);
  char want[65];
  sign(ch, "AWS4-HMAC-SHA256-PAYLOAD", hashes, want);
  if (strlen(provided) != 64 || !buckets_ct_equal(want, provided, 64)) {
    return fail(ch, BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH);
  }
  memcpy(ch->prev_sig, want, 65);
  return true;
}

static bool add_trailer(buckets_chunked *ch, const char *line) {
  const char *colon = strchr(line, ':');
  if (!colon || colon == line || ch->ntrailers == MAX_TRAILERS) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
  /* strings.TrimSpace: minio-go ends trailer lines with "\n\r\n". */
  const char *v = colon + 1;
  while (*v && isspace((unsigned char)*v)) v++;
  size_t vl = strlen(v);
  while (vl && isspace((unsigned char)v[vl - 1])) vl--;
  ch->tnames[ch->ntrailers] = buckets_xstrndup(line, (size_t)(colon - line));
  ch->tvalues[ch->ntrailers] = buckets_xstrndup(v, vl);
  ch->ntrailers++;
  return true;
}

static bool read_trailers(buckets_chunked *ch) {
  char line[MAX_LINE];
  size_t n;
  if (!ch->signed_chunks) {
    /* Unsigned: "k:v\r\n" lines until an empty line. */
    for (;;) {
      if (!read_line(ch, line, sizeof(line), &n)) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
      if (n == 0) return true;
      if (!add_trailer(ch, line)) return false;
    }
  }
  /* Signed: one trailer line, then its signature, then an empty line. */
  if (!read_line(ch, line, sizeof(line), &n) || n == 0) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
  char sigline[MAX_LINE];
  size_t sn;
  if (!read_line(ch, sigline, sizeof(sigline), &sn)) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
  size_t blank;
  char empty[4];
  if (!read_line(ch, empty, sizeof(empty), &blank) || blank != 0) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
  static const char prefix[] = "x-amz-trailer-signature:";
  if (strncmp(sigline, prefix, sizeof(prefix) - 1) != 0) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
  const char *provided = sigline + sizeof(prefix) - 1;
  while (*provided == ' ') provided++;

  char with_nl[MAX_LINE + 2];
  snprintf(with_nl, sizeof(with_nl), "%s\n", line);
  uint8_t sum[32];
  char hashes[65];
  buckets_sha256(with_nl, strlen(with_nl), sum);
  buckets_hex_encode(sum, 32, hashes);
  char want[65];
  sign(ch, "AWS4-HMAC-SHA256-TRAILER", hashes, want);
  if (strlen(provided) < 64 || !buckets_ct_equal(want, provided, 64)) {
    return fail(ch, BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH);
  }
  return add_trailer(ch, line);
}

/* Reads and verifies the next chunk into ch->chunk. Sets done at the final chunk. */
static bool next_chunk(buckets_chunked *ch) {
  char line[MAX_LINE];
  size_t n;
  if (!read_line(ch, line, sizeof(line), &n)) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
  size_t size = 0, i = 0;
  for (; i < n && line[i] != ';'; i++) {
    char c = line[i];
    int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
    if (d < 0) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
    size = size << 4 | (size_t)d;
    if (size > MAX_CHUNK) return fail(ch, BUCKETS_ERR_CHUNK_TOO_BIG);
  }
  if (i == 0) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
  const char *provided = NULL;
  if (ch->signed_chunks) {
    static const char key[] = ";chunk-signature=";
    if (strncmp(line + i, key, sizeof(key) - 1) != 0) return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
    provided = line + i + sizeof(key) - 1;
  }
  if (size && !read_exact(ch, ch->chunk, size)) return fail(ch, BUCKETS_ERR_INCOMPLETE_BODY);
  ch->chunk_len = size;
  ch->chunk_pos = 0;
  if (ch->signed_chunks && !verify_chunk(ch, provided)) return false;
  if (size == 0) {
    ch->done = true;
    return ch->trailer ? read_trailers(ch) : true;
  }
  if (next_byte(ch) != '\r' || next_byte(ch) != '\n') return fail(ch, BUCKETS_ERR_MALFORMED_CHUNKED_ENCODING);
  return true;
}

long buckets_chunked_read(void *ud, void *buf, size_t n) {
  buckets_chunked *ch = ud;
  if (ch->err) return -1;
  size_t out = 0;
  while (out < n) {
    if (ch->chunk_pos == ch->chunk_len) {
      if (ch->done) break;
      if (!next_chunk(ch)) return -1;
      continue;
    }
    size_t take = BUCKETS_MIN(n - out, ch->chunk_len - ch->chunk_pos);
    memcpy((uint8_t *)buf + out, ch->chunk + ch->chunk_pos, take);
    ch->chunk_pos += take;
    out += take;
  }
  return (long)out;
}
