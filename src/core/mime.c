/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Go's mime.TypeByExtension (the built-in table; system mime.types files are
 * not read) and net/http's DetectContentType. */
#include "core/mime.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const struct {
  const char *ext, *type;
} k_types[] = {
    {".ai", "application/postscript"},
    {".apk", "application/vnd.android.package-archive"},
    {".apng", "image/apng"},
    {".avif", "image/avif"},
    {".bin", "application/octet-stream"},
    {".bmp", "image/bmp"},
    {".com", "application/octet-stream"},
    {".css", "text/css; charset=utf-8"},
    {".csv", "text/csv; charset=utf-8"},
    {".doc", "application/msword"},
    {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".ehtml", "text/html; charset=utf-8"},
    {".eml", "message/rfc822"},
    {".eps", "application/postscript"},
    {".exe", "application/octet-stream"},
    {".flac", "audio/flac"},
    {".gif", "image/gif"},
    {".gz", "application/gzip"},
    {".htm", "text/html; charset=utf-8"},
    {".html", "text/html; charset=utf-8"},
    {".ico", "image/vnd.microsoft.icon"},
    {".ics", "text/calendar; charset=utf-8"},
    {".jfif", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".js", "text/javascript; charset=utf-8"},
    {".json", "application/json"},
    {".m4a", "audio/mp4"},
    {".mjs", "text/javascript; charset=utf-8"},
    {".mp3", "audio/mpeg"},
    {".mp4", "video/mp4"},
    {".oga", "audio/ogg"},
    {".ogg", "audio/ogg"},
    {".ogv", "video/ogg"},
    {".opus", "audio/ogg"},
    {".pdf", "application/pdf"},
    {".pjp", "image/jpeg"},
    {".pjpeg", "image/jpeg"},
    {".png", "image/png"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {".ps", "application/postscript"},
    {".rdf", "application/rdf+xml"},
    {".rtf", "application/rtf"},
    {".shtml", "text/html; charset=utf-8"},
    {".svg", "image/svg+xml"},
    {".text", "text/plain; charset=utf-8"},
    {".tif", "image/tiff"},
    {".tiff", "image/tiff"},
    {".txt", "text/plain; charset=utf-8"},
    {".vtt", "text/vtt; charset=utf-8"},
    {".wasm", "application/wasm"},
    {".wav", "audio/wav"},
    {".weba", "audio/webm"},
    {".webm", "video/webm"},
    {".webp", "image/webp"},
    {".xbl", "text/xml; charset=utf-8"},
    {".xbm", "image/x-xbitmap"},
    {".xht", "application/xhtml+xml"},
    {".xhtml", "application/xhtml+xml"},
    {".xls", "application/vnd.ms-excel"},
    {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".xml", "text/xml; charset=utf-8"},
    {".xsl", "text/xml; charset=utf-8"},
    {".zip", "application/zip"},
};

const char *buckets_mime_by_ext(const char *name) {
  /* filepath.Ext: from the last dot after the last slash */
  const char *slash = strrchr(name, '/'), *dot = strrchr(name, '.');
  if (!dot || (slash && dot < slash)) return "";
  for (size_t i = 0; i < sizeof(k_types) / sizeof(k_types[0]); i++)
    if (strcasecmp(dot, k_types[i].ext) == 0) return k_types[i].type;
  return "";
}

static int is_ws(uint8_t b) { return b == '\t' || b == '\n' || b == '\x0c' || b == '\r' || b == ' '; }

static int prefix(const uint8_t *d, size_t n, const char *sig, size_t sn) { return n >= sn && !memcmp(d, sig, sn); }

static int masked(const uint8_t *d, size_t n, const char *mask, const char *pat, size_t len) {
  if (n < len) return 0;
  for (size_t i = 0; i < len; i++)
    if ((d[i] & (uint8_t)mask[i]) != (uint8_t)pat[i]) return 0;
  return 1;
}

static int html_sig(const uint8_t *d, size_t n, const char *h) {
  size_t hl = strlen(h);
  if (n < hl + 1) return 0;
  for (size_t i = 0; i < hl; i++) {
    uint8_t b = (uint8_t)h[i], db = d[i];
    if (b >= 'A' && b <= 'Z') db &= 0xdf;
    if (b != db) return 0;
  }
  return d[hl] == ' ' || d[hl] == '>';
}

static int mp4_sig(const uint8_t *d, size_t n) {
  if (n < 12) return 0;
  uint32_t box = (uint32_t)d[0] << 24 | (uint32_t)d[1] << 16 | (uint32_t)d[2] << 8 | d[3];
  if (n < box || box % 4 || memcmp(d + 4, "ftyp", 4)) return 0;
  for (uint32_t st = 8; st < box; st += 4) {
    if (st == 12) continue;
    if (!memcmp(d + st, "mp4", 3)) return 1;
  }
  return 0;
}

#define EXACT(s, t) \
  if (prefix(d, n, s, sizeof(s) - 1)) return t
#define MASKED(m, p, t) \
  if (masked(d, n, m, p, sizeof(p) - 1)) return t

const char *buckets_mime_sniff(const void *data, size_t n) {
  const uint8_t *d = data;
  if (n > 512) n = 512;
  size_t ws = 0;
  while (ws < n && is_ws(d[ws])) ws++;
  static const char *const html[] = {"<!DOCTYPE HTML", "<HTML", "<HEAD", "<SCRIPT", "<IFRAME", "<H1", "<DIV",
                                     "<FONT", "<TABLE", "<A", "<STYLE", "<TITLE", "<B", "<BODY", "<BR", "<P", "<!--"};
  for (size_t i = 0; i < sizeof(html) / sizeof(html[0]); i++)
    if (html_sig(d + ws, n - ws, html[i])) return "text/html; charset=utf-8";
  if (masked(d + ws, n - ws, "\xFF\xFF\xFF\xFF\xFF", "<?xml", 5)) return "text/xml; charset=utf-8";
  EXACT("%PDF-", "application/pdf");
  EXACT("%!PS-Adobe-", "application/postscript");
  MASKED("\xFF\xFF\x00\x00", "\xFE\xFF\x00\x00", "text/plain; charset=utf-16be");
  MASKED("\xFF\xFF\x00\x00", "\xFF\xFE\x00\x00", "text/plain; charset=utf-16le");
  MASKED("\xFF\xFF\xFF\x00", "\xEF\xBB\xBF\x00", "text/plain; charset=utf-8");
  EXACT("\x00\x00\x01\x00", "image/x-icon");
  EXACT("\x00\x00\x02\x00", "image/x-icon");
  EXACT("BM", "image/bmp");
  EXACT("GIF87a", "image/gif");
  EXACT("GIF89a", "image/gif");
  MASKED("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF", "RIFF\x00\x00\x00\x00WEBPVP", "image/webp");
  EXACT("\x89PNG\x0D\x0A\x1A\x0A", "image/png");
  EXACT("\xFF\xD8\xFF", "image/jpeg");
  MASKED("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", "FORM\x00\x00\x00\x00AIFF", "audio/aiff");
  MASKED("\xFF\xFF\xFF", "ID3", "audio/mpeg");
  MASKED("\xFF\xFF\xFF\xFF\xFF", "OggS\x00", "application/ogg");
  MASKED("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "MThd\x00\x00\x00\x06", "audio/midi");
  MASKED("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", "RIFF\x00\x00\x00\x00AVI ", "video/avi");
  MASKED("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", "RIFF\x00\x00\x00\x00WAVE", "audio/wave");
  if (mp4_sig(d, n)) return "video/mp4";
  EXACT("\x1A\x45\xDF\xA3", "video/webm");
  if (n >= 36) {
    /* 34 bytes of anything (masked by zeros), then "LP" */
    if (d[34] == 'L' && d[35] == 'P') return "application/vnd.ms-fontobject";
  }
  EXACT("\x00\x01\x00\x00", "font/ttf");
  EXACT("OTTO", "font/otf");
  EXACT("ttcf", "font/collection");
  EXACT("wOFF", "font/woff");
  EXACT("wOF2", "font/woff2");
  EXACT("\x1F\x8B\x08", "application/x-gzip");
  EXACT("PK\x03\x04", "application/zip");
  EXACT("Rar!\x1A\x07\x00", "application/x-rar-compressed");
  EXACT("Rar!\x1A\x07\x01\x00", "application/x-rar-compressed");
  EXACT("\x00\x61\x73\x6D", "application/wasm");
  for (size_t i = ws; i < n; i++) {
    uint8_t b = d[i];
    if (b <= 0x08 || b == 0x0b || (b >= 0x0e && b <= 0x1a) || (b >= 0x1c && b <= 0x1f)) return "application/octet-stream";
  }
  return "text/plain; charset=utf-8";
}

/* ---- minio/pkg mimedb ---- */

typedef struct {
  const char *ext, *type;
} mimedb_ent;

static const mimedb_ent k_mimedb[] = {
#include "core/mimedb.inc"
};

static int mimedb_cmp(const void *key, const void *ent) { return strcmp(key, ((const mimedb_ent *)ent)->ext); }

const char *buckets_mimedb_type(const char *ext) {
  if (!ext || !*ext) return "application/octet-stream";
  if (*ext == '.') ext++;
  char low[64];
  size_t i = 0;
  for (; ext[i] && i + 1 < sizeof(low); i++) low[i] = (char)tolower((unsigned char)ext[i]);
  low[i] = '\0';
  const mimedb_ent *e = bsearch(low, k_mimedb, sizeof(k_mimedb) / sizeof(k_mimedb[0]), sizeof(k_mimedb[0]), mimedb_cmp);
  return e ? e->type : "application/octet-stream";
}
