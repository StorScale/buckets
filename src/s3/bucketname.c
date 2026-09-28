/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/bucketname.h"

#include <string.h>

static bool is_alnum(char c, bool strict) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (!strict && c >= 'A' && c <= 'Z');
}

static bool looks_like_ipv4(const char *s) {
  int dots = 0, digits = 0;
  for (; *s; s++) {
    if (*s == '.') {
      if (digits == 0) return false;
      dots++;
      digits = 0;
    } else if (*s >= '0' && *s <= '9') {
      digits++;
    } else {
      return false;
    }
  }
  return dots == 3 && digits > 0;
}

static bool check(const char *name, bool strict) {
  size_t n = strlen(name);
  if (n < 3 || n > 63) return false;
  if (looks_like_ipv4(name)) return false;
  if (strstr(name, "..") || strstr(name, ".-") || strstr(name, "-.")) return false;
  if (!is_alnum(name[0], strict) || !is_alnum(name[n - 1], strict)) return false;
  for (size_t i = 1; i + 1 < n; i++) {
    char c = name[i];
    if (is_alnum(c, strict) || c == '.' || c == '-') continue;
    if (!strict && (c == '_' || c == ':')) continue;
    return false;
  }
  return true;
}

bool buckets_bucket_name_valid_strict(const char *name) { return check(name, true); }

bool buckets_bucket_name_valid(const char *name) { return check(name, false); }

bool buckets_bucket_name_reserved(const char *name) {
  return strcmp(name, ".minio.sys") == 0 || strcmp(name, "minio") == 0;
}
