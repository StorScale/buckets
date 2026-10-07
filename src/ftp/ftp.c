/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/tls.h"
#include "ftp/ftp.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/buf.h"
#include "core/common.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "ftp/s3fs.h"
#include "notify/event.h"
#include "trace/trace.h"

#define GOFTP_VERSION "2.0beta"
#define LICENSE "GNU AGPLv3 - https://www.gnu.org/licenses/agpl-3.0.html"

/* ---- options ---- */

static char *xdup(const char *s) { return s ? buckets_xstrdup(s) : NULL; }

/* net.SplitHostPort, for the errors Go gives */
bool buckets_ftp_split_host_port(const char *a, char **host, char **port, char *err, size_t errlen) {
  const char *colon = strrchr(a, ':');
  if (!colon) {
    snprintf(err, errlen, "address %s: missing port in address", a);
    return false;
  }
  if (a[0] == '[') {
    const char *end = strchr(a, ']');
    if (!end || end[1] != ':') {
      snprintf(err, errlen, "address %s: missing port in address", a);
      return false;
    }
    *host = buckets_xstrndup(a + 1, (size_t)(end - a - 1));
  } else {
    if (memchr(a, ':', (size_t)(colon - a))) {
      snprintf(err, errlen, "address %s: too many colons in address", a);
      return false;
    }
    *host = buckets_xstrndup(a, (size_t)(colon - a));
  }
  *port = buckets_xstrdup(colon + 1);
  return true;
}

bool buckets_ftp_atoi(const char *s, int *out) {
  char *end;
  errno = 0;
  long v = strtol(s, &end, 10);
  if (!*s || *end || errno || v < -2147483648L || v > 2147483647L) return false;
  *out = (int)v;
  return true;
}

bool buckets_ftp_parse_bool(const char *s, bool *out) {
  static const char *const t[] = {"1", "t", "T", "TRUE", "true", "True"};
  static const char *const f[] = {"0", "f", "F", "FALSE", "false", "False"};
  for (int i = 0; i < 6; i++) {
    if (!strcmp(s, t[i])) return *out = true, true;
    if (!strcmp(s, f[i])) return *out = false, true;
  }
  return false;
}

bool buckets_ftp_parse(char *const *args, size_t n, buckets_ftp_opts *o, char *err, size_t errlen) {
  memset(o, 0, sizeof(*o));
  for (size_t i = 0; i < n; i++) {
    const char *eq = strchr(args[i], '=');
    if (!eq) {
      snprintf(err, errlen, "invalid arguments passed to --ftp=%s", args[i]);
      return false;
    }
    char *key = buckets_xstrndup(args[i], (size_t)(eq - args[i]));
    const char *val = eq + 1;
    char e2[256];
    bool ok = true;
    if (!strcmp(key, "address")) {
      char *host = NULL, *port = NULL;
      if (!buckets_ftp_split_host_port(val, &host, &port, e2, sizeof(e2))) {
        snprintf(err, errlen, "invalid arguments passed to --ftp=%s (%s)", args[i], e2);
        ok = false;
      } else if (!buckets_ftp_atoi(port, &o->port)) {
        snprintf(err, errlen, "invalid arguments passed to --ftp=%s (strconv.Atoi: parsing \"%s\": invalid syntax)",
                 args[i], port);
        ok = false;
      } else if (o->port < 1 || o->port > 65535) {
        snprintf(err, errlen, "invalid arguments passed to --ftp=%s, (port number must be between 1 to 65535)",
                 args[i]);
        ok = false;
      } else {
        free(o->public_ip);
        o->public_ip = xdup(host);
      }
      free(host);
      free(port);
    } else if (!strcmp(key, "passive-port-range")) {
      free(o->port_range);
      o->port_range = xdup(val);
    } else if (!strcmp(key, "tls-private-key")) {
      free(o->key);
      o->key = xdup(val);
    } else if (!strcmp(key, "tls-public-cert")) {
      free(o->cert);
      o->cert = xdup(val);
    } else if (!strcmp(key, "force-tls")) {
      if (!buckets_ftp_parse_bool(val, &o->force_tls)) {
        snprintf(err, errlen, "invalid arguments passed to --ftp=%s (strconv.ParseBool: parsing \"%s\": invalid syntax)",
                 args[i], val);
        ok = false;
      }
    }
    free(key);
    if (!ok) return false;
  }
  bool k = o->key && *o->key, c = o->cert && *o->cert;
  if (!k && c) {
    snprintf(err, errlen, "invalid TLS arguments provided missing private key --ftp=\"tls-private-key=path/to/private.key\"");
    return false;
  }
  if (k && !c) {
    snprintf(err, errlen, "invalid TLS arguments provided missing public cert --ftp=\"tls-public-cert=path/to/public.crt\"");
    return false;
  }
  if (!o->port) o->port = 8021;
  return true;
}

/* ---- the server ---- */

typedef struct {
  buckets_ftp_opts o;
  SSL_CTX *tls; /* NULL: plain FTP only */
  char name[64];
  int lfd;
} ftp_server;

static ftp_server g_srv;

/* a connection: TCP, maybe TLS */
typedef struct {
  int fd;
  SSL *ssl;
} xconn;

static long xread(xconn *c, void *buf, size_t n) {
  if (c->ssl) {
    int r = SSL_read(c->ssl, buf, (int)BUCKETS_MIN(n, (size_t)1 << 30));
    return r > 0 ? r : (SSL_get_error(c->ssl, r) == SSL_ERROR_ZERO_RETURN ? 0 : -1);
  }
  ssize_t r;
  do r = recv(c->fd, buf, n, 0);
  while (r < 0 && errno == EINTR);
  return (long)r;
}

static bool xwrite(xconn *c, const void *buf, size_t n) {
  const char *p = buf;
  while (n) {
    long w;
    if (c->ssl) {
      int r = SSL_write(c->ssl, p, (int)BUCKETS_MIN(n, (size_t)1 << 30));
      w = r > 0 ? r : -1;
    } else {
#ifdef MSG_NOSIGNAL
      w = send(c->fd, p, n, MSG_NOSIGNAL);
#else
      w = send(c->fd, p, n, 0);
#endif
      if (w < 0 && errno == EINTR) continue;
    }
    if (w <= 0) return false;
    p += w, n -= (size_t)w;
  }
  return true;
}

static void xclose(xconn *c) {
  if (c->ssl) {
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
  }
  if (c->fd >= 0) close(c->fd);
  c->fd = -1;
  c->ssl = NULL;
}

/* the data connection of a session */
typedef enum { DATA_NONE, DATA_PASSIVE, DATA_ACTIVE } data_kind;

typedef struct {
  data_kind kind;
  int lfd;          /* passive: the listener until a client connects */
  time_t deadline;  /* passive: accept until then */
  int port;
  char host[64];
  xconn c;          /* the connection, fd -1 until there is one */
  bool failed;
  char err[128];
} data_sock;

typedef struct {
  xconn ctl;
  buckets_buf in;
  char remote_ip[64], local_ip[64];
  char cur_dir[4096];
  char *req_user, *user;
  char *rename_from;
  int64_t last_pos;
  char pre_cmd[16];
  bool closed, tls;
  data_sock data;
  bool have_data;
  buckets_fs *fs;
  /* the command being run, for traces */
  const char *cmd;
  const char *param;
} session;

static void reply(session *s, int code, const char *msg) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "%d %s\r\n", code, msg);
  xwrite(&s->ctl, b.data, b.len);
  buckets_buf_free(&b);
}

static void replyf(session *s, int code, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void replyf(session *s, int code, const char *fmt, ...) {
  char msg[8192];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  reply(s, code, msg);
}

/* ---- traces (ftpTrace) ---- */

typedef struct {
  const char *func; /* the driver method */
  int line;         /* MinIO's source line of its trace call */
} tsrc;

static const tsrc T_STAT = {"Stat", 144}, T_LIST = {"ListDir", 202}, T_PASS = {"CheckPasswd", 264},
                  T_RMDIR = {"DeleteDir", 394}, T_DELE = {"DeleteFile", 444}, T_RENAME = {"Rename", 462},
                  T_MKDIR = {"MakeDir", 470}, T_GET = {"GetFile", 497}, T_PUT = {"PutFile", 536};

static int64_t wall_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void ftp_trace(session *s, tsrc src, int64_t start, const char *path, const char *err, int64_t bytes) {
  if (!buckets_trace_wanted(BUCKETS_TRACE_FTP)) return;
  int64_t dur = wall_ns() - start;
  char when[64], source[128];
  buckets_time_rfc3339_nano(start / 1000000000LL, (long)(start % 1000000000LL), when);
  snprintf(source, sizeof(source), "[ftp-server-driver.go:%d:(*ftpDriver).%s()]", src.line, src.func);
  buckets_buf j = BUCKETS_BUF_INIT;
  const char *node = buckets_trace_node();
  buckets_buf_appendf(&j, "{\"type\":%u,\"nodename\":", (unsigned)BUCKETS_TRACE_FTP);
  buckets_json_go_string(&j, node, strlen(node));
  buckets_buf_append_c(&j, ",\"funcname\":");
  buckets_json_go_string(&j, s->cmd, strlen(s->cmd));
  buckets_buf_appendf(&j, ",\"time\":\"%s\",\"path\":", when);
  buckets_json_go_string(&j, path, strlen(path));
  buckets_buf_appendf(&j, ",\"dur\":%lld", (long long)dur);
  if (bytes) buckets_buf_appendf(&j, ",\"bytes\":%lld", (long long)bytes);
  if (err && *err) {
    buckets_buf_append_c(&j, ",\"error\":");
    buckets_json_go_string(&j, err, strlen(err));
  }
  const char *user = s->user ? s->user : "";
  buckets_buf_append_c(&j, ",\"custom\":{\"cmd\":");
  buckets_json_go_string(&j, s->cmd, strlen(s->cmd));
  buckets_buf_appendf(&j, ",\"login\":\"%s\",\"param\":", s->user ? "true" : "false");
  buckets_json_go_string(&j, s->param, strlen(s->param));
  buckets_buf_append_c(&j, ",\"source\":");
  buckets_json_go_string(&j, source, strlen(source));
  buckets_buf_append_c(&j, ",\"user\":");
  buckets_json_go_string(&j, user, strlen(user));
  buckets_buf_append_c(&j, "}}");
  buckets_trace_meta m = {.type = BUCKETS_TRACE_FTP, .dur_ns = dur};
  buckets_trace_publish(&m, j.data, j.len);
  buckets_buf_free(&j);
}

/* ---- the driver calls, traced ---- */

static bool fs_ready(session *s, char *err, size_t errlen) {
  if (s->fs) return true;
  s->fs = buckets_fs_open(s->user, s->remote_ip, err, errlen);
  return s->fs != NULL;
}

static bool d_stat(session *s, const char *path, buckets_fs_info *fi, char *err, size_t errlen) {
  int64_t t0 = wall_ns();
  memset(fi, 0, sizeof(*fi));
  bool ok;
  if (!strcmp(path, "/")) { /* answered before any client is made */
    fi->name = buckets_xstrdup("/");
    fi->dir = ok = true;
  } else {
    ok = fs_ready(s, err, errlen) && buckets_fs_stat(s->fs, path, fi, err, errlen);
  }
  ftp_trace(s, T_STAT, t0, path, ok ? NULL : err, 0);
  return ok;
}

static bool d_list(session *s, const char *path, buckets_fs_info **v, size_t *n, char *err, size_t errlen) {
  int64_t t0 = wall_ns();
  *v = NULL, *n = 0;
  bool ok = fs_ready(s, err, errlen) && buckets_fs_list(s->fs, path, v, n, err, errlen);
  ftp_trace(s, T_LIST, t0, path, ok ? NULL : err, 0);
  return ok;
}

/* ---- data connections ---- */

static void data_close(session *s) {
  if (!s->have_data) return;
  if (s->data.lfd >= 0) close(s->data.lfd);
  xclose(&s->data.c);
  s->have_data = false;
}

static int rand_below(int n) {
  unsigned int r = 0;
  RAND_bytes((unsigned char *)&r, sizeof(r));
  return n > 0 ? (int)(r % (unsigned)n) : 0;
}

/* PassivePort: a random port of the range, or 0 */
static int passive_port(void) {
  const char *pr = g_srv.o.port_range;
  if (!pr || !*pr) return 0;
  const char *dash = strchr(pr, '-');
  if (!dash || strchr(dash + 1, '-')) return 0;
  int lo = atoi(pr), hi = atoi(dash + 1);
  return lo + rand_below(hi - lo);
}

static const char *passive_ip(session *s) {
  static __thread char ip[64];
  snprintf(ip, sizeof(ip), "%s", g_srv.o.public_ip && *g_srv.o.public_ip ? g_srv.o.public_ip : s->local_ip);
  if (!strcmp(ip, "::1")) return ip;
  char *last = strrchr(ip, ':');
  if (last && last != ip) *last = '\0';
  return ip;
}

static bool passive_open(session *s) {
  data_close(s);
  memset(&s->data, 0, sizeof(s->data));
  s->data.kind = DATA_PASSIVE;
  s->data.lfd = -1;
  s->data.c.fd = -1;
  s->have_data = true; /* sess.dataConn is set even when the listen failed */
  snprintf(s->data.host, sizeof(s->data.host), "%s", passive_ip(s));
  for (int i = 1; i <= 10; i++) {
    int port = passive_port();
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    bool v6 = fd >= 0;
    if (!v6) fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    int one = 1, zero = 0;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int rc;
    if (v6) {
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
      struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((uint16_t)port), .sin6_addr = in6addr_any};
      rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
    } else {
      struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port), .sin_addr.s_addr = INADDR_ANY};
      rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
    }
    if (rc != 0 || listen(fd, 1) != 0) {
      int e = errno;
      close(fd);
      if (port && e == EADDRINUSE) continue;
      return false;
    }
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    getsockname(fd, (struct sockaddr *)&ss, &sl);
    s->data.port = ntohs(ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                                                   : ((struct sockaddr_in *)&ss)->sin_port);
    s->data.lfd = fd;
    s->data.deadline = time(NULL) + 60;
    return true;
  }
  return false;
}

static bool active_open(session *s, const char *host, int port) {
  char ps[16];
  snprintf(ps, sizeof(ps), "%d", port);
  struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res = NULL;
  if (getaddrinfo(host, ps, &hints, &res) != 0) return false;
  int fd = -1;
  for (struct addrinfo *a = res; a && fd < 0; a = a->ai_next) {
    fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
    if (fd >= 0 && connect(fd, a->ai_addr, a->ai_addrlen) != 0) close(fd), fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return false;
  data_close(s);
  memset(&s->data, 0, sizeof(s->data));
  s->data.kind = DATA_ACTIVE;
  s->data.lfd = -1;
  s->data.c.fd = fd; /* newActiveSocket: plain TCP, even under TLS */
  s->data.port = port;
  snprintf(s->data.host, sizeof(s->data.host), "%s", host);
  s->have_data = true;
  return true;
}

/* The connection a transfer uses: a passive client is accepted now (within
 * the listener's minute), over TLS when the server has a certificate. */
static xconn *data_conn(session *s) {
  data_sock *d = &s->data;
  if (d->c.fd >= 0) return &d->c;
  if (d->failed || d->lfd < 0) return NULL;
  int left = (int)(d->deadline - time(NULL));
  struct pollfd p = {d->lfd, POLLIN, 0};
  int fd = -1;
  if (left > 0 && poll(&p, 1, left * 1000) == 1) fd = accept(d->lfd, NULL, NULL);
  close(d->lfd);
  d->lfd = -1;
  if (fd < 0) {
    d->failed = true;
    snprintf(d->err, sizeof(d->err), "accept tcp [::]:%d: i/o timeout", d->port);
    return NULL;
  }
  d->c.fd = fd;
  if (g_srv.tls) {
    d->c.ssl = SSL_new(g_srv.tls);
    SSL_set_fd(d->c.ssl, fd);
    if (SSL_accept(d->c.ssl) != 1) {
      xclose(&d->c);
      d->failed = true;
      snprintf(d->err, sizeof(d->err), "tls: handshake failure");
      return NULL;
    }
  }
  return &d->c;
}

/* sendOutofbandData */
static void send_oob(session *s, const buckets_buf *b) {
  if (s->have_data) {
    xconn *c = data_conn(s);
    if (c) xwrite(c, b->data, b->len);
    data_close(s);
  }
  replyf(s, 226, "Closing data connection, sent %zu bytes", b->len);
}

/* ---- paths ---- */

/* buildPath */
static char *build_path(session *s, const char *name) {
  buckets_buf p = BUCKETS_BUF_INIT;
  if (*name == '/') buckets_buf_append_c(&p, name);
  else if (*name && strcmp(name, "-a") != 0) buckets_buf_appendf(&p, "%s/%s", s->cur_dir, name);
  else buckets_buf_append_c(&p, s->cur_dir);
  char *c = buckets_fs_clean(p.data);
  buckets_buf_free(&p);
  if (!*c) {
    free(c);
    c = buckets_xstrdup(".");
  }
  return c;
}

/* parseListParam: the path after any -flags */
static const char *list_param(const char *param) {
  if (!*param) return param;
  size_t i = 0;
  const char *p = param;
  while (*p) {
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '-') break;
    const char *f = p;
    while (*p && *p != ' ' && *p != '\t') p++;
    /* strings.LastIndex(param, " "+field) + len(field) + 1 */
    size_t flen = (size_t)(p - f);
    char *needle = buckets_xcalloc(flen + 2, 1);
    needle[0] = ' ';
    memcpy(needle + 1, f, flen);
    const char *last = NULL;
    for (const char *q = param; (q = strstr(q, needle)); q++) last = q;
    i = last ? (size_t)(last - param) + flen + 1 : flen; /* LastIndex -1 + len + 1 */
    if (!last) i = flen;
    free(needle);
  }
  const char *r = param + i;
  while (*r == ' ') r++;
  return r;
}

/* ---- listings ---- */

static int64_t mod_time(const buckets_fs_info *f) {
  return f->mtime_ns ? f->mtime_ns : 315532800LL * 1000000000LL; /* minFileDate */
}

static void fmt_time(int64_t ns, const char *layout, char *out, size_t cap) {
  time_t t = (time_t)(ns / 1000000000LL);
  struct tm tm;
  gmtime_r(&t, &tm);
  strftime(out, cap, layout, &tm);
}

/* listFormatter.Detailed */
static void detailed(buckets_buf *b, const buckets_fs_info *v, size_t n) {
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  tm.tm_year -= 1;
  time_t year_ago = timegm(&tm);
  static const char *const mon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  for (size_t i = 0; i < n; i++) {
    buckets_buf_append_c(b, v[i].dir ? "drwxrwxrwx" : "-rwxrwxrwx");
    buckets_buf_append_c(b, " 1 nobody nobody ");
    char sz[32];
    snprintf(sz, sizeof(sz), "%lld", (long long)v[i].size);
    size_t l = strlen(sz);
    if (l < 12) buckets_buf_appendf(b, "%*s", 12, sz);
    else buckets_buf_append(b, sz, 12);
    int64_t mt = mod_time(&v[i]);
    time_t t = (time_t)(mt / 1000000000LL);
    struct tm m;
    gmtime_r(&t, &m);
    if (t < year_ago) buckets_buf_appendf(b, " %s %2d  %d ", mon[m.tm_mon], m.tm_mday, m.tm_year + 1900);
    else buckets_buf_appendf(b, " %s %2d %02d:%02d ", mon[m.tm_mon], m.tm_mday, m.tm_hour, m.tm_min);
    buckets_buf_appendf(b, "%s\r\n", v[i].name);
  }
}

/* list(): the entries of a directory, or the one file */
static bool list_entries(session *s, const char *p, buckets_fs_info **v, size_t *n, char *err, size_t errlen) {
  buckets_fs_info fi;
  if (!d_stat(s, p, &fi, err, errlen)) return false;
  bool ok = true;
  if (fi.dir) {
    ok = d_list(s, p, v, n, err, errlen);
    free(fi.name);
  } else {
    *v = buckets_xcalloc(1, sizeof(**v));
    **v = fi;
    *n = 1;
  }
  return ok;
}

/* ---- commands ---- */

typedef struct {
  const char *name;
  bool need_param, need_auth, extend;
  void (*run)(session *s, const char *param);
} command;

static void c_allo(session *s, const char *p) { (void)p, reply(s, 202, "Obsolete"); }
static void c_not_taken(session *s, const char *p) { (void)p, reply(s, 550, "Action not taken"); }
static void c_clnt(session *s, const char *p) { (void)p, reply(s, 200, "OK"); }
static void c_noop(session *s, const char *p) { (void)p, reply(s, 200, "OK"); }
static void c_syst(session *s, const char *p) { (void)p, reply(s, 215, "UNIX Type: L8"); }

static void c_opts(session *s, const char *p) {
  char a[64] = "", b[64] = "", extra[8] = "";
  int k = sscanf(p, "%63s %63s %7s", a, b, extra);
  if (k != 2 || strcasecmp(a, "UTF8") != 0) {
    reply(s, 550, "Unknow params");
    return;
  }
  if (!strcasecmp(b, "ON")) reply(s, 200, "UTF8 mode enabled");
  else reply(s, 550, "Unsupported non-utf8 mode");
}

static void c_feat(session *s, const char *p) {
  (void)p;
  buckets_buf b = BUCKETS_BUF_INIT;
  /* goftp walks a map: the order is Go's random map order; ours is sorted */
  buckets_buf_append_c(&b, "211-Extensions supported:\n UTF8\n CLNT\n EPRT\n EPSV\n LPRT\n MLSD\n");
  if (g_srv.tls) buckets_buf_append_c(&b, " AUTH TLS\n PBSZ\n PROT\n");
  buckets_buf_append_c(&b, "\r\n211 END\r\n");
  xwrite(&s->ctl, b.data, b.len);
  buckets_buf_free(&b);
}

static void c_cwd(session *s, const char *param) {
  char *path = build_path(s, param), err[1024];
  buckets_fs_info fi;
  if (!d_stat(s, path, &fi, err, sizeof(err))) {
    replyf(s, 550, "Directory change to %s failed.", path);
  } else if (!fi.dir) {
    replyf(s, 550, "Directory change to %s is a file", path);
    free(fi.name);
  } else {
    snprintf(s->cur_dir, sizeof(s->cur_dir), "%s", path);
    replyf(s, 250, "Directory changed to %s", path);
    free(fi.name);
  }
  free(path);
}

static void c_cdup(session *s, const char *p) { (void)p, c_cwd(s, ".."); }

static void c_dele(session *s, const char *param) {
  char *path = build_path(s, param), err[1024];
  int64_t t0 = wall_ns();
  bool ok = fs_ready(s, err, sizeof(err)) && buckets_fs_delete(s->fs, path, err, sizeof(err));
  ftp_trace(s, T_DELE, t0, path, ok ? NULL : err, 0);
  if (ok) reply(s, 250, "File deleted");
  else reply(s, 550, "File delete failed. ");
  free(path);
}

static void c_eprt(session *s, const char *param) {
  char delim = param[0];
  char *copy = buckets_xstrdup(param);
  char *parts[8] = {0};
  int np = 0;
  for (char *q = copy, *start = copy; np < 8; q++) {
    if (*q == delim || !*q) {
      bool end = !*q;
      *q = '\0';
      parts[np++] = start;
      start = q + 1;
      if (end) break;
    }
  }
  int af, port;
  if (np < 4 || !buckets_ftp_atoi(parts[1], &af) || (af != 1 && af != 2) || !buckets_ftp_atoi(parts[3], &port)) {
    reply(s, 522, "Network protocol not supported, use (1,2)");
  } else if (!active_open(s, parts[2], port)) {
    reply(s, 425, "Data connection failed");
  } else {
    replyf(s, 200, "Connection established (%d)", port);
  }
  free(copy);
}

static void c_lprt(session *s, const char *param) {
  char *copy = buckets_xstrdup(param);
  char *parts[64];
  int np = 0;
  for (char *tok = copy, *q; tok && np < 64; tok = q) {
    q = strchr(tok, ',');
    if (q) *q++ = '\0';
    parts[np++] = tok;
  }
  int af, al, pl;
  if (!buckets_ftp_atoi(parts[0], &af) || af != 4) reply(s, 522, "Network protocol not supported, use 4");
  else if (np < 2 || !buckets_ftp_atoi(parts[1], &al)) reply(s, 522, "Network protocol not supported, use 4");
  else if (al != 4) reply(s, 522, "Network IP length not supported, use 4");
  else if (np < 7 || !buckets_ftp_atoi(parts[6], &pl)) reply(s, 522, "Network protocol not supported, use 4");
  else {
    char host[64];
    snprintf(host, sizeof(host), "%s.%s.%s.%s", parts[2], parts[3], parts[4], parts[5]);
    int port = 0;
    for (int i = 0; i < pl && 7 + i < np; i++) port = port * 256 + (atoi(parts[7 + i]) & 0xff);
    if (pl == 2) port &= 0xffff;
    if (s->have_data && !strcmp(s->data.host, host) && s->data.port == port) {
      /* already connected there: no reply */
    } else if (!active_open(s, host, port)) {
      reply(s, 425, "Data connection failed");
    } else {
      replyf(s, 200, "Connection established (%d)", port);
    }
  }
  free(copy);
}

static void c_epsv(session *s, const char *p) {
  (void)p;
  if (!passive_open(s)) {
    reply(s, 425, "Data connection failed");
    return;
  }
  replyf(s, 229, "Entering Extended Passive Mode (|||%d|)", s->data.port);
}

static void c_pasv(session *s, const char *p) {
  (void)p;
  const char *ip = passive_ip(s);
  if (!strncmp(ip, "::", 2)) {
    reply(s, 550, "Action not taken");
    return;
  }
  char host[64];
  snprintf(host, sizeof(host), "%s", ip);
  if (!passive_open(s)) {
    reply(s, 425, "Data connection failed");
    return;
  }
  int p1 = s->data.port / 256, p2 = s->data.port - p1 * 256;
  for (char *q = host; *q; q++)
    if (*q == '.') *q = ',';
  replyf(s, 227, "Entering Passive Mode (%s,%d,%d)", host, p1, p2);
}

static void c_port(session *s, const char *param) {
  char *copy = buckets_xstrdup(param);
  char *n[6] = {0};
  int k = 0;
  for (char *tok = copy, *q; tok && k < 6; tok = q) {
    q = strchr(tok, ',');
    if (q) *q++ = '\0';
    n[k++] = tok;
  }
  if (k < 6) { /* goftp indexes past the end and its handler recovers: no reply */
    free(copy);
    return;
  }
  int port = atoi(n[4]) * 256 + atoi(n[5]);
  char host[64];
  snprintf(host, sizeof(host), "%s.%s.%s.%s", n[0], n[1], n[2], n[3]);
  if (!active_open(s, host, port)) reply(s, 425, "Data connection failed");
  else replyf(s, 200, "Connection established (%d)", port);
  free(copy);
}

static void c_list(session *s, const char *param) {
  char *p = build_path(s, list_param(param)), err[1024];
  buckets_fs_info *v = NULL;
  size_t n = 0;
  if (!list_entries(s, p, &v, &n, err, sizeof(err))) {
    reply(s, 550, err);
  } else {
    reply(s, 150, "Opening ASCII mode data connection for file list");
    buckets_buf b = BUCKETS_BUF_INIT;
    detailed(&b, v, n);
    send_oob(s, &b);
    buckets_buf_free(&b);
  }
  buckets_fs_info_free(v, n);
  free(p);
}

static void c_nlst(session *s, const char *param) {
  char *p = build_path(s, list_param(param)), err[1024];
  buckets_fs_info fi;
  if (!d_stat(s, p, &fi, err, sizeof(err))) {
    reply(s, 550, err);
  } else if (!fi.dir) {
    replyf(s, 550, "%s is not a directory", param);
    free(fi.name);
  } else {
    free(fi.name);
    buckets_fs_info *v = NULL;
    size_t n = 0;
    if (!d_list(s, p, &v, &n, err, sizeof(err))) {
      reply(s, 550, err);
    } else {
      reply(s, 150, "Opening ASCII mode data connection for file list");
      buckets_buf b = BUCKETS_BUF_INIT;
      for (size_t i = 0; i < n; i++) buckets_buf_appendf(&b, "%s\r\n", v[i].name);
      send_oob(s, &b);
      buckets_buf_free(&b);
    }
    buckets_fs_info_free(v, n);
  }
  free(p);
}

static void c_mlsd(session *s, const char *param) {
  char *p = build_path(s, *param ? param : s->cur_dir), err[1024];
  buckets_fs_info *v = NULL;
  size_t n = 0;
  if (!list_entries(s, p, &v, &n, err, sizeof(err))) {
    reply(s, 550, err);
  } else {
    reply(s, 150, "Opening ASCII mode data connection for file list");
    buckets_buf b = BUCKETS_BUF_INIT;
    for (size_t i = 0; i < n; i++) {
      char t[32];
      fmt_time(mod_time(&v[i]), "%Y%m%d%H%M%S", t, sizeof(t));
      buckets_buf_appendf(&b, "Type=%s;Modify=%s;Size=%lld; %s\n", v[i].dir ? "dir" : "file", t, (long long)v[i].size,
                          v[i].name);
    }
    send_oob(s, &b);
    buckets_buf_free(&b);
  }
  buckets_fs_info_free(v, n);
  free(p);
}

static void c_mdtm(session *s, const char *param) {
  char *p = build_path(s, param), err[1024];
  buckets_fs_info fi;
  if (d_stat(s, p, &fi, err, sizeof(err))) {
    char t[32];
    fmt_time(mod_time(&fi), "%Y%m%d%H%M%S", t, sizeof(t));
    reply(s, 213, t);
    free(fi.name);
  } else {
    reply(s, 450, "File not available");
  }
  free(p);
}

static void c_size(session *s, const char *param) {
  char *p = build_path(s, param), err[1024];
  buckets_fs_info fi;
  if (d_stat(s, p, &fi, err, sizeof(err))) {
    replyf(s, 213, "%d", (int)fi.size);
    free(fi.name);
  } else {
    replyf(s, 450, "path %s not found", param);
  }
  free(p);
}

static void c_stat(session *s, const char *param) {
  if (!*param) {
    const char *ip = g_srv.o.public_ip ? g_srv.o.public_ip : "";
    replyf(s, 211,
           "%s FTP server status:\nVersion %sConnected to %s (%s)\nLogged in %s\n"
           "TYPE: ASCII, FORM: Nonprint; STRUcture: File; transfer MODE: Stream\nNo data connection",
           ip, GOFTP_VERSION, ip, GOFTP_VERSION, s->user ? s->user : "");
    reply(s, 211, "End of status");
    return;
  }
  char *p = build_path(s, param), err[1024];
  buckets_fs_info fi;
  if (!d_stat(s, p, &fi, err, sizeof(err))) {
    replyf(s, 450, "path %s not found", p);
  } else if (fi.dir) {
    free(fi.name);
    buckets_fs_info *v = NULL;
    size_t n = 0;
    if (!d_list(s, p, &v, &n, err, sizeof(err))) {
      reply(s, 550, err);
    } else {
      reply(s, 213, "Opening ASCII mode data connection for file list");
      buckets_buf b = BUCKETS_BUF_INIT;
      detailed(&b, v, n);
      send_oob(s, &b);
      buckets_buf_free(&b);
    }
    buckets_fs_info_free(v, n);
  } else {
    reply(s, 212, "Opening ASCII mode data connection for file list");
    buckets_buf b = BUCKETS_BUF_INIT;
    detailed(&b, &fi, 1);
    send_oob(s, &b);
    buckets_buf_free(&b);
    free(fi.name);
  }
  free(p);
}

static void c_mkd(session *s, const char *param) {
  char *p = build_path(s, param), err[1024];
  int64_t t0 = wall_ns();
  bool ok = fs_ready(s, err, sizeof(err)) && buckets_fs_mkdir(s->fs, p, err, sizeof(err));
  ftp_trace(s, T_MKDIR, t0, p, ok ? NULL : err, 0);
  if (ok) reply(s, 257, "Directory created");
  else replyf(s, 550, "Action not taken: %s", err);
  free(p);
}

static void c_mode(session *s, const char *p) {
  if (!strcasecmp(p, "S")) reply(s, 200, "OK");
  else reply(s, 504, "MODE is an obsolete command");
}

static void c_stru(session *s, const char *p) {
  if (!strcasecmp(p, "F")) reply(s, 200, "OK");
  else reply(s, 504, "STRU is an obsolete command");
}

static void c_type(session *s, const char *p) {
  if (!strcasecmp(p, "A")) reply(s, 200, "Type set to ASCII");
  else if (!strcasecmp(p, "I")) reply(s, 200, "Type set to binary");
  else reply(s, 500, "Invalid type");
}

static void c_user(session *s, const char *param) {
  free(s->req_user);
  s->req_user = buckets_xstrdup(param);
  reply(s, 331, "User name ok, password required");
}

static void c_pass(session *s, const char *param) {
  const char *user = s->req_user ? s->req_user : "";
  char err[1024] = "";
  int64_t t0 = wall_ns();
  bool ok = buckets_fs_check_password(user, param, err, sizeof(err));
  ftp_trace(s, T_PASS, t0, user, *err ? err : NULL, 0);
  if (*err) {
    reply(s, 550, "Checking password error");
    return;
  }
  if (ok) {
    free(s->user);
    s->user = s->req_user;
    s->req_user = NULL;
    buckets_fs_close(s->fs);
    s->fs = NULL;
    reply(s, 230, "Password ok, continue");
  } else {
    reply(s, 530, "Incorrect password, not logged in");
  }
}

static void c_pwd(session *s, const char *p) {
  (void)p;
  replyf(s, 257, "\"%s\" is the current directory", s->cur_dir);
}

static void c_quit(session *s, const char *p) {
  (void)p;
  reply(s, 221, "Goodbye");
  s->closed = true;
}

static long stream_read(void *ud, void *buf, size_t n) { return buckets_http_stream_read(ud, buf, n); }

static void c_retr(session *s, const char *param) {
  char *p = build_path(s, param), err[1024];
  if (strcmp(s->pre_cmd, "REST") != 0) s->last_pos = -1;
  int64_t pos = s->last_pos < 0 ? 0 : s->last_pos;
  int64_t size = 0, t0 = wall_ns();
  buckets_http_stream *st = fs_ready(s, err, sizeof(err)) ? buckets_fs_get(s->fs, p, pos, &size, err, sizeof(err)) : NULL;
  if (!st) {
    ftp_trace(s, T_GET, t0, p, err, 0);
    reply(s, 551, "File not available");
  } else {
    ftp_trace(s, T_GET, t0, p, NULL, size);
    replyf(s, 150, "Data transfer starting %lld bytes", (long long)size);
    xconn *c = s->have_data ? data_conn(s) : NULL;
    if (!s->have_data) {
      /* io.Copy to a nil connection: goftp's handler recovers, no reply */
    } else {
      char buf[65536];
      long k;
      int64_t sent = 0;
      bool failed = !c;
      while (!failed && (k = stream_read(st, buf, sizeof(buf))) > 0) {
        if (!xwrite(c, buf, (size_t)k)) failed = true;
        else sent += k;
      }
      if (!failed && k < 0) failed = true;
      data_close(s);
      if (failed) reply(s, 551, "Error reading file");
      else replyf(s, 226, "Closing data connection, sent %d bytes", (int)sent);
    }
    buckets_http_stream_free(st);
  }
  s->last_pos = -1;
  free(p);
}

static void c_rest(session *s, const char *param) {
  char *end;
  errno = 0;
  long long v = strtoll(param, &end, 10);
  if (!*param || *end || errno) {
    s->last_pos = 0;
    reply(s, 551, "File not available");
    return;
  }
  s->last_pos = v;
  replyf(s, 350, "Start transfer from %lld", v);
}

static void c_rnfr(session *s, const char *param) {
  free(s->rename_from);
  s->rename_from = NULL;
  char *p = build_path(s, param), err[1024];
  buckets_fs_info fi;
  if (!d_stat(s, p, &fi, err, sizeof(err))) {
    replyf(s, 550, "Action not taken: %s", err);
    free(p);
    return;
  }
  free(fi.name);
  s->rename_from = p;
  reply(s, 350, "Requested file action pending further information.");
}

static void c_rnto(session *s, const char *param) {
  char *to = build_path(s, param);
  int64_t t0 = wall_ns();
  buckets_buf paths = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&paths, "%s %s", s->rename_from ? s->rename_from : "", to);
  ftp_trace(s, T_RENAME, t0, paths.data, NULL, 0); /* NotImplemented{}: an empty error */
  buckets_buf_free(&paths);
  free(s->rename_from);
  s->rename_from = NULL;
  reply(s, 550, "Action not taken: ");
  free(to);
}

static void c_rmd(session *s, const char *param) {
  char *p = build_path(s, param), err[1024];
  if (!strcmp(param, "/") || !*param) {
    reply(s, 550, "Directory / cannot be deleted");
    free(p);
    return;
  }
  bool change = !strncmp(param, s->cur_dir, strlen(s->cur_dir));
  int64_t t0 = wall_ns();
  bool ok = fs_ready(s, err, sizeof(err)) && buckets_fs_rmdir(s->fs, p, err, sizeof(err));
  ftp_trace(s, T_RMDIR, t0, p, ok ? NULL : err, 0);
  if (change) {
    /* path.Dir(param) */
    char *d = buckets_xstrdup(param);
    char *sl = strrchr(d, '/');
    if (!sl) snprintf(s->cur_dir, sizeof(s->cur_dir), ".");
    else {
      sl[sl == d ? 1 : 0] = '\0';
      char *c = buckets_fs_clean(d);
      snprintf(s->cur_dir, sizeof(s->cur_dir), "%s", *c ? c : ".");
      free(c);
    }
    free(d);
  }
  if (ok) reply(s, 250, "Directory deleted");
  else replyf(s, 550, "Directory delete failed: %s", err);
  free(p);
}

static void c_auth(session *s, const char *param) {
  if (!strcmp(param, "TLS") && g_srv.tls) {
    reply(s, 234, "AUTH command OK");
    SSL *ssl = SSL_new(g_srv.tls);
    SSL_set_fd(ssl, s->ctl.fd);
    if (SSL_accept(ssl) == 1) {
      s->ctl.ssl = ssl;
      s->tls = true;
      buckets_buf_reset(&s->in);
    } else {
      SSL_free(ssl);
    }
  } else {
    reply(s, 550, "Action not taken");
  }
}

static void c_pbsz(session *s, const char *p) {
  if (s->tls && !strcmp(p, "0")) reply(s, 200, "OK");
  else reply(s, 550, "Action not taken");
}

static void c_prot(session *s, const char *p) {
  if (s->tls && !strcmp(p, "P")) reply(s, 200, "OK");
  else if (s->tls) reply(s, 536, "Only P level is supported");
  else reply(s, 550, "Action not taken");
}

/* the data connection as PutFile's reader */
typedef struct {
  session *s;
  xconn *c;
  bool failed;
} put_src;

static long put_read(void *ud, void *buf, size_t n) {
  put_src *p = ud;
  if (!p->c) return -1;
  long k = xread(p->c, buf, n);
  if (k < 0) p->failed = true;
  return k;
}

static void store(session *s, const char *param) {
  char *p = build_path(s, param), err[1024] = "";
  reply(s, 150, "Data transfer starting");
  if (strcmp(s->pre_cmd, "REST") != 0) s->last_pos = -1;
  int64_t n = 0, t0 = wall_ns();
  bool ok;
  if (s->last_pos != -1) {
    ok = false; /* NotImplemented{}: its message is empty */
  } else if (!s->have_data) {
    /* reading a nil connection: goftp's handler recovers, no reply */
    s->last_pos = -1;
    free(p);
    return;
  } else {
    put_src src = {s, data_conn(s), false};
    if (!src.c) snprintf(err, sizeof(err), "%s", s->data.err);
    ok = src.c && fs_ready(s, err, sizeof(err)) && buckets_fs_put(s->fs, p, put_read, &src, &n, err, sizeof(err));
    /* goftp leaves the connection to the client; it is done with here */
    xclose(&s->data.c);
    s->data.failed = true;
    snprintf(s->data.err, sizeof(s->data.err), "use of closed network connection");
  }
  ftp_trace(s, T_PUT, t0, p, ok ? NULL : err, n);
  if (ok) replyf(s, 226, "OK, received %lld bytes", (long long)n);
  else replyf(s, 450, "error during transfer: %s", err);
  s->last_pos = -1;
  free(p);
}

static void c_stor(session *s, const char *param) { store(s, param); }
static void c_appe(session *s, const char *param) { store(s, param); }

static const command k_commands[] = {
    {"ADAT", true, true, false, c_not_taken}, {"ALLO", false, false, false, c_allo},
    {"APPE", true, true, false, c_appe},      {"AUTH", true, false, false, c_auth},
    {"CCC", true, true, false, c_not_taken},  {"CDUP", false, true, false, c_cdup},
    {"CLNT", false, false, true, c_clnt},     {"CONF", true, true, false, c_not_taken},
    {"CWD", true, true, false, c_cwd},        {"DELE", true, true, false, c_dele},
    {"ENC", true, true, false, c_not_taken},  {"EPRT", true, true, true, c_eprt},
    {"EPSV", false, true, true, c_epsv},      {"FEAT", false, false, false, c_feat},
    {"LIST", false, true, false, c_list},     {"LPRT", true, true, true, c_lprt},
    {"MDTM", true, true, false, c_mdtm},      {"MIC", true, true, false, c_not_taken},
    {"MKD", true, true, false, c_mkd},        {"MLSD", false, true, true, c_mlsd},
    {"MODE", true, true, false, c_mode},      {"NLST", false, true, false, c_nlst},
    {"NOOP", false, false, false, c_noop},    {"OPTS", false, false, false, c_opts},
    {"PASS", true, false, false, c_pass},     {"PASV", false, true, false, c_pasv},
    {"PBSZ", true, false, false, c_pbsz},     {"PORT", true, true, false, c_port},
    {"PROT", true, false, false, c_prot},     {"PWD", false, true, false, c_pwd},
    {"QUIT", false, false, false, c_quit},    {"REST", true, true, false, c_rest},
    {"RETR", true, true, false, c_retr},      {"RMD", true, true, false, c_rmd},
    {"RNFR", true, true, false, c_rnfr},      {"RNTO", true, true, false, c_rnto},
    {"SIZE", true, true, false, c_size},      {"STAT", false, true, false, c_stat},
    {"STOR", true, true, false, c_stor},      {"STRU", true, true, false, c_stru},
    {"SYST", false, true, false, c_syst},     {"TYPE", false, true, false, c_type},
    {"USER", true, false, false, c_user},     {"XCUP", false, true, false, c_cdup},
    {"XCWD", true, true, false, c_cwd},       {"XMKD", true, true, false, c_mkd},
    {"XPWD", false, true, false, c_pwd},      {"XRMD", true, true, false, c_rmd},
};

static void receive_line(session *s, char *line) {
  /* strings.Trim(line, "\r\n"), then SplitN(" ", 2) */
  size_t n = strlen(line);
  while (n && (line[n - 1] == '\r' || line[n - 1] == '\n')) line[--n] = '\0';
  char *start = line;
  while (*start == '\r' || *start == '\n') start++;
  char *sp = strchr(start, ' ');
  const char *param = "";
  if (sp) *sp = '\0', param = sp + 1;
  char up[16];
  size_t i = 0;
  for (; start[i] && i + 1 < sizeof(up); i++) up[i] = (char)toupper((unsigned char)start[i]);
  up[i] = '\0';
  const command *cmd = NULL;
  if (strlen(start) < sizeof(up))
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(k_commands) && !cmd; k++)
      if (!strcmp(k_commands[k].name, up)) cmd = &k_commands[k];
  if (!cmd) {
    reply(s, 500, "Command not found");
    return;
  }
  if (cmd->need_param && !*param) {
    reply(s, 553, "action aborted, required param missing");
  } else if (cmd->need_auth && !s->user) {
    reply(s, 530, "not logged in");
  } else {
    s->cmd = cmd->name;
    s->param = param;
    cmd->run(s, param);
    snprintf(s->pre_cmd, sizeof(s->pre_cmd), "%s", up);
  }
}

static void *session_run(void *arg) {
  session *s = arg;
  char welcome[256];
  /* MinIO passes the license and the version the other way round */
  snprintf(welcome, sizeof(welcome), "Welcome to 'Buckets' FTP Server Version='%s' License='%s'", LICENSE,
           BUCKETS_VERSION);
  reply(s, 220, welcome);
  char buf[4096];
  while (!s->closed) {
    char *nl;
    while (!(nl = memchr(s->in.data ? s->in.data : "", '\n', s->in.len))) {
      if (s->in.len > (1 << 20)) goto done;
      long k = xread(&s->ctl, buf, sizeof(buf));
      if (k <= 0) goto done;
      buckets_buf_append(&s->in, buf, (size_t)k);
    }
    size_t len = (size_t)(nl - s->in.data) + 1;
    char *line = buckets_xstrndup(s->in.data, len);
    memmove(s->in.data, s->in.data + len, s->in.len - len);
    s->in.len -= len;
    receive_line(s, line);
    free(line);
  }
done:
  data_close(s);
  xclose(&s->ctl);
  buckets_fs_close(s->fs);
  buckets_buf_free(&s->in);
  free(s->req_user);
  free(s->user);
  free(s->rename_from);
  free(s);
  return NULL;
}

static void addr_ip(const struct sockaddr_storage *ss, char *out, size_t cap) {
  if (ss->ss_family == AF_INET6) {
    const struct sockaddr_in6 *a = (const void *)ss;
    if (IN6_IS_ADDR_V4MAPPED(&a->sin6_addr)) inet_ntop(AF_INET, &a->sin6_addr.s6_addr[12], out, (socklen_t)cap);
    else inet_ntop(AF_INET6, &a->sin6_addr, out, (socklen_t)cap);
  } else {
    inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, out, (socklen_t)cap);
  }
}

static void *accept_run(void *arg) {
  (void)arg;
  for (;;) {
    struct sockaddr_storage peer;
    socklen_t pl = sizeof(peer);
    int fd = accept(g_srv.lfd, (struct sockaddr *)&peer, &pl);
    if (fd < 0) {
      if (errno == EINTR || errno == ECONNABORTED || errno == EMFILE) continue;
      break;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    session *s = buckets_xcalloc(1, sizeof(*s));
    s->ctl.fd = fd;
    s->data.lfd = -1;
    s->data.c.fd = -1;
    s->last_pos = -1;
    snprintf(s->cur_dir, sizeof(s->cur_dir), "/");
    addr_ip(&peer, s->remote_ip, sizeof(s->remote_ip));
    struct sockaddr_storage local;
    socklen_t ll = sizeof(local);
    getsockname(fd, (struct sockaddr *)&local, &ll);
    addr_ip(&local, s->local_ip, sizeof(s->local_ip));
    pthread_t t;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &at, session_run, s) != 0) {
      close(fd);
      free(s);
    }
    pthread_attr_destroy(&at);
  }
  return NULL;
}

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                       unsigned int inlen, void *arg) {
  (void)ssl, (void)arg;
  static const unsigned char ftp[] = {3, 'f', 't', 'p'};
  if (SSL_select_next_proto((unsigned char **)out, outlen, ftp, sizeof(ftp), in, inlen) == OPENSSL_NPN_NEGOTIATED)
    return SSL_TLSEXT_ERR_OK;
  return SSL_TLSEXT_ERR_ALERT_FATAL; /* Go: no application protocol in common */
}

bool buckets_ftp_start(buckets_ftp_opts *o, bool s3_tls, const char *certs_dir, char *err, size_t errlen) {
  g_srv.o = *o;
  /* force-tls only takes part in the startup checks: goftp's optsWithDefaults
   * drops Options.ForceTLS, so MinIO never enforces it (nor do we) */
  char kbuf[4096], cbuf[4096];
  if (s3_tls && !(o->key && *o->key) && !(o->cert && *o->cert) && certs_dir) {
    snprintf(kbuf, sizeof(kbuf), "%s/private.key", certs_dir);
    snprintf(cbuf, sizeof(cbuf), "%s/public.crt", certs_dir);
    g_srv.o.key = buckets_xstrdup(kbuf);
    g_srv.o.cert = buckets_xstrdup(cbuf);
  }
  bool tls = g_srv.o.key && *g_srv.o.key && g_srv.o.cert && *g_srv.o.cert;
  if (g_srv.o.force_tls && !tls) {
    snprintf(err, errlen, "invalid TLS arguments provided. force-tls, but missing private key "
                          "--ftp=\"tls-private-key=path/to/private.key\"");
    return false;
  }
  snprintf(g_srv.name, sizeof(g_srv.name), tls ? "Buckets FTP(Secure) Server" : "Buckets FTP Server");
  if (tls) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    buckets_tls_ctx_setup(ctx);
    /* a peer closing without close_notify ends the stream, as for Go */
    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
    if (SSL_CTX_use_certificate_chain_file(ctx, g_srv.o.cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, g_srv.o.key, SSL_FILETYPE_PEM) != 1) {
      unsigned long e = ERR_get_error();
      snprintf(err, errlen, "unable to start FTP server: %s", e ? ERR_reason_error_string(e) : "bad certificate");
      SSL_CTX_free(ctx);
      return false;
    }
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    g_srv.tls = ctx;
  }
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  bool v6 = fd >= 0;
  if (!v6) fd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1, zero = 0;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  int rc;
  if (v6) {
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((uint16_t)o->port), .sin6_addr = in6addr_any};
    rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
  } else {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)o->port), .sin_addr.s_addr = INADDR_ANY};
    rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
  }
  if (rc != 0 || listen(fd, 128) != 0) {
    snprintf(err, errlen, "unable to start FTP server: listen tcp :%d: %s", o->port, strerror(errno));
    close(fd);
    return false;
  }
  g_srv.lfd = fd;
  pthread_t t;
  if (pthread_create(&t, NULL, accept_run, NULL) != 0) {
    snprintf(err, errlen, "unable to start FTP server");
    return false;
  }
  pthread_detach(t);
  const char *ip = g_srv.o.public_ip ? g_srv.o.public_ip : "";
  buckets_log_info("%s listening on %s%s%s:%d", g_srv.name, strchr(ip, ':') ? "[" : "", ip, strchr(ip, ':') ? "]" : "",
                   o->port);
  return true;
}
