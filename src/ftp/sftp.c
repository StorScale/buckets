/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ftp/sftp.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#define WITH_SERVER 1 /* sftp.h declares its server side for this */
#include <libssh/sftp.h>
#include <netinet/in.h>
#include <pthread.h>
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
#include "ftp/ftp.h"
#include "ftp/s3fs.h"
#include "ftp/sshcert.h"
#include "notify/event.h"
#include "trace/trace.h"

/* ---- options (startSFTPServer) ---- */

static const char *const k_kex_supported[] = {"curve25519-sha256",
                                              "curve25519-sha256@libssh.org",
                                              "ecdh-sha2-nistp256",
                                              "ecdh-sha2-nistp384",
                                              "ecdh-sha2-nistp521",
                                              "diffie-hellman-group14-sha256",
                                              "diffie-hellman-group16-sha512",
                                              "diffie-hellman-group14-sha1",
                                              "diffie-hellman-group1-sha1",
                                              NULL};
static const char *const k_kex_preferred[] = {"curve25519-sha256",           "curve25519-sha256@libssh.org",
                                              "ecdh-sha2-nistp256",          "ecdh-sha2-nistp384",
                                              "ecdh-sha2-nistp521",          "diffie-hellman-group14-sha256",
                                              "diffie-hellman-group14-sha1", NULL};
static const char *const k_pubkey_supported[] = {"ssh-ed25519",
                                                 "sk-ssh-ed25519@openssh.com",
                                                 "sk-ecdsa-sha2-nistp256@openssh.com",
                                                 "ecdsa-sha2-nistp256",
                                                 "ecdsa-sha2-nistp384",
                                                 "ecdsa-sha2-nistp521",
                                                 "rsa-sha2-256",
                                                 "rsa-sha2-512",
                                                 "ssh-rsa",
                                                 "ssh-dss",
                                                 NULL};
static const char *const k_cipher_supported[] = {"aes128-ctr",
                                                 "aes192-ctr",
                                                 "aes256-ctr",
                                                 "aes128-gcm@openssh.com",
                                                 "aes256-gcm@openssh.com",
                                                 "chacha20-poly1305@openssh.com",
                                                 "arcfour256",
                                                 "arcfour128",
                                                 "arcfour",
                                                 "aes128-cbc",
                                                 "3des-cbc",
                                                 NULL};
static const char *const k_cipher_preferred[] = {"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
                                                 "chacha20-poly1305@openssh.com", "aes128-ctr",
                                                 "aes192-ctr",             "aes256-ctr",
                                                 NULL};
static const char *const k_mac_supported[] = {"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
                                              "hmac-sha2-256",                 "hmac-sha2-512",
                                              "hmac-sha1",                     "hmac-sha1-96",
                                              NULL};

/* what libssh implements of those (the rest is accepted, then left out) */
static const char *const k_libssh_algos[] = {
    "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "ssh-ed25519", "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa", "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes128-cbc", "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", NULL};

static bool in_set(const char *const *set, const char *s) {
  for (size_t i = 0; set[i]; i++)
    if (!strcmp(set[i], s)) return true;
  return false;
}

static void join_set(const char *const *set, buckets_buf *out) {
  for (size_t i = 0; set[i]; i++) buckets_buf_appendf(out, "%s%s", i ? ", " : "", set[i]);
}

/* filterAlgos: every name must be known; the list libssh gets */
static char *filter_algos(const char *arg, const char *val, const char *const *allowed, char *err, size_t errlen) {
  buckets_buf out = BUCKETS_BUF_INIT, all = BUCKETS_BUF_INIT;
  join_set(allowed, &all);
  char *copy = buckets_xstrdup(val);
  bool any = false, ok = true;
  for (char *tok = copy, *next; tok && ok; tok = next) {
    next = strchr(tok, ',');
    if (next) *next++ = '\0';
    if (!*tok) continue;
    char *a = tok;
    while (*a == ' ' || *a == '\t') a++;
    size_t n = strlen(a);
    while (n && (a[n - 1] == ' ' || a[n - 1] == '\t')) a[--n] = '\0';
    for (char *c = a; *c; c++) *c = (char)tolower((unsigned char)*c);
    if (!in_set(allowed, a)) {
      snprintf(err, errlen, "unknown algorithm \"%s\" passed to --sftp=%s\nValid algorithms: %s", a, arg, all.data);
      ok = false;
      break;
    }
    any = true;
    if (in_set(k_libssh_algos, a)) buckets_buf_appendf(&out, "%s%s", out.len ? "," : "", a);
  }
  free(copy);
  if (ok && !any) {
    snprintf(err, errlen, "no valid algorithms passed to --sftp=%s\nValid algorithms: %s", arg, all.data);
    ok = false;
  }
  buckets_buf_free(&all);
  if (!ok) {
    buckets_buf_free(&out);
    return NULL;
  }
  char *r = buckets_xstrdup(out.data ? out.data : "");
  buckets_buf_free(&out);
  return r;
}

bool buckets_sftp_parse(char *const *args, size_t n, buckets_sftp_opts *o, char *err, size_t errlen) {
  memset(o, 0, sizeof(*o));
  for (size_t i = 0; i < n; i++) {
    const char *eq = strchr(args[i], '=');
    if (!eq) {
      snprintf(err, errlen, "invalid arguments passed to --sftp=%s", args[i]);
      return false;
    }
    char *key = buckets_xstrndup(args[i], (size_t)(eq - args[i]));
    const char *val = eq + 1;
    bool ok = true;
    char **slot = NULL;
    if (!strcmp(key, "address")) {
      char *host = NULL, *port = NULL, e2[256];
      if (!buckets_ftp_split_host_port(val, &host, &port, e2, sizeof(e2))) {
        snprintf(err, errlen, "invalid arguments passed to --sftp=%s (%s)", args[i], e2);
        ok = false;
      } else if (!buckets_ftp_atoi(port, &o->port)) {
        snprintf(err, errlen, "invalid arguments passed to --sftp=%s (strconv.Atoi: parsing \"%s\": invalid syntax)",
                 args[i], port);
        ok = false;
      } else if (o->port < 1 || o->port > 65535) {
        snprintf(err, errlen, "invalid arguments passed to --sftp=%s, (port number must be between 1 to 65535)",
                 args[i]);
        ok = false;
      } else {
        free(o->public_ip);
        o->public_ip = buckets_xstrdup(host);
      }
      free(host);
      free(port);
    } else if (!strcmp(key, "ssh-private-key")) {
      free(o->key_file);
      o->key_file = buckets_xstrdup(val);
    } else if (!strcmp(key, "trusted-user-ca-key")) {
      free(o->ca_file);
      o->ca_file = buckets_xstrdup(val);
    } else if (!strcmp(key, "disable-password-auth")) {
      bool b = false;
      buckets_ftp_parse_bool(val, &b); /* its error is ignored */
      o->no_password = b;
    } else if (!strcmp(key, "pub-key-algos") || !strcmp(key, "kex-algos") || !strcmp(key, "cipher-algos") ||
               !strcmp(key, "mac-algos")) {
      const char *const *allowed = !strcmp(key, "pub-key-algos") ? k_pubkey_supported
                                   : !strcmp(key, "kex-algos")    ? k_kex_supported
                                   : !strcmp(key, "cipher-algos") ? k_cipher_supported
                                                                  : k_mac_supported;
      slot = !strcmp(key, "pub-key-algos") ? &o->pub_key_algos
             : !strcmp(key, "kex-algos")    ? &o->kex_algos
             : !strcmp(key, "cipher-algos") ? &o->cipher_algos
                                            : &o->mac_algos;
      char *list = filter_algos(args[i], val, allowed, err, errlen);
      if (!list) ok = false;
      else free(*slot), *slot = list;
    }
    free(key);
    if (!ok) return false;
  }
  if (!o->port) o->port = 8022;
  if (!o->key_file || !*o->key_file) {
    snprintf(err, errlen, "invalid arguments passed, private key file is mandatory for "
                          "--sftp='ssh-private-key=path/to/id_ecdsa'");
    return false;
  }
  return true;
}

/* ---- the server ---- */

typedef struct {
  buckets_sftp_opts o;
  ssh_bind bind;
  ssh_key ca; /* trusted-user-ca-key, or NULL */
} sftp_server;

static sftp_server g_srv;

/* ---- traces (sftpTrace) ---- */

typedef struct {
  const char *func;
  int line;
} tsrc;

static const tsrc T_GET = {"Fileread", 143}, T_PUT = {"Filewrite", 249}, T_CMD = {"Filecmd", 303},
                  T_LIST = {"Filelist", 399};

static int64_t wall_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void sftp_trace(tsrc src, const char *method, const char *path, const char *user, int64_t start,
                       const char *err, int64_t bytes) {
  if (!buckets_trace_wanted(BUCKETS_TRACE_FTP)) return;
  int64_t dur = wall_ns() - start;
  char when[64], source[128];
  buckets_time_rfc3339_nano(start / 1000000000LL, (long)(start % 1000000000LL), when);
  snprintf(source, sizeof(source), "[sftp-server-driver.go:%d:(*sftpDriver).%s()]", src.line, src.func);
  buckets_buf j = BUCKETS_BUF_INIT;
  const char *node = buckets_trace_node();
  buckets_buf_appendf(&j, "{\"type\":%u,\"nodename\":", (unsigned)BUCKETS_TRACE_FTP);
  buckets_json_go_string(&j, node, strlen(node));
  buckets_buf_append_c(&j, ",\"funcname\":");
  buckets_json_go_string(&j, method, strlen(method));
  buckets_buf_appendf(&j, ",\"time\":\"%s\",\"path\":", when);
  buckets_json_go_string(&j, path, strlen(path));
  buckets_buf_appendf(&j, ",\"dur\":%lld", (long long)dur);
  if (bytes) buckets_buf_appendf(&j, ",\"bytes\":%lld", (long long)bytes);
  if (err && *err) {
    buckets_buf_append_c(&j, ",\"error\":");
    buckets_json_go_string(&j, err, strlen(err));
  }
  buckets_buf_append_c(&j, ",\"custom\":{\"cmd\":");
  buckets_json_go_string(&j, method, strlen(method));
  buckets_buf_append_c(&j, ",\"param\":");
  buckets_json_go_string(&j, path, strlen(path));
  buckets_buf_append_c(&j, ",\"source\":");
  buckets_json_go_string(&j, source, strlen(source));
  buckets_buf_append_c(&j, ",\"user\":");
  buckets_json_go_string(&j, user, strlen(user));
  buckets_buf_append_c(&j, "}}");
  buckets_trace_meta m = {.type = BUCKETS_TRACE_FTP, .dur_ns = dur};
  buckets_trace_publish(&m, j.data, j.len);
  buckets_buf_free(&j);
}

/* ---- the upload pipe (io.Pipe between WriteAt and PutObject) ---- */

typedef struct {
  pthread_mutex_t mu;
  pthread_cond_t cv;
  const uint8_t *data; /* the write being handed over */
  size_t len;
  bool wclosed;        /* the writer closed: EOF */
  bool rclosed;        /* the upload ended: writes fail with rerr */
  char rerr[512];
} pipe_t;

static void pipe_init(pipe_t *p) {
  memset(p, 0, sizeof(*p));
  pthread_mutex_init(&p->mu, NULL);
  pthread_cond_init(&p->cv, NULL);
}

/* PipeWriter.Write: blocks until the reader has taken everything */
static bool pipe_write(pipe_t *p, const uint8_t *b, size_t n, char *err, size_t errlen) {
  pthread_mutex_lock(&p->mu);
  if (p->rclosed) {
    snprintf(err, errlen, "%s", p->rerr[0] ? p->rerr : "io: read/write on closed pipe");
    pthread_mutex_unlock(&p->mu);
    return false;
  }
  p->data = b, p->len = n;
  pthread_cond_broadcast(&p->cv);
  while (p->len && !p->rclosed) pthread_cond_wait(&p->cv, &p->mu);
  bool ok = !p->len;
  if (!ok) snprintf(err, errlen, "%s", p->rerr[0] ? p->rerr : "io: read/write on closed pipe");
  p->data = NULL, p->len = 0;
  pthread_mutex_unlock(&p->mu);
  return ok;
}

static long pipe_read(void *ud, void *buf, size_t n) {
  pipe_t *p = ud;
  pthread_mutex_lock(&p->mu);
  while (!p->len && !p->wclosed && !p->rclosed) pthread_cond_wait(&p->cv, &p->mu);
  long k;
  if (p->len) {
    size_t c = BUCKETS_MIN(n, p->len);
    memcpy(buf, p->data, c);
    p->data += c, p->len -= c;
    k = (long)c;
    if (!p->len) pthread_cond_broadcast(&p->cv);
  } else {
    k = p->rclosed || p->rerr[0] ? -1 : 0; /* a transfer error, or the end */
  }
  pthread_mutex_unlock(&p->mu);
  return k;
}

/* ---- handles ---- */

typedef enum { H_LIST, H_READ, H_WRITE } hkind;

typedef struct {
  char *path; /* cleanPathWithBase */
  char *name; /* the entry's name */
  int64_t size, mtime_ns;
  bool dir;
} entry;

struct session;

typedef struct {
  hkind kind;
  char *path;
  /* list */
  buckets_fs_info *ents;
  size_t nents, next;
  /* read */
  buckets_http_stream *st;
  int64_t pos, size;
  /* write: WriteAt reorders into the pipe; the upload runs in a thread */
  pipe_t pipe;
  pthread_t up;
  bool up_started;
  int64_t next_off;
  struct wseg {
    int64_t off;
    uint8_t *b;
    size_t n;
  } *segs;
  size_t nsegs;
  char werr[512];
  struct session *sess;
} handle;

typedef struct session {
  ssh_session ssh;
  ssh_channel chan;
  struct ssh_channel_callbacks_struct *chan_cb;
  char remote_ip[64];
  char *user;           /* the SSH user name */
  const char *login_user; /* the name being authenticated (certificate principals) */
  char *ak, *sk, *token; /* credentials from the login */
  ssh_key auth_key;     /* the key under test (pubkey callback) */
  bool authed, want_sftp, failed;
  buckets_fs *fs;
  handle **handles;
  size_t nhandles;
} session;

/* ---- attributes (fileStatFromInfo) and ls (runLs) ---- */

static int64_t mod_ns(const buckets_fs_info *f) { return f->mtime_ns ? f->mtime_ns : 315532800LL * 1000000000LL; }

static void fill_attrs(struct sftp_attributes_struct *a, const buckets_fs_info *f) {
  memset(a, 0, sizeof(*a));
  a->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;
  a->size = (uint64_t)f->size;
  a->permissions = f->dir ? 040000 : 0100777; /* minioFileInfo.Mode: ModeDir alone, or ModePerm */
  a->atime = a->mtime = (uint32_t)(mod_ns(f) / 1000000000LL);
}

static void longname(const buckets_fs_info *f, char *out, size_t cap) {
  static const char *const mon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  time_t t = (time_t)(mod_ns(f) / 1000000000LL), now = time(NULL);
  struct tm m, n;
  gmtime_r(&t, &m);
  gmtime_r(&now, &n);
  n.tm_mon -= 6;
  time_t half_year = timegm(&n);
  char yt[16];
  if (t < half_year) snprintf(yt, sizeof(yt), "%d", m.tm_year + 1900);
  else snprintf(yt, sizeof(yt), "%02d:%02d", m.tm_hour, m.tm_min);
  char date[16];
  snprintf(date, sizeof(date), "%s %d", mon[m.tm_mon], m.tm_mday);
  snprintf(out, cap, "%s %4d %-8s %-8s %8lld %s %5s %s", f->dir ? "d---------" : "-rwxrwxrwx", 1, "0", "0",
           (long long)f->size, date, yt, f->name);
}

/* cleanPathWithBase("/", p) */
static char *clean_path(const char *p) {
  buckets_buf b = BUCKETS_BUF_INIT;
  if (*p != '/') buckets_buf_append_char(&b, '/');
  buckets_buf_append_c(&b, p);
  char *c = buckets_fs_clean(b.data);
  buckets_buf_free(&b);
  if (!*c) {
    free(c);
    c = buckets_xstrdup("/");
  }
  return c;
}

/* ---- replies ---- */

static void status(sftp_client_message m, uint32_t code, const char *msg) { sftp_reply_status(m, code, msg); }

static void status_err(sftp_client_message m, const char *err) { status(m, SSH_FX_FAILURE, err); }

/* statusFromError for the driver's errors: os.ErrNotExist is "no such file" */
static void status_fs(sftp_client_message m, const char *err) {
  if (!strcmp(err, "file does not exist")) status(m, SSH_FX_NO_SUCH_FILE, err);
  else status_err(m, err);
}

/* ---- the operations ---- */

static bool fs_stat(session *s, const char *path, buckets_fs_info *fi, char *err, size_t errlen) {
  int64_t t0 = wall_ns();
  memset(fi, 0, sizeof(*fi));
  bool ok;
  if (!strcmp(path, "/")) {
    fi->name = buckets_xstrdup("/");
    fi->dir = ok = true;
  } else {
    ok = buckets_fs_stat(s->fs, path, fi, err, errlen);
  }
  sftp_trace(T_LIST, "Stat", path, s->ak, t0, ok ? NULL : err, 0);
  return ok;
}

static void op_stat(session *s, sftp_client_message m, const char *path) {
  buckets_fs_info fi;
  char err[1024];
  if (!fs_stat(s, path, &fi, err, sizeof(err))) {
    status_fs(m, err);
    return;
  }
  struct sftp_attributes_struct a;
  fill_attrs(&a, &fi);
  sftp_reply_attr(m, &a);
  free(fi.name);
}

static handle *new_handle(session *s, hkind k, const char *path) {
  handle *h = buckets_xcalloc(1, sizeof(*h));
  h->kind = k;
  h->path = buckets_xstrdup(path);
  h->sess = s;
  s->handles = buckets_xrealloc(s->handles, (s->nhandles + 1) * sizeof(*s->handles));
  s->handles[s->nhandles++] = h;
  return h;
}

static void op_opendir(session *s, sftp_client_message m, const char *path) {
  int64_t t0 = wall_ns();
  char err[1024];
  buckets_fs_info *v = NULL;
  size_t n = 0;
  bool ok = buckets_fs_list(s->fs, path, &v, &n, err, sizeof(err));
  sftp_trace(T_LIST, "List", path, s->ak, t0, ok ? NULL : err, 0);
  if (!ok) {
    status_fs(m, err);
    return;
  }
  handle *h = new_handle(s, H_LIST, path);
  h->ents = v, h->nents = n;
  ssh_string hs = sftp_handle_alloc(m->sftp, h);
  sftp_reply_handle(m, hs);
  ssh_string_free(hs);
}

static void op_readdir(session *s, sftp_client_message m, handle *h) {
  (void)s;
  if (h->kind != H_LIST) {
    status_err(m, "unexpected dir packet");
    return;
  }
  if (h->next >= h->nents) {
    status(m, SSH_FX_EOF, "EOF");
    return;
  }
  for (size_t k = 0; k < 100 && h->next < h->nents; k++, h->next++) {
    const buckets_fs_info *f = &h->ents[h->next];
    struct sftp_attributes_struct a;
    fill_attrs(&a, f);
    char ln[2048];
    longname(f, ln, sizeof(ln));
    sftp_reply_names_add(m, f->name, ln, &a);
  }
  sftp_reply_names(m);
}

static void *upload_run(void *arg) {
  handle *h = arg;
  session *s = h->sess;
  int64_t t0 = wall_ns(), n = 0;
  char err[1024] = "";
  bool ok = buckets_fs_put(s->fs, h->path, pipe_read, &h->pipe, &n, err, sizeof(err));
  sftp_trace(T_PUT, "Put", h->path, s->ak, t0, ok ? NULL : err, n);
  pthread_mutex_lock(&h->pipe.mu);
  h->pipe.rclosed = true; /* pr.CloseWithError(err) */
  if (!ok) snprintf(h->pipe.rerr, sizeof(h->pipe.rerr), "%s", err);
  pthread_cond_broadcast(&h->pipe.cv);
  pthread_mutex_unlock(&h->pipe.mu);
  return NULL;
}

static void op_open(session *s, sftp_client_message m, const char *path) {
  uint32_t f = m->flags;
  bool rd = f & SSH_FXF_READ, wr = f & SSH_FXF_WRITE, ap = f & SSH_FXF_APPEND, cr = f & SSH_FXF_CREAT,
       tr = f & SSH_FXF_TRUNC;
  char err[1024];
  if (wr || ap || cr || tr) {
    /* Filewrite */
    int64_t t0 = wall_ns();
    char *bucket, *object;
    buckets_fs_split(path, &bucket, &object);
    buckets_fs_info fi;
    bool ok = false;
    if (!wr) snprintf(err, sizeof(err), "invalid argument");
    else if (!*bucket) snprintf(err, sizeof(err), "bucket name cannot be empty");
    else {
      char *bp = buckets_xcalloc(strlen(bucket) + 2, 1);
      snprintf(bp, strlen(bucket) + 2, "/%s", bucket);
      ok = buckets_fs_stat(s->fs, bp, &fi, err, sizeof(err)); /* BucketExists */
      if (ok) free(fi.name);
      free(bp);
    }
    free(bucket);
    free(object);
    if (!ok) {
      sftp_trace(T_PUT, "Put", path, s->ak, t0, err, 0);
      status_fs(m, err);
      return;
    }
    handle *h = new_handle(s, H_WRITE, path);
    pipe_init(&h->pipe);
    h->up_started = pthread_create(&h->up, NULL, upload_run, h) == 0;
    ssh_string hs = sftp_handle_alloc(m->sftp, h);
    sftp_reply_handle(m, hs);
    ssh_string_free(hs);
    return;
  }
  if (!rd) {
    status_err(m, "bad file flags");
    return;
  }
  /* Fileread: GetObject, then its Stat */
  int64_t t0 = wall_ns(), size = 0;
  buckets_http_stream *st = buckets_fs_get(s->fs, path, 0, &size, err, sizeof(err));
  sftp_trace(T_GET, "Get", path, s->ak, t0, st ? NULL : err, 0);
  if (!st) {
    status_fs(m, err);
    return;
  }
  handle *h = new_handle(s, H_READ, path);
  h->st = st, h->pos = 0, h->size = size;
  ssh_string hs = sftp_handle_alloc(m->sftp, h);
  sftp_reply_handle(m, hs);
  ssh_string_free(hs);
}

static void op_read(session *s, sftp_client_message m, handle *h) {
  if (h->kind != H_READ) {
    status_err(m, h->kind == H_WRITE ? "unexpected read packet" : "unexpected read packet");
    return;
  }
  int64_t off = (int64_t)m->offset;
  uint32_t len = m->len > 262144 ? 262144 : m->len;
  if (off >= h->size) {
    status(m, SSH_FX_EOF, "EOF");
    return;
  }
  if (off != h->pos || !h->st) {
    /* a read elsewhere: a new ranged GET, as minio.Object's ReadAt does */
    buckets_http_stream_free(h->st);
    char err[1024];
    int64_t left;
    h->st = buckets_fs_get(s->fs, h->path, off, &left, err, sizeof(err));
    if (!h->st) {
      status_fs(m, err);
      return;
    }
    h->pos = off;
  }
  uint8_t *buf = malloc(len ? len : 1);
  size_t got = 0;
  while (got < len) {
    long k = buckets_http_stream_read(h->st, buf + got, len - got);
    if (k <= 0) break;
    got += (size_t)k;
  }
  h->pos += (int64_t)got;
  if (!got) status(m, SSH_FX_EOF, "EOF");
  else sftp_reply_data(m, buf, (int)got);
  free(buf);
}

/* writerAt.WriteAt */
static bool write_at(handle *h, const uint8_t *b, size_t n, int64_t off, char *err, size_t errlen) {
  if (h->next_off == off) {
    if (!pipe_write(&h->pipe, b, n, err, errlen)) return false;
    h->next_off += (int64_t)n;
  } else {
    if (off > h->next_off + (100 << 20)) {
      snprintf(err, errlen, "write offset %lld is too far ahead of next offset %lld", (long long)off,
               (long long)h->next_off);
      return false;
    }
    h->segs = buckets_xrealloc(h->segs, (h->nsegs + 1) * sizeof(*h->segs));
    h->segs[h->nsegs].off = off;
    h->segs[h->nsegs].b = buckets_xcalloc(n ? n : 1, 1);
    memcpy(h->segs[h->nsegs].b, b, n);
    h->segs[h->nsegs].n = n;
    h->nsegs++;
  }
  for (bool again = true; again;) {
    again = false;
    for (size_t i = 0; i < h->nsegs; i++) {
      if (h->segs[i].off != h->next_off) continue;
      struct wseg sg = h->segs[i];
      h->segs[i] = h->segs[--h->nsegs];
      bool ok = pipe_write(&h->pipe, sg.b, sg.n, err, errlen);
      free(sg.b);
      if (!ok) return false;
      h->next_off += (int64_t)sg.n;
      again = true;
      break;
    }
  }
  return true;
}

static void op_write(session *s, sftp_client_message m, handle *h) {
  (void)s;
  if (h->kind != H_WRITE) {
    status_err(m, "unexpected write packet");
    return;
  }
  char err[1024];
  size_t n = ssh_string_len(m->data);
  if (!write_at(h, ssh_string_data(m->data), n, (int64_t)m->offset, err, sizeof(err))) status_err(m, err);
  else status(m, SSH_FX_OK, "");
}

/* the end of a handle: a write's upload finishes (or is aborted) */
static void handle_close(handle *h, bool transfer_error, char *err, size_t errlen) {
  if (err) *err = '\0';
  if (h->kind == H_READ) buckets_http_stream_free(h->st);
  if (h->kind == H_LIST) buckets_fs_info_free(h->ents, h->nents);
  if (h->kind == H_WRITE) {
    pthread_mutex_lock(&h->pipe.mu);
    if (transfer_error) {
      h->pipe.rclosed = true; /* TransferError: the upload fails, and aborts */
      snprintf(h->pipe.rerr, sizeof(h->pipe.rerr), "unexpected EOF");
    } else if (h->nsegs) {
      h->pipe.rclosed = true;
      snprintf(h->pipe.rerr, sizeof(h->pipe.rerr), "some file segments were not flushed from the queue");
      if (err) snprintf(err, errlen, "some file segments were not flushed from the queue");
    }
    h->pipe.wclosed = true;
    pthread_cond_broadcast(&h->pipe.cv);
    pthread_mutex_unlock(&h->pipe.mu);
    if (h->up_started) pthread_join(h->up, NULL);
    for (size_t i = 0; i < h->nsegs; i++) free(h->segs[i].b);
    free(h->segs);
    pthread_mutex_destroy(&h->pipe.mu);
    pthread_cond_destroy(&h->pipe.cv);
  }
  session *s = h->sess;
  for (size_t i = 0; i < s->nhandles; i++)
    if (s->handles[i] == h) s->handles[i] = s->handles[--s->nhandles];
  free(h->path);
  free(h);
}

static void op_cmd(session *s, sftp_client_message m, const char *method, const char *path) {
  int64_t t0 = wall_ns();
  char err[1024] = "";
  bool ok = false;
  bool unsupported = false;
  if (!strcmp(method, "Setstat") || !strcmp(method, "Rename") || !strcmp(method, "Link") ||
      !strcmp(method, "Symlink")) {
    unsupported = true;
    snprintf(err, sizeof(err), "operation unsupported");
  } else if (!strcmp(method, "Rmdir")) {
    ok = buckets_fs_rmdir(s->fs, path, err, sizeof(err));
  } else if (!strcmp(method, "Remove")) {
    ok = buckets_fs_delete(s->fs, path, err, sizeof(err));
  } else if (!strcmp(method, "Mkdir")) {
    ok = buckets_fs_mkdir(s->fs, path, err, sizeof(err));
  }
  sftp_trace(T_CMD, method, path, s->ak, t0, ok ? NULL : err, 0);
  if (ok) status(m, SSH_FX_OK, "");
  else if (unsupported) status(m, SSH_FX_OP_UNSUPPORTED, err);
  else status_fs(m, err);
}

static handle *get_handle(session *s, sftp_client_message m) {
  handle *h = m->handle ? sftp_handle(m->sftp, m->handle) : NULL;
  for (size_t i = 0; h && i < s->nhandles; i++)
    if (s->handles[i] == h) return h;
  return NULL;
}

static void serve_sftp(session *s) {
  sftp_session sftp = sftp_server_new(s->ssh, s->chan);
  if (!sftp) return;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  if (sftp_server_init(sftp) != 0) {
    sftp_server_free(sftp);
    return;
  }
#pragma GCC diagnostic pop
#pragma clang diagnostic pop
  s->fs = buckets_fs_open_creds(s->ak, s->sk, s->token, s->remote_ip);
  sftp_client_message m;
  while ((m = sftp_get_client_message(sftp)) != NULL) {
    const char *fn = m->filename ? m->filename : "";
    char *p = NULL;
    handle *h;
    switch (m->type) {
    case SSH_FXP_REALPATH:
      p = clean_path(fn);
      sftp_reply_name(m, p, NULL);
      break;
    case SSH_FXP_STAT:
    case SSH_FXP_LSTAT:
      p = clean_path(fn);
      op_stat(s, m, p);
      break;
    case SSH_FXP_FSTAT:
      if (!(h = get_handle(s, m))) status_err(m, "bad file descriptor");
      else p = clean_path(h->path), op_stat(s, m, p);
      break;
    case SSH_FXP_OPENDIR:
      p = clean_path(fn);
      op_opendir(s, m, p);
      break;
    case SSH_FXP_READDIR:
      if (!(h = get_handle(s, m))) status_err(m, "bad file descriptor");
      else op_readdir(s, m, h);
      break;
    case SSH_FXP_OPEN:
      p = clean_path(fn);
      op_open(s, m, p);
      break;
    case SSH_FXP_READ:
      if (!(h = get_handle(s, m))) status_err(m, "bad file descriptor");
      else op_read(s, m, h);
      break;
    case SSH_FXP_WRITE:
      if (!(h = get_handle(s, m))) status_err(m, "bad file descriptor");
      else op_write(s, m, h);
      break;
    case SSH_FXP_CLOSE:
      if (!(h = get_handle(s, m))) {
        status_err(m, "bad file descriptor");
      } else {
        char err[512];
        sftp_handle_remove(sftp, h);
        handle_close(h, false, err, sizeof(err));
        if (*err) status_err(m, err);
        else status(m, SSH_FX_OK, "");
      }
      break;
    case SSH_FXP_SETSTAT:
      p = clean_path(fn);
      op_cmd(s, m, "Setstat", p);
      break;
    case SSH_FXP_FSETSTAT:
      if (!(h = get_handle(s, m))) status_err(m, "bad file descriptor");
      else p = clean_path(h->path), op_cmd(s, m, "Setstat", p);
      break;
    case SSH_FXP_REMOVE:
      p = clean_path(fn);
      op_cmd(s, m, "Remove", p);
      break;
    case SSH_FXP_MKDIR:
      p = clean_path(fn);
      op_cmd(s, m, "Mkdir", p);
      break;
    case SSH_FXP_RMDIR:
      p = clean_path(fn);
      op_cmd(s, m, "Rmdir", p);
      break;
    case SSH_FXP_RENAME:
      p = clean_path(fn);
      op_cmd(s, m, "Rename", p);
      break;
    case SSH_FXP_SYMLINK:
      p = clean_path(fn);
      op_cmd(s, m, "Symlink", p);
      break;
    case SSH_FXP_READLINK: {
      /* no ReadlinkFileLister: Filelist, whose methods do not include it */
      p = clean_path(fn);
      int64_t t0 = wall_ns();
      sftp_trace(T_LIST, "Readlink", p, s->ak, t0, NULL, 0);
      status_err(m, "");
      break;
    }
    case SSH_FXP_EXTENDED: {
      const char *sub = m->submessage ? m->submessage : "";
      p = clean_path(fn);
      if (!strcmp(sub, "posix-rename@openssh.com")) op_cmd(s, m, "Rename", p);
      else if (!strcmp(sub, "hardlink@openssh.com")) op_cmd(s, m, "Link", p);
      else status(m, SSH_FX_OP_UNSUPPORTED, "operation unsupported");
      break;
    }
    default:
      status(m, SSH_FX_OP_UNSUPPORTED, "operation unsupported");
    }
    free(p);
    sftp_client_message_free(m);
  }
  /* the connection ended: open uploads fail (and abort) */
  while (s->nhandles) {
    handle *hh = s->handles[0];
    sftp_handle_remove(sftp, hh);
    handle_close(hh, true, NULL, 0);
  }
  sftp_server_free(sftp);
}

/* ---- SSH: authentication and the sftp subsystem ---- */

static bool key_matches(void *ud, const char *line) {
  session *s = ud;
  char *copy = buckets_xstrdup(line);
  char *type = strtok(copy, " \t"), *b64 = type ? strtok(NULL, " \t\r\n") : NULL;
  bool ok = false;
  ssh_key k = NULL;
  if (b64 && ssh_pki_import_pubkey_base64(b64, ssh_key_type_from_name(type), &k) == SSH_OK)
    ok = ssh_key_cmp(k, s->auth_key, SSH_KEY_CMP_PUBLIC) == 0;
  ssh_key_free(k);
  free(copy);
  return ok;
}

static bool cert_trusted(void *ud, const char *user) {
  session *s = ud;
  (void)user; /* CertChecker uses the connection's user name, suffix and all */
  return buckets_sshcert_trusted(s->auth_key, g_srv.ca, s->login_user, s->remote_ip);
}

static void set_creds(session *s, char *ak, char *sk, char *token) {
  free(s->ak), free(s->sk), free(s->token);
  s->ak = ak, s->sk = sk, s->token = token;
}

static int auth_password(ssh_session ssh, const char *user, const char *password, void *ud) {
  (void)ssh;
  session *s = ud;
  if (g_srv.o.no_password) return SSH_AUTH_DENIED;
  buckets_fs_ssh_auth a = {.password = password, .ud = s};
  char *ak, *sk, *token, err[512];
  if (!buckets_fs_ssh_login(user, &a, &ak, &sk, &token, err, sizeof(err))) return SSH_AUTH_DENIED;
  set_creds(s, ak, sk, token);
  free(s->user);
  s->user = buckets_xstrdup(user);
  s->authed = true;
  return SSH_AUTH_SUCCESS;
}

static int auth_pubkey(ssh_session ssh, const char *user, struct ssh_key_struct *key, char state, void *ud) {
  (void)ssh;
  session *s = ud;
  s->auth_key = key;
  s->login_user = user;
  buckets_fs_ssh_auth a = {.password = NULL, .key_matches = key_matches, .cert_trusted = g_srv.ca ? cert_trusted : NULL,
                           .ud = s};
  char *ak, *sk, *token, err[512];
  bool ok = buckets_fs_ssh_login(user, &a, &ak, &sk, &token, err, sizeof(err));
  s->auth_key = NULL;
  if (!ok) return SSH_AUTH_DENIED;
  if (state == SSH_PUBLICKEY_STATE_NONE) { /* a query: the key would do */
    free(ak), free(sk), free(token);
    return SSH_AUTH_SUCCESS;
  }
  if (state != SSH_PUBLICKEY_STATE_VALID) {
    free(ak), free(sk), free(token);
    return SSH_AUTH_DENIED;
  }
  set_creds(s, ak, sk, token);
  free(s->user);
  s->user = buckets_xstrdup(user);
  s->authed = true;
  return SSH_AUTH_SUCCESS;
}

static int subsystem_request(ssh_session ssh, ssh_channel chan, const char *subsystem, void *ud) {
  (void)ssh, (void)chan;
  session *s = ud;
  if (strcmp(subsystem, "sftp") != 0) return 1;
  s->want_sftp = true;
  return 0;
}

static struct ssh_channel_callbacks_struct g_chan_cb = {.channel_subsystem_request_function = subsystem_request};

static ssh_channel open_session(ssh_session ssh, void *ud) {
  session *s = ud;
  if (!s->authed || s->chan) return NULL;
  s->chan = ssh_channel_new(ssh);
  struct ssh_channel_callbacks_struct *cb = s->chan_cb = buckets_xcalloc(1, sizeof(*cb));
  *cb = g_chan_cb;
  cb->userdata = s;
  ssh_callbacks_init(cb);
  ssh_set_channel_callbacks(s->chan, cb);
  return s->chan;
}

static void *session_run(void *arg) {
  session *s = arg;
  struct ssh_server_callbacks_struct cb = {
      .userdata = s,
      .auth_password_function = auth_password,
      .auth_pubkey_function = auth_pubkey,
      .channel_open_request_session_function = open_session,
  };
  ssh_callbacks_init(&cb);
  ssh_set_server_callbacks(s->ssh, &cb);
  int methods = SSH_AUTH_METHOD_PUBLICKEY | (g_srv.o.no_password ? 0 : SSH_AUTH_METHOD_PASSWORD);
  ssh_set_auth_methods(s->ssh, methods);
  if (ssh_handle_key_exchange(s->ssh) == SSH_OK) {
    ssh_event ev = ssh_event_new();
    ssh_event_add_session(ev, s->ssh);
    time_t deadline = time(NULL) + 120; /* SSHHandshakeDeadline */
    while (!s->want_sftp && time(NULL) < deadline && ssh_is_connected(s->ssh)) {
      if (ssh_event_dopoll(ev, 200) == SSH_ERROR) break;
    }
    ssh_event_remove_session(ev, s->ssh);
    ssh_event_free(ev);
    if (s->want_sftp && s->chan) serve_sftp(s);
  }
  buckets_fs_close(s->fs);
  if (s->chan) {
    ssh_channel_send_eof(s->chan);
    ssh_channel_close(s->chan);
    ssh_channel_free(s->chan);
  }
  ssh_disconnect(s->ssh);
  ssh_free(s->ssh);
  free(s->chan_cb);
  free(s->handles);
  free(s->user);
  free(s->ak), free(s->sk), free(s->token);
  free(s);
  return NULL;
}

static void *accept_run(void *arg) {
  (void)arg;
  for (;;) {
    ssh_session ssh = ssh_new();
    if (!ssh) break;
    if (ssh_bind_accept(g_srv.bind, ssh) != SSH_OK) {
      ssh_free(ssh);
      continue;
    }
    session *s = buckets_xcalloc(1, sizeof(*s));
    s->ssh = ssh;
    struct sockaddr_storage peer;
    socklen_t pl = sizeof(peer);
    if (getpeername(ssh_get_fd(ssh), (struct sockaddr *)&peer, &pl) == 0) {
      if (peer.ss_family == AF_INET6) {
        struct sockaddr_in6 *a = (void *)&peer;
        if (IN6_IS_ADDR_V4MAPPED(&a->sin6_addr)) inet_ntop(AF_INET, &a->sin6_addr.s6_addr[12], s->remote_ip, sizeof(s->remote_ip));
        else inet_ntop(AF_INET6, &a->sin6_addr, s->remote_ip, sizeof(s->remote_ip));
      } else {
        inet_ntop(AF_INET, &((struct sockaddr_in *)&peer)->sin_addr, s->remote_ip, sizeof(s->remote_ip));
      }
    }
    pthread_t t;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &at, session_run, s) != 0) {
      ssh_free(ssh);
      free(s);
    }
    pthread_attr_destroy(&at);
  }
  return NULL;
}

static void join_default(const char *const *set, char *out, size_t cap) {
  buckets_buf b = BUCKETS_BUF_INIT;
  for (size_t i = 0; set[i]; i++)
    if (in_set(k_libssh_algos, set[i])) buckets_buf_appendf(&b, "%s%s", b.len ? "," : "", set[i]);
  snprintf(out, cap, "%s", b.data ? b.data : "");
  buckets_buf_free(&b);
}

bool buckets_sftp_start(buckets_sftp_opts *o, char *err, size_t errlen) {
  g_srv.o = *o;
  ssh_init();
  ssh_key host = NULL;
  if (access(o->key_file, R_OK) != 0) {
    snprintf(err, errlen, "invalid arguments passed, private key file is not accessible: open %s: %s", o->key_file,
             strerror(errno));
    return false;
  }
  if (ssh_pki_import_privkey_file(o->key_file, NULL, NULL, NULL, &host) != SSH_OK) {
    snprintf(err, errlen, "invalid arguments passed, private key file is not parseable: ssh: no key found");
    return false;
  }
  if (o->ca_file && *o->ca_file) {
    if (access(o->ca_file, R_OK) != 0) {
      snprintf(err, errlen,
               "invalid arguments passed, trusted user certificate authority public key file is not accessible: "
               "open %s: %s",
               o->ca_file, strerror(errno));
      return false;
    }
    if (ssh_pki_import_pubkey_file(o->ca_file, &g_srv.ca) != SSH_OK) {
      snprintf(err, errlen, "invalid arguments passed, trusted user certificate authority public key file is not "
                            "parseable: ssh: no key found");
      return false;
    }
  }
  g_srv.bind = ssh_bind_new();
  int port = o->port;
  ssh_bind_options_set(g_srv.bind, SSH_BIND_OPTIONS_BINDPORT, &port);
  ssh_bind_options_set(g_srv.bind, SSH_BIND_OPTIONS_IMPORT_KEY, host);
  char kex[1024], ciphers[1024], macs[1024], pubs[2048];
  join_default(k_kex_preferred, kex, sizeof(kex));
  join_default(k_cipher_preferred, ciphers, sizeof(ciphers));
  join_default(k_mac_supported, macs, sizeof(macs));
  join_default(k_pubkey_supported, pubs, sizeof(pubs));
  const char *K = o->kex_algos ? o->kex_algos : kex, *C = o->cipher_algos ? o->cipher_algos : ciphers,
             *M = o->mac_algos ? o->mac_algos : macs;
  /* certificates for every key type allowed: a trusted CA's user certificates */
  buckets_buf pk = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&pk, o->pub_key_algos ? o->pub_key_algos : pubs);
  static const char *const certs[][2] = {{"ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"},
                                         {"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256-cert-v01@openssh.com"},
                                         {"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384-cert-v01@openssh.com"},
                                         {"ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521-cert-v01@openssh.com"},
                                         {"rsa-sha2-256", "rsa-sha2-256-cert-v01@openssh.com"},
                                         {"rsa-sha2-512", "rsa-sha2-512-cert-v01@openssh.com"}};
  for (size_t i = 0; i < sizeof(certs) / sizeof(certs[0]); i++)
    if (strstr(pk.data, certs[i][0])) buckets_buf_appendf(&pk, ",%s", certs[i][1]);
  if ((*K && ssh_bind_options_set(g_srv.bind, SSH_BIND_OPTIONS_KEY_EXCHANGE, K) != SSH_OK) ||
      (*C && (ssh_bind_options_set(g_srv.bind, SSH_BIND_OPTIONS_CIPHERS_C_S, C) != SSH_OK ||
              ssh_bind_options_set(g_srv.bind, SSH_BIND_OPTIONS_CIPHERS_S_C, C) != SSH_OK)) ||
      (*M && (ssh_bind_options_set(g_srv.bind, SSH_BIND_OPTIONS_HMAC_C_S, M) != SSH_OK ||
              ssh_bind_options_set(g_srv.bind, SSH_BIND_OPTIONS_HMAC_S_C, M) != SSH_OK)) ||
      ssh_bind_options_set(g_srv.bind, SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES, pk.data) != SSH_OK) {
    snprintf(err, errlen, "Unable to start SFTP Server: %s", ssh_get_error(g_srv.bind));
    buckets_buf_free(&pk);
    return false;
  }
  buckets_buf_free(&pk);
  if (ssh_bind_listen(g_srv.bind) != SSH_OK) {
    snprintf(err, errlen, "SFTP Server had an unrecoverable error while accepting connections: %s",
             ssh_get_error(g_srv.bind));
    return false;
  }
  pthread_t t;
  if (pthread_create(&t, NULL, accept_run, NULL) != 0) {
    snprintf(err, errlen, "Unable to start SFTP Server");
    return false;
  }
  pthread_detach(t);
  const char *ip = o->public_ip ? o->public_ip : "";
  buckets_log_info("Buckets SFTP Server listening on %s%s%s:%d", strchr(ip, ':') ? "[" : "", ip,
                   strchr(ip, ':') ? "]" : "", o->port);
  return true;
}
