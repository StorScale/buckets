/* bucketsd - Buckets storage server.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include "config/config.h"
#include "core/log.h"
#include "dist/dsync.h"
#include "dist/endpoint.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "admin/admin.h"
#include "ftp/ftp.h"
#include "ftp/s3fs.h"
#include "ftp/sftp.h"
#include "admin/info.h"
#include "dist/storage_server.h"
#include "storage/remote.h"
#include "storage/xlmeta.h"
#include "core/pool.h"
#include "core/loop.h"
#include "net/http.h"
#include "s3/server.h"
#include "trace/trace.h"
#include "erasure/layout.h"
#include "heal/healer.h"
#include "scanner/scanner.h"
#include "object/object.h"
#include "storage/drive.h"
#include "storage/format.h"

#ifndef BUCKETS_VERSION
#define BUCKETS_VERSION "dev"
#endif

#define DEFAULT_ROOT_USER "minioadmin"
#define DEFAULT_ROOT_PASSWORD "minioadmin"
#define SHUTDOWN_GRACE_SECONDS 10
/* MinIO's limits: 5 TiB per PUT (globalMaxObjectSize); 1 MiB stays in memory. */
#define MAX_BODY_BYTES (5LL * 1024 * 1024 * 1024 * 1024)
#define MEM_BODY_BYTES (1u * 1024 * 1024)

static buckets_loop *g_loop;
static volatile sig_atomic_t g_signal;
static atomic_bool g_restart; /* mc admin service restart: exec ourselves after draining */

/* mc admin service restart|stop: drain as on SIGTERM (the admin response
 * goes out first), then exit or re-exec. */
static void on_service(void *ud, const char *action) {
  (void)ud;
  if (strcmp(action, "restart") == 0) atomic_store(&g_restart, true);
  else if (strcmp(action, "stop") != 0) return;
  g_signal = SIGTERM;
  if (g_loop) buckets_loop_wake(g_loop);
}

typedef struct {
  buckets_http_server *http;
  bool draining;
  time_t drain_deadline;
} app_state;

static void on_signal(int sig) {
  g_signal = sig;
  if (g_loop) buckets_loop_wake(g_loop);
}

static void on_wake(buckets_loop *loop, void *ud) {
  app_state *app = ud;
  if (!g_signal || app->draining) return;
  buckets_log_info("received signal %d, draining connections", (int)g_signal);
  app->draining = true;
  app->drain_deadline = time(NULL) + SHUTDOWN_GRACE_SECONDS;
  buckets_http_server_shutdown(app->http);
  if (buckets_http_server_connections(app->http) == 0) buckets_loop_stop(loop);
}

static void on_tick(buckets_loop *loop, void *ud) {
  app_state *app = ud;
  if (!app->draining) return;
  size_t open = buckets_http_server_connections(app->http);
  if (open == 0 || time(NULL) >= app->drain_deadline) {
    if (open) buckets_log_warn("shutdown grace period elapsed with %zu connections open", open);
    buckets_loop_stop(loop);
  }
}

/* BUCKETS_* wins; MINIO_* is honored so existing deployments can switch over. */
static const char *env2(const char *primary, const char *compat) {
  const char *v = getenv(primary);
  if (v && *v) return v;
  v = getenv(compat);
  return (v && *v) ? v : NULL;
}

/* A secret from <NAME>_FILE (a mounted Kubernetes or Docker secret) when set,
 * else from <NAME>, with the MINIO_* fallback for both. Trailing newlines in
 * the file are dropped. The result is never freed (it lives for the process). */
static const char *env_secret(const char *primary, const char *compat) {
  char pf[128], cf[128];
  snprintf(pf, sizeof(pf), "%s_FILE", primary);
  snprintf(cf, sizeof(cf), "%s_FILE", compat);
  const char *path = env2(pf, cf);
  if (!path) return env2(primary, compat);
  FILE *f = fopen(path, "r");
  if (!f) {
    buckets_log_error("cannot read %s: %s", path, strerror(errno));
    exit(1);
  }
  char *buf = buckets_xcalloc(1, 4096);
  size_t n = fread(buf, 1, 4095, f);
  fclose(f);
  while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
  return buf;
}

static void usage(FILE *f) {
  fprintf(f,
          "Usage: bucketsd server [--address [HOST]:PORT] [--certs-dir DIR] [--ftp KEY=VALUE]... DRIVE...\n"
          "  DRIVE may use MinIO ellipses, e.g. /mnt/disk{1...16}; each ellipsis argument is a pool\n"
          "  --certs-dir: public.crt + private.key enable HTTPS (default ~/.buckets/certs,\n"
          "               then ~/.minio/certs); subdirectories add certificates chosen by SNI\n"
          "  --ftp:       serve FTP (MinIO's --ftp keys: address=[HOST]:PORT, passive-port-range=LO-HI,\n"
          "               tls-private-key=FILE, tls-public-cert=FILE, force-tls=BOOL); repeat per key\n"
          "  --sftp:      serve SFTP (MinIO's --sftp keys: address, ssh-private-key=FILE (required),\n"
          "               pub-key-algos, kex-algos, cipher-algos, mac-algos, trusted-user-ca-key=FILE,\n"
          "               disable-password-auth=BOOL)\n"
          "\n"
          "Environment:\n"
          "  BUCKETS_ROOT_USER / MINIO_ROOT_USER          root access key (default minioadmin)\n"
          "  BUCKETS_ROOT_PASSWORD / MINIO_ROOT_PASSWORD  root secret key (default minioadmin)\n"
          "  BUCKETS_REGION / MINIO_REGION                server region (default: accept any)\n"
          "  BUCKETS_VOLUMES / MINIO_VOLUMES              drives, space separated, when none are given\n"
          "  *_ROOT_USER_FILE / *_ROOT_PASSWORD_FILE      read the root credentials from files\n"
          "  BUCKETS_CONFIG_ENV_FILE / MINIO_CONFIG_ENV_FILE  a file of KEY=value lines (\"export\" allowed) that\n"
          "                                               override the environment\n"
          "  BUCKETS_XL_META_VERSION                      3 (default), or 2 for drives MinIO before\n"
          "                                               RELEASE.2024-10-29 must still read (a rollback)\n"
          "  BUCKETS_LOG_LEVEL                            debug|info|warn|error\n"
          "  BUCKETS_API_THREADS                          request handler threads (default: 2 x CPUs, min 8)\n"
          "  BUCKETS_NET_THREADS                          network loop threads (default: CPUs / 2, max 16)\n"
          "  BUCKETS_IO_THREADS                           drive I/O threads (default: set size + 2)\n");
}

/* globalMinioEndpoint, else getAPIEndpoints()[0]: MINIO_SERVER_URL, else the
 * --address host, else the local IPv4 sortIPs puts first (non-loopback,
 * highest last octet). */
static void origin_endpoint(char *out, size_t cap, const char *host, int port, bool tls) {
  const char *url = getenv("BUCKETS_SERVER_URL");
  if (!url || !*url) url = getenv("MINIO_SERVER_URL");
  if (url && *url) {
    snprintf(out, cap, "%s", url);
    size_t n = strlen(out);
    const char *p = strstr(out, "://");
    char *slash = p ? strchr(p + 3, '/') : NULL;
    if (slash) *slash = '\0';
    else if (n && out[n - 1] == '/') out[n - 1] = '\0';
    return;
  }
  char best[INET_ADDRSTRLEN] = "127.0.0.1";
  if (!host || !*host) {
    struct ifaddrs *ifs = NULL;
    int best_octet = -1;
    if (getifaddrs(&ifs) == 0) {
      for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in sin;
        memcpy(&sin, i->ifa_addr, sizeof(sin));
        const uint8_t *b = (const uint8_t *)&sin.sin_addr;
        if (b[0] == 127) continue;
        if (b[3] > best_octet) {
          best_octet = b[3];
          inet_ntop(AF_INET, &sin.sin_addr, best, sizeof(best));
        }
      }
      freeifaddrs(ifs);
    }
    host = best;
  }
  bool v6 = strchr(host, ':') != NULL;
  snprintf(out, cap, "%s://%s%s%s:%d", tls ? "https" : "http", v6 ? "[" : "", host, v6 ? "]" : "", port);
}

static bool parse_address(const char *addr, char **host, int *port) {
  const char *colon = strrchr(addr, ':');
  if (!colon) return false;
  char *end = NULL;
  long p = strtol(colon + 1, &end, 10);
  if (*end || p < 0 || p > 65535) return false;
  const char *h = addr;
  size_t hn = (size_t)(colon - addr);
  if (hn >= 2 && h[0] == '[' && h[hn - 1] == ']') { /* [::1]:9000 */
    h++;
    hn -= 2;
  }
  *host = buckets_xstrndup(h, hn);
  *port = (int)p;
  return true;
}


/* ---- topology & bootstrap -------------------------------------------------- */

typedef struct {
  char *key; /* host:port */
  bool secure;
  char *host;
  int port;
  buckets_http_client *client;
} peer;

typedef struct {
  int port;
  size_t npools;
  buckets_pool_layout *layouts;
  buckets_endpoint **eps; /* per pool, per drive (distributed only) */
  bool distributed, secure;
  int parity;
  peer *peers;
  size_t npeers;
  buckets_tls_client *tls_client;
  buckets_drive **local_drives; /* served to peers; separate from the layer's */
  size_t nlocal;
  const char *first_local; /* path of a local drive, for spooling */
  buckets_lock_server *lock_server;
  buckets_dsync *dsync;
  char **cmdlines; /* each pool's command-line argument (MinIO's CmdLine) */
  bool legacy;     /* drives given without ellipses */
} topology;

/* The deployment's nodes and drive endpoints, for the admin API. */
static buckets_cluster_info *cluster_describe(const topology *t, const char *host, bool secure) {
  buckets_cluster_info *ci = buckets_xcalloc(1, sizeof(*ci));
  ci->secure = secure;
  ci->distributed = t->distributed;
  ci->started = time(NULL);
  size_t total = 0;
  for (size_t p = 0; p < t->npools; p++) total += t->layouts[p].ndrives;
  ci->eps = buckets_xcalloc(total ? total : 1, sizeof(*ci->eps));
  ci->nodes = buckets_xcalloc(total + 1, sizeof(char *));
  char self[300];
  snprintf(self, sizeof(self), "%s:%d", host && *host ? host : "127.0.0.1", t->port);
  for (size_t p = 0; p < t->npools; p++) {
    for (size_t i = 0; i < t->layouts[p].ndrives; i++) {
      buckets_info_endpoint *ep = &ci->eps[ci->neps++];
      ep->pool = p;
      if (t->distributed) {
        const buckets_endpoint *e = &t->eps[p][i];
        char node[300];
        snprintf(node, sizeof(node), "%s:%d", e->host, e->port);
        ep->endpoint = buckets_xstrdup(e->url);
        ep->path = buckets_xstrdup(e->path);
        ep->node = buckets_xstrdup(node);
        ep->local = e->local;
        if (e->local) snprintf(self, sizeof(self), "%s", node);
      } else {
        ep->endpoint = buckets_xstrdup(t->layouts[p].drives[i]);
        ep->path = buckets_xstrdup(t->layouts[p].drives[i]);
        ep->local = true;
      }
      bool seen = false;
      for (size_t k = 0; k < ci->nnodes && ep->node; k++) seen |= strcmp(ci->nodes[k], ep->node) == 0;
      if (ep->node && !seen) ci->nodes[ci->nnodes++] = buckets_xstrdup(ep->node);
    }
  }
  ci->self = buckets_xstrdup(self);
  for (size_t i = 0; i < ci->neps; i++) {
    if (!ci->eps[i].node) ci->eps[i].node = buckets_xstrdup(self);
  }
  if (!ci->nnodes) ci->nodes[ci->nnodes++] = buckets_xstrdup(self);
  return ci;
}

static peer *peer_for(topology *t, const buckets_endpoint *e) {
  for (size_t i = 0; i < t->npeers; i++) {
    if (strcmp(t->peers[i].host, e->host) == 0 && t->peers[i].port == e->port) return &t->peers[i];
  }
  return NULL;
}

/* Parses the URL endpoints and works out which are this node's. */
static bool topology_resolve(topology *t) {
  char err[512];
  size_t nlocal_eps = 0, nsecure = 0, n = 0;
  for (size_t p = 0; p < t->npools; p++) {
    t->eps[p] = buckets_xcalloc(t->layouts[p].ndrives, sizeof(buckets_endpoint));
    for (size_t i = 0; i < t->layouts[p].ndrives; i++) {
      buckets_endpoint *e = &t->eps[p][i];
      if (!buckets_endpoint_parse(t->layouts[p].drives[i], t->port, e, err, sizeof(err))) {
        buckets_log_error("%s", err);
        return false;
      }
      buckets_endpoint_resolve_local(e, t->port);
      nlocal_eps += e->local;
      nsecure += e->secure;
      n++;
      if (!e->local && !peer_for(t, e)) {
        t->peers = buckets_xrealloc(t->peers, (t->npeers + 1) * sizeof(peer));
        peer *pr = &t->peers[t->npeers++];
        memset(pr, 0, sizeof(*pr));
        pr->host = buckets_xstrdup(e->host);
        pr->port = e->port;
        pr->secure = e->secure;
      }
    }
  }
  if (!nlocal_eps) {
    buckets_log_error("none of the endpoints is on this server (port %d); check --address", t->port);
    return false;
  }
  if (nsecure && nsecure != n) {
    buckets_log_error("endpoints must all be http:// or all https://");
    return false;
  }
  t->secure = nsecure > 0;
  t->local_drives = buckets_xcalloc(nlocal_eps, sizeof(buckets_drive *));
  for (size_t p = 0; p < t->npools; p++) {
    for (size_t i = 0; i < t->layouts[p].ndrives; i++) {
      buckets_endpoint *e = &t->eps[p][i];
      if (!e->local) continue;
      if (buckets_drive_open_raw(e->path, &t->local_drives[t->nlocal]) == BUCKETS_DRIVE_OK) {
        if (!t->first_local) t->first_local = t->local_drives[t->nlocal]->root;
        t->nlocal++;
      } else {
        buckets_log_warn("drive %s is unavailable; continuing without it", e->path);
      }
    }
  }
  if (!t->first_local) {
    buckets_log_error("no local drive is usable");
    return false;
  }
  t->lock_server = buckets_lock_server_new();
  return true;
}

static void topology_connect(topology *t) {
  buckets_http_client **clients = buckets_xcalloc(t->npeers ? t->npeers : 1, sizeof(*clients));
  for (size_t i = 0; i < t->npeers; i++) {
    t->peers[i].client = buckets_http_client_new(t->peers[i].host, t->peers[i].port,
                                                 t->peers[i].secure ? t->tls_client : NULL, 10000);
    clients[i] = t->peers[i].client;
  }
  t->dsync = buckets_dsync_new(clients, t->npeers, t->lock_server);
  free(clients);
}

static void topology_free(topology *t) {
  for (size_t p = 0; p < t->npools; p++) {
    for (size_t i = 0; t->eps[p] && i < t->layouts[p].ndrives; i++) buckets_endpoint_free(&t->eps[p][i]);
    free(t->eps[p]);
    buckets_layout_free(&t->layouts[p]);
  }
  free(t->eps);
  free(t->layouts);
  for (size_t i = 0; i < t->npeers; i++) {
    buckets_http_client_free(t->peers[i].client);
    free(t->peers[i].host);
  }
  free(t->peers);
  for (size_t i = 0; i < t->nlocal; i++) buckets_drive_close(t->local_drives[i]);
  free(t->local_drives);
  buckets_lock_server_free(t->lock_server);
}

/* A pool's drives for one negotiation attempt: local paths opened raw,
 * remote ones as RPC handles (reachable or not). */
static buckets_drive **open_pool(topology *t, size_t p) {
  buckets_pool_layout *l = &t->layouts[p];
  buckets_drive **drives = buckets_xcalloc(l->ndrives, sizeof(buckets_drive *));
  for (size_t i = 0; i < l->ndrives; i++) {
    const char *path = t->distributed ? t->eps[p][i].path : l->drives[i];
    if (t->distributed && !t->eps[p][i].local) {
      drives[i] = buckets_drive_open_remote(peer_for(t, &t->eps[p][i])->client, path, t->eps[p][i].url);
    } else if (buckets_drive_open_raw(path, &drives[i]) != BUCKETS_DRIVE_OK) {
      buckets_log_warn("drive %s is unavailable; continuing without it", path);
      drives[i] = NULL;
    } else if (t->distributed) {
      free(drives[i]->root); /* log local drives by URL too */
      drives[i]->root = buckets_xstrdup(path);
    }
  }
  return drives;
}

typedef struct {
  topology *topo;
  buckets_s3_server *s3;
  buckets_objlayer *layer;
  buckets_healer *healer;
  buckets_scanner *scanner;
  atomic_bool stop;
} boot_state;

/* The cluster's leader lock (MinIO's globalLeaderLock, a sharedLock on
 * .minio.sys/leader.lock): one node holds it for good, and another takes
 * it over if that node goes away and its lock expires. */
typedef struct {
  buckets_dsync *d;
  atomic_bool stop, held;
  pthread_t thread;
  bool started;
} leader_lock;
static leader_lock g_leader;

static void *leader_run(void *arg) {
  leader_lock *l = arg;
  while (!atomic_load(&l->stop)) {
    void *h = buckets_dsync_lock_src(l->d, BUCKETS_META_BUCKET "/leader.lock", true, 2000,
                                     "[shared-lock.go:38:sharedLock.backgroundRoutine()]");
    if (!h) { /* too few lock servers answer, which fails at once: wait before retrying */
      for (int i = 0; i < 10 && !atomic_load(&l->stop); i++) {
        struct timespec ts = {0, 100000000L};
        nanosleep(&ts, NULL);
      }
      continue;
    }
    atomic_store(&l->held, true);
    while (!atomic_load(&l->stop)) {
      struct timespec ts = {0, 100000000L};
      nanosleep(&ts, NULL);
    }
    atomic_store(&l->held, false);
    buckets_dsync_unlock(l->d, h);
  }
  return NULL;
}

static void leader_start(leader_lock *l, buckets_dsync *d) {
  l->d = d;
  if (pthread_create(&l->thread, NULL, leader_run, l) != 0) buckets_fatal("start leader lock");
  l->started = true;
}

static void leader_stop(leader_lock *l) {
  if (!l->started) return;
  atomic_store(&l->stop, true);
  pthread_join(l->thread, NULL);
  l->started = false;
}

/* The endless request bodies of the network speedtests are streamed. */
static bool stream_chunked(buckets_str path) {
  return buckets_str_eq_c(path, "/minio/admin/v3/speedtest/client/devnull") ||
         buckets_str_eq_c(path, "/minio/admin/v3/site-replication/devnull");
}

static void *dsync_lock_fn(void *ud, const char *res, bool write, int timeout_ms) {
  return buckets_dsync_lock(ud, res, write, timeout_ms);
}
static void dsync_unlock_fn(void *ud, void *h) { buckets_dsync_unlock(ud, h); }

/* Negotiates every pool's format (retrying while peers come up, in a
 * cluster), then builds the object layer and publishes it. */
static bool bootstrap(boot_state *b) {
  topology *t = b->topo;
  buckets_format_result *fr = buckets_xcalloc(t->npools, sizeof(*fr));
  char err[512], last_err[512] = "";
  time_t last_log = 0;
  size_t p = 0;
  while (p < t->npools) {
    if (atomic_load(&b->stop)) {
      for (size_t q = 0; q < p; q++) buckets_format_result_free(&fr[q]);
      free(fr);
      return false;
    }
    buckets_drive **drives = open_pool(t, p);
    /* In a cluster only the node owning a pool's first endpoint formats it. */
    buckets_format_opts opts = {.may_format_fresh = !t->distributed || t->eps[p][0].local};
    bool ok = buckets_format_negotiate(drives, t->layouts[p].ndrives, t->layouts[p].set_size,
                                       p ? fr[0].deployment_id : NULL, &opts, &fr[p], err, sizeof(err));
    free(drives);
    if (ok) {
      p++;
      continue;
    }
    if (!t->distributed || opts.fatal) {
      buckets_log_error("%s%s", t->npools > 1 ? "pool: " : "", err);
      if (t->distributed) exit(1); /* waiting will not fix a foreign or mismatched layout */
      for (size_t q = 0; q < p; q++) buckets_format_result_free(&fr[q]);
      free(fr);
      return false;
    }
    if (strcmp(err, last_err) != 0 || time(NULL) - last_log >= 5) {
      buckets_log_info("%s", err);
      snprintf(last_err, sizeof(last_err), "%s", err);
      last_log = time(NULL);
    }
    struct timespec ts = {0, 500 * 1000000L};
    nanosleep(&ts, NULL);
  }
  buckets_objlayer *layer = buckets_objlayer_new(fr, t->npools, t->parity);
  if (t->dsync) buckets_objlayer_set_locker(layer, dsync_lock_fn, dsync_unlock_fn, t->dsync);
  buckets_objlayer_set_cmdlines(layer, t->cmdlines, t->npools);
  layer->legacy = t->legacy;
  size_t first = 0, total = 0;
  for (size_t q = 0; q < t->npools; q++) {
    buckets_drive_place pl;
    buckets_objlayer_place(layer, first, &pl);
    buckets_log_info("%s%zu drive%s in %zu set%s of %zu (EC %d+%d), deployment %s%s", t->npools > 1 ? "pool: " : "",
                     t->layouts[q].ndrives, t->layouts[q].ndrives == 1 ? "" : "s", pl.nsets, pl.nsets == 1 ? "" : "s",
                     pl.set_size, (int)pl.set_size - pl.parity, pl.parity, layer->deployment_id_str,
                     fr[q].formatted_fresh == t->layouts[q].ndrives ? " (newly formatted)" : "");
    first += t->layouts[q].ndrives;
    total += t->layouts[q].ndrives;
    buckets_format_result_free(&fr[q]);
  }
  free(fr);
  if (buckets_objlayer_online(layer) < total) {
    buckets_log_warn("%zu of %zu drives are offline", total - buckets_objlayer_online(layer), total);
  }
  if (!t->first_local) t->first_local = buckets_objlayer_scratch(layer)->root;
  b->layer = layer;
  b->healer = buckets_healer_start(layer);
  atomic_store(&b->s3->healer, b->healer);
  buckets_s3_server_set_layer(b->s3, layer);
  buckets_scanner_hooks hooks;
  buckets_s3_scanner_hooks(b->s3, &hooks);
  b->scanner = buckets_scanner_start(layer, &hooks);
  atomic_store(&b->s3->scanner, b->scanner);
  if (t->distributed) buckets_log_info("storage initialized; serving S3");
  return true;
}

static void *bootstrap_thread(void *arg) {
  bootstrap(arg);
  return NULL;
}

/* This executable's path, for re-exec on restart. */
static void exe_path(const char *argv0, char *out, size_t cap) {
#ifdef __APPLE__
  uint32_t n = (uint32_t)cap;
  if (_NSGetExecutablePath(out, &n) == 0) return;
#else
  ssize_t n = readlink("/proc/self/exe", out, cap - 1);
  if (n > 0) {
    out[n] = '\0';
    return;
  }
#endif
  snprintf(out, cap, "%s", argv0);
}

int main(int argc, char **argv) {
  static char self_exe[4096];
  exe_path(argv[0], self_exe, sizeof(self_exe));
  /* MINIO_CONFIG_ENV_FILE (the MinIO Operator's config.env): its settings
   * override the environment, before anything reads it. */
  const char *envfile = env2("BUCKETS_CONFIG_ENV_FILE", "MINIO_CONFIG_ENV_FILE");
  if (envfile) {
    char err[512];
    if (!buckets_config_load_env_file(envfile, err, sizeof(err))) {
      fprintf(stderr, "bucketsd: unable to read the config environment file: %s\n", err);
      return 1;
    }
  }
  const char *level_s = getenv("BUCKETS_LOG_LEVEL");
  buckets_log_level level;
  if (level_s && buckets_log_parse_level(level_s, &level)) buckets_log_set_level(level);
  /* For a tenant adopted from MinIO before RELEASE.2024-10-29, so that it can
   * still be handed back: that MinIO refuses xl.meta metaVersion 3. */
  const char *xmv = getenv("BUCKETS_XL_META_VERSION");
  if (xmv && *xmv) {
    char *end;
    unsigned long v = strtoul(xmv, &end, 10);
    if (*end || !buckets_xlmeta_set_write_version((unsigned)v)) {
      fprintf(stderr, "bucketsd: BUCKETS_XL_META_VERSION must be 2 or 3, not %s\n", xmv);
      return 1;
    }
    if (v == 2) buckets_log_info("writing xl.meta metaVersion 2, readable by MinIO before RELEASE.2024-10-29");
  }

  if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
    printf("bucketsd %s\n", BUCKETS_VERSION);
    return 0;
  }
  if (argc < 2 || strcmp(argv[1], "server") != 0) {
    usage(stderr);
    return 2;
  }

  const char *address = ":9000";
  const char *certs_dir = NULL;
  char **drive_args = buckets_xcalloc((size_t)argc, sizeof(char *));
  size_t ndrive_args = 0;
  char **ftp_args = buckets_xcalloc((size_t)argc, sizeof(char *));
  size_t nftp_args = 0;
  char **sftp_args = buckets_xcalloc((size_t)argc, sizeof(char *));
  size_t nsftp_args = 0;
  for (int i = 2; i < argc; i++) {
    if (strncmp(argv[i], "--sftp=", 7) == 0) {
      sftp_args[nsftp_args++] = argv[i] + 7;
    } else if (strcmp(argv[i], "--sftp") == 0 && i + 1 < argc) {
      sftp_args[nsftp_args++] = argv[++i];
    } else if (strncmp(argv[i], "--ftp=", 6) == 0) {
      ftp_args[nftp_args++] = argv[i] + 6;
    } else if (strcmp(argv[i], "--ftp") == 0 && i + 1 < argc) {
      ftp_args[nftp_args++] = argv[++i];
    } else if (strcmp(argv[i], "--address") == 0 && i + 1 < argc) {
      address = argv[++i];
    } else if ((strcmp(argv[i], "--certs-dir") == 0 || strcmp(argv[i], "-S") == 0) && i + 1 < argc) {
      certs_dir = argv[++i];
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      usage(stdout);
      return 0;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "unknown flag: %s\n", argv[i]);
      return 2;
    } else {
      drive_args[ndrive_args++] = argv[i];
    }
  }
  /* No drive arguments: BUCKETS_VOLUMES (or MINIO_VOLUMES) holds them,
   * separated by spaces -- how the operator configures its pods. */
  if (!ndrive_args) {
    const char *vols = env2("BUCKETS_VOLUMES", "MINIO_VOLUMES");
    if (vols) {
      char *copy = buckets_xstrdup(vols), *save = NULL;
      for (char *t = strtok_r(copy, " \t\n", &save); t; t = strtok_r(NULL, " \t\n", &save)) {
        drive_args = buckets_xrealloc(drive_args, (ndrive_args + 1) * sizeof(char *));
        drive_args[ndrive_args++] = t; /* copy lives for the process */
      }
    }
  }
  if (!ndrive_args) {
    usage(stderr);
    return 2;
  }

  char *host = NULL;
  int port = 0;
  if (!parse_address(address, &host, &port)) {
    fprintf(stderr, "invalid --address %s (want [HOST]:PORT)\n", address);
    return 2;
  }

  const char *root_user = env_secret("BUCKETS_ROOT_USER", "MINIO_ROOT_USER");
  const char *root_password = env_secret("BUCKETS_ROOT_PASSWORD", "MINIO_ROOT_PASSWORD");
  if (!root_user && !root_password) {
    root_user = DEFAULT_ROOT_USER;
    root_password = DEFAULT_ROOT_PASSWORD;
    buckets_log_warn("using default root credentials %s:%s; set BUCKETS_ROOT_USER and "
                     "BUCKETS_ROOT_PASSWORD before exposing this server",
                     DEFAULT_ROOT_USER, DEFAULT_ROOT_PASSWORD);
  }
  if (!root_user || !root_password) {
    buckets_log_error("root user and password must be set together");
    return 1;
  }
  /* Same limits as MinIO's auth.IsAccessKeyValid / IsSecretKeyValid. */
  if (strlen(root_user) < 3 || strlen(root_password) < 8) {
    buckets_log_error("root user must be at least 3 characters and password at least 8");
    return 1;
  }
  /* Drives -> pools -> erasure sets (MinIO's ellipses + set sizing). As in
   * MinIO, every ellipsis argument is its own pool; plain drive lists form
   * one pool. Drives are local paths, or http(s):// URLs for a cluster. */
  const char *sdc = env2("BUCKETS_ERASURE_SET_DRIVE_COUNT", "MINIO_ERASURE_SET_DRIVE_COUNT");
  size_t nell = 0;
  for (size_t i = 0; i < ndrive_args; i++) nell += buckets_ell_has(drive_args[i]);
  if (nell && nell != ndrive_args) {
    buckets_log_error("all drive arguments must use ellipses (one pool each), or none may");
    return 1;
  }
  topology topo = {.port = port};
  topo.npools = nell ? ndrive_args : 1;
  topo.legacy = nell == 0;
  topo.cmdlines = buckets_xcalloc(topo.npools, sizeof(char *));
  if (nell) {
    for (size_t p = 0; p < topo.npools; p++) topo.cmdlines[p] = buckets_xstrdup(drive_args[p]);
  } else {
    buckets_buf joined = BUCKETS_BUF_INIT; /* strings.Join(args, " ") */
    for (size_t i = 0; i < ndrive_args; i++) {
      if (i) buckets_buf_append_char(&joined, ' ');
      buckets_buf_append_c(&joined, drive_args[i]);
    }
    buckets_buf_append_char(&joined, '\0');
    topo.cmdlines[0] = buckets_buf_detach(&joined);
  }
  topo.layouts = buckets_xcalloc(topo.npools, sizeof(*topo.layouts));
  topo.eps = buckets_xcalloc(topo.npools, sizeof(*topo.eps));
  char lerr[512];
  size_t nurl = 0, total = 0;
  for (size_t p = 0; p < topo.npools; p++) {
    char *const *args = nell ? &drive_args[p] : drive_args;
    size_t nargs = nell ? 1 : ndrive_args;
    if (!buckets_layout_pool(args, nargs, sdc ? (size_t)strtoul(sdc, NULL, 10) : 0, &topo.layouts[p], lerr,
                             sizeof(lerr))) {
      buckets_log_error("invalid drive layout%s: %s", topo.npools > 1 ? " in a pool" : "", lerr);
      return 1;
    }
    if (topo.npools > 1 && topo.layouts[p].ndrives == 1) {
      buckets_log_error("a single-drive deployment cannot be expanded with more pools");
      return 1;
    }
    for (size_t i = 0; i < topo.layouts[p].ndrives; i++) nurl += strstr(topo.layouts[p].drives[i], "://") != NULL;
    total += topo.layouts[p].ndrives;
  }
  free(drive_args);
  if (nurl && nurl != total) {
    buckets_log_error("drives must be all local paths or all http(s):// URLs");
    return 1;
  }
  topo.distributed = nurl > 0;
  if (topo.distributed && !topology_resolve(&topo)) return 1;

  const char *region = env2("BUCKETS_REGION", "MINIO_REGION");
  buckets_internode_set_secret(root_user, root_password);
  const char *sc = env2("BUCKETS_STORAGE_CLASS_STANDARD", "MINIO_STORAGE_CLASS_STANDARD");
  topo.parity = sc && strncasecmp(sc, "EC:", 3) == 0 ? atoi(sc + 3) : -1;

  /* Drive I/O threads: by default one per drive of a set, so every drive in
   * a set is read and written at once (the calling thread takes part). */
  size_t max_set = 0;
  for (size_t p = 0; p < topo.npools; p++) max_set = BUCKETS_MAX(max_set, topo.layouts[p].set_size);
  const char *iot = getenv("BUCKETS_IO_THREADS");
  /* +3: the payload hashes (MD5, SHA-256, checksum) run beside the writes. */
  long nio = iot ? strtol(iot, NULL, 10) : (long)max_set - 1 + 3 + (topo.distributed ? 8 : 0);
  buckets_pool *io_pool = NULL;
  if (nio > 0) {
    io_pool = buckets_pool_new((int)BUCKETS_MIN(nio, 1024L));
    buckets_io_pool_set(io_pool);
  }

  buckets_s3_server s3;
  buckets_s3_server_init(&s3, NULL, root_user, root_password, region);
  /* Other servers change bucket metadata too: trust snapshots only briefly. */
  s3.meta_ttl_ms = topo.distributed ? 5000 : 0;
  boot_state boot = {.topo = &topo, .s3 = &s3};
  if (!topo.distributed && !bootstrap(&boot)) return 1; /* a single node formats before it serves */

  g_loop = buckets_loop_new();
  if (!g_loop) {
    buckets_log_error("create event loop failed");
    return 1;
  }
  /* Bodies too large for memory spool to the first local drive. */
  char spool[4096];
  snprintf(spool, sizeof(spool), "%s/" BUCKETS_META_BUCKET "/tmp", topo.first_local);
  buckets_http_config hcfg = {
      .host = host,
      .port = port,
      .max_body = MAX_BODY_BYTES,
      .mem_body_limit = MEM_BODY_BYTES,
      .stream_chunked = stream_chunked,
      .spool_dir = spool,
      .idle_timeout_sec = 30,
      .server_header = "Buckets",
  };
  /* Request workers run the S3 handlers; the loop thread only moves bytes. */
  const char *apit = getenv("BUCKETS_API_THREADS");
  long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
  long napi = apit ? strtol(apit, NULL, 10) : BUCKETS_MAX(8L, 2 * ncpu);
  buckets_pool *api_pool = napi > 0 ? buckets_pool_new((int)BUCKETS_MIN(napi, 4096L)) : NULL;
  s3.requests_max = napi > 0 ? (int)BUCKETS_MIN(napi, 4096L) : 0; /* X-Ratelimit-Limit */
  hcfg.workers = api_pool;
  /* Loop threads moving the bytes (one saturates on large GETs). Inline
   * handlers (BUCKETS_API_THREADS=0) keep the single loop. */
  const char *nett = getenv("BUCKETS_NET_THREADS");
  long nnet = nett ? strtol(nett, NULL, 10) : BUCKETS_MIN(16L, BUCKETS_MAX(1L, ncpu / 2));
  hcfg.reactors = api_pool ? (int)BUCKETS_MIN(BUCKETS_MAX(nnet, 1L), 256L) : 1;
  /* The admin API and health probes get their own workers: a frozen S3 API
   * (mc admin service freeze) parks its requests, which must not block the
   * unfreeze or the kubelet's probes. */
  buckets_pool *control_pool = api_pool ? buckets_pool_new(4) : NULL;
  /* The network speedtests' devnull endpoints hold a worker per incoming
   * stream for the whole test (tens of them per peer): workers of their own. */
  buckets_pool *perf_pool = api_pool ? buckets_pool_new(96) : NULL;
  if (perf_pool) {
    static const char *const perf[] = {"/minio/admin/v3/speedtest/client/devnull",
                                       "/minio/admin/v3/site-replication/devnull"};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(perf); i++)
      hcfg.routes[hcfg.nroutes++] = (buckets_http_route){perf[i], buckets_s3_handle, &s3, perf_pool};
  }
  if (control_pool) {
    static const char *const control[] = {"/minio/admin/", "/minio/health/", "/buckets/health/"};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(control); i++)
      hcfg.routes[hcfg.nroutes++] = (buckets_http_route){control[i], buckets_s3_handle, &s3, control_pool};
  }
  s3.service = on_service;

  /* Internode RPC gets its own workers, so peers never wait behind clients
   * (two nodes filling each other's pools with S3 requests would deadlock). */
  buckets_pool *internode_pool = NULL;
  buckets_storage_server *storage_srv = NULL;
  static buckets_peer_handlers peer_handlers;
  peer_handlers = (buckets_peer_handlers){buckets_s3_peer_iam, buckets_s3_peer_bucket, buckets_s3_peer_server_info,
                                          buckets_s3_peer_metrics, buckets_s3_peer_listen, &s3,
                                          buckets_s3_peer_tier_stats, buckets_s3_peer_batch_metrics,
                                          buckets_s3_peer_datamove, buckets_s3_peer_admin};
  if (topo.distributed) {
    internode_pool = buckets_pool_new((int)BUCKETS_MAX(16L, 2 * ncpu));
    storage_srv = buckets_storage_server_new(topo.local_drives, topo.nlocal);
    hcfg.routes[hcfg.nroutes++] = (buckets_http_route){BUCKETS_INTERNODE_PREFIX "storage/", buckets_storage_server_handle,
                                                        storage_srv, internode_pool};
    hcfg.routes[hcfg.nroutes++] = (buckets_http_route){BUCKETS_INTERNODE_PREFIX "lock/", buckets_lock_server_handle,
                                                        topo.lock_server, internode_pool};
    hcfg.routes[hcfg.nroutes++] = (buckets_http_route){BUCKETS_INTERNODE_PREFIX "peer/", buckets_peer_server_handle,
                                                        &peer_handlers, internode_pool};
    hcfg.routes[hcfg.nroutes++] = (buckets_http_route){BUCKETS_INTERNODE_PREFIX "perf/", buckets_admin_internode_devnull,
                                                        &s3, perf_pool ? perf_pool : internode_pool};
  }

  /* HTTPS when the certs directory holds a key pair, as in MinIO. */
  char certs_buf[4096];
  if (!certs_dir) {
    const char *home = getenv("HOME");
    const char *cands[] = {".buckets/certs", ".minio/certs"};
    for (size_t i = 0; home && i < 2 && !certs_dir; i++) {
      snprintf(certs_buf, sizeof(certs_buf), "%s/%s", home, cands[i]);
      char crt[4200];
      snprintf(crt, sizeof(crt), "%s/public.crt", certs_buf);
      if (access(crt, R_OK) == 0) certs_dir = certs_buf;
    }
  }
  buckets_tls *tls = NULL;
  if (certs_dir) {
    char crt[4200];
    snprintf(crt, sizeof(crt), "%s/public.crt", certs_dir);
    if (access(crt, F_OK) == 0) {
      char terr[512];
      if (!(tls = buckets_tls_server_new(certs_dir, terr, sizeof(terr)))) {
        buckets_log_error("TLS: %s", terr);
        return 1;
      }
      buckets_log_info("TLS enabled with %zu certificate%s from %s", buckets_tls_cert_count(tls),
                       buckets_tls_cert_count(tls) == 1 ? "" : "s", certs_dir);
      /* identity_tls: clients may present a certificate for AssumeRoleWithCertificate. */
      if (buckets_config_parse_bool(buckets_config_getenv("MINIO_IDENTITY_TLS_ENABLE")) == 1)
        buckets_tls_request_client_certs(tls, true);
    }
  }
  hcfg.tls = tls;
  /* Identity providers (LDAP) also trust certs/CAs, as MinIO's globalRootCAs. */
  static char ca_path[4200];
  snprintf(ca_path, sizeof(ca_path), "%s/CAs", certs_dir ? certs_dir : ".");
  if (certs_dir && access(ca_path, R_OK) == 0) s3.ca_path = ca_path;
  if (topo.distributed && topo.secure) {
    char cas[4200], terr[512];
    snprintf(cas, sizeof(cas), "%s/CAs", certs_dir ? certs_dir : ".");
    if (!(topo.tls_client = buckets_tls_client_new(cas, terr, sizeof(terr)))) {
      buckets_log_error("TLS client: %s", terr);
      return 1;
    }
  }
  __atomic_store_n(&s3.cluster, cluster_describe(&topo, host, tls != NULL), __ATOMIC_RELEASE); /* metrics_main polls it */
  s3.internode_tls = topo.tls_client;
  buckets_trace_set_node(s3.cluster->self);
  if (topo.distributed) {
    topology_connect(&topo);
    buckets_dsync_set_owner(topo.dsync, s3.cluster->self); /* globalLocalNodeName */
    leader_start(&g_leader, topo.dsync);
    buckets_http_client **pc = buckets_xcalloc(topo.npeers ? topo.npeers : 1, sizeof(*pc));
    for (size_t i = 0; i < topo.npeers; i++) pc[i] = topo.peers[i].client;
    s3.peers = buckets_peer_sys_new(pc, topo.npeers);
    s3.internode = pc; /* kept for the internode traffic metrics */
    s3.ninternode = topo.npeers;
    s3.lock_server = topo.lock_server;
  }

  app_state app = {0};
  app.http = buckets_http_server_start(g_loop, &hcfg, buckets_s3_handle, &s3);
  if (!app.http) return 1;
  origin_endpoint(s3.endpoint, sizeof(s3.endpoint), host, buckets_http_server_port(app.http), tls != NULL);
  buckets_fs_init(&s3, buckets_http_server_port(app.http), tls != NULL);
  if (nftp_args) {
    buckets_ftp_opts fo;
    char ferr[512];
    if (!buckets_ftp_parse(ftp_args, nftp_args, &fo, ferr, sizeof(ferr)) ||
        !buckets_ftp_start(&fo, tls != NULL, certs_dir, ferr, sizeof(ferr))) {
      buckets_log_error("unable to start FTP server: %s", ferr);
      return 1;
    }
  }
  if (nsftp_args) {
    buckets_sftp_opts so;
    char serr[1024];
    if (!buckets_sftp_parse(sftp_args, nsftp_args, &so, serr, sizeof(serr)) ||
        !buckets_sftp_start(&so, serr, sizeof(serr))) {
      buckets_log_error("unable to start SFTP server: %s", serr);
      return 1;
    }
  }
  buckets_loop_set_wake(g_loop, on_wake, &app);
  buckets_loop_add_tick(g_loop, on_tick, &app);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);

  buckets_log_info("bucketsd %s listening on %s://%s:%d", BUCKETS_VERSION, tls ? "https" : "http", *host ? host : "*",
                   buckets_http_server_port(app.http));
  pthread_t boot_thread;
  bool boot_started = false;
  if (topo.distributed) {
    buckets_log_info("cluster of %zu node%s; waiting for peers to format and start", topo.npeers + 1,
                     topo.npeers ? "s" : "");
    boot_started = pthread_create(&boot_thread, NULL, bootstrap_thread, &boot) == 0;
  }
  int rc = buckets_loop_run(g_loop);

  atomic_store(&boot.stop, true);
  if (boot_started) pthread_join(boot_thread, NULL);
  /* A frozen API would hold its workers forever. */
  pthread_mutex_lock(&s3.freeze_mu);
  s3.freeze_cnt = 0;
  pthread_cond_broadcast(&s3.freeze_cv);
  pthread_mutex_unlock(&s3.freeze_mu);
  buckets_pool_free(api_pool); /* finishes in-flight handlers before their connections go */
  buckets_pool_free(control_pool);
  buckets_pool_free(perf_pool);
  buckets_pool_free(internode_pool);
  buckets_admin_heal_shutdown(); /* heal sequences use the object layer */
  leader_stop(&g_leader);
  buckets_s3_server_stop(&s3); /* its background threads use the object layer */
  buckets_http_server_free(app.http);
  buckets_tls_free(tls);
  buckets_scanner_stop(boot.scanner);
  buckets_healer_stop(boot.healer);
  buckets_s3_server_close_targets(&s3); /* the scanner sends lifecycle events */
  buckets_loop_free(g_loop);
  if (boot.layer) buckets_objlayer_set_locker(boot.layer, NULL, NULL, NULL);
  buckets_peer_sys_free(s3.peers);
  free(s3.internode);
  buckets_cluster_info_free(s3.cluster);
  buckets_dsync_free(topo.dsync);
  buckets_objlayer_free(boot.layer);
  buckets_storage_server_free(storage_srv);
  topology_free(&topo);
  buckets_tls_client_free(topo.tls_client);
  buckets_io_pool_set(NULL);
  buckets_pool_free(io_pool);
  free(host);
  if (atomic_load(&g_restart)) {
    buckets_log_info("bucketsd restarting");
    execv(self_exe, argv);
    buckets_log_error("restart: exec %s: %s", self_exe, strerror(errno));
    return 1;
  }
  buckets_log_info("bucketsd stopped");
  return rc == 0 ? 0 : 1;
}
