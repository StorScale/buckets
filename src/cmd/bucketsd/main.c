/* bucketsd - Buckets storage server.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "core/log.h"
#include "dist/dsync.h"
#include "dist/endpoint.h"
#include "dist/internode.h"
#include "dist/storage_server.h"
#include "storage/remote.h"
#include "core/pool.h"
#include "core/loop.h"
#include "net/http.h"
#include "s3/server.h"
#include "erasure/layout.h"
#include "heal/healer.h"
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
          "Usage: bucketsd server [--address [HOST]:PORT] [--certs-dir DIR] DRIVE...\n"
          "  DRIVE may use MinIO ellipses, e.g. /mnt/disk{1...16}; each ellipsis argument is a pool\n"
          "  --certs-dir: public.crt + private.key enable HTTPS (default ~/.buckets/certs,\n"
          "               then ~/.minio/certs); subdirectories add certificates chosen by SNI\n"
          "\n"
          "Environment:\n"
          "  BUCKETS_ROOT_USER / MINIO_ROOT_USER          root access key (default minioadmin)\n"
          "  BUCKETS_ROOT_PASSWORD / MINIO_ROOT_PASSWORD  root secret key (default minioadmin)\n"
          "  BUCKETS_REGION / MINIO_REGION                server region (default: accept any)\n"
          "  BUCKETS_VOLUMES / MINIO_VOLUMES              drives, space separated, when none are given\n"
          "  *_ROOT_USER_FILE / *_ROOT_PASSWORD_FILE      read the root credentials from files\n"
          "  BUCKETS_LOG_LEVEL                            debug|info|warn|error\n"
          "  BUCKETS_API_THREADS                          request handler threads (default: 2 x CPUs, min 8)\n"
          "  BUCKETS_IO_THREADS                           drive I/O threads (default: set size + 2)\n");
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
} topology;

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
  atomic_bool stop;
} boot_state;

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
  buckets_s3_server_set_layer(b->s3, layer);
  if (t->distributed) buckets_log_info("storage initialized; serving S3");
  return true;
}

static void *bootstrap_thread(void *arg) {
  bootstrap(arg);
  return NULL;
}

int main(int argc, char **argv) {
  const char *level_s = getenv("BUCKETS_LOG_LEVEL");
  buckets_log_level level;
  if (level_s && buckets_log_parse_level(level_s, &level)) buckets_log_set_level(level);

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
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--address") == 0 && i + 1 < argc) {
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
      .spool_dir = spool,
      .idle_timeout_sec = 30,
      .server_header = "Buckets",
  };
  /* Request workers run the S3 handlers; the loop thread only moves bytes. */
  const char *apit = getenv("BUCKETS_API_THREADS");
  long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
  long napi = apit ? strtol(apit, NULL, 10) : BUCKETS_MAX(8L, 2 * ncpu);
  buckets_pool *api_pool = napi > 0 ? buckets_pool_new((int)BUCKETS_MIN(napi, 4096L)) : NULL;
  hcfg.workers = api_pool;

  /* Internode RPC gets its own workers, so peers never wait behind clients
   * (two nodes filling each other's pools with S3 requests would deadlock). */
  buckets_pool *internode_pool = NULL;
  buckets_storage_server *storage_srv = NULL;
  if (topo.distributed) {
    internode_pool = buckets_pool_new((int)BUCKETS_MAX(16L, 2 * ncpu));
    storage_srv = buckets_storage_server_new(topo.local_drives, topo.nlocal);
    hcfg.routes[hcfg.nroutes++] = (buckets_http_route){BUCKETS_INTERNODE_PREFIX "storage/", buckets_storage_server_handle,
                                                        storage_srv, internode_pool};
    hcfg.routes[hcfg.nroutes++] = (buckets_http_route){BUCKETS_INTERNODE_PREFIX "lock/", buckets_lock_server_handle,
                                                        topo.lock_server, internode_pool};
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
    }
  }
  hcfg.tls = tls;
  if (topo.distributed && topo.secure) {
    char cas[4200], terr[512];
    snprintf(cas, sizeof(cas), "%s/CAs", certs_dir ? certs_dir : ".");
    if (!(topo.tls_client = buckets_tls_client_new(cas, terr, sizeof(terr)))) {
      buckets_log_error("TLS client: %s", terr);
      return 1;
    }
  }
  if (topo.distributed) topology_connect(&topo);

  app_state app = {0};
  app.http = buckets_http_server_start(g_loop, &hcfg, buckets_s3_handle, &s3);
  if (!app.http) return 1;
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
  buckets_pool_free(api_pool); /* finishes in-flight handlers before their connections go */
  buckets_pool_free(internode_pool);
  buckets_http_server_free(app.http);
  buckets_tls_free(tls);
  buckets_healer_stop(boot.healer);
  buckets_loop_free(g_loop);
  if (boot.layer) buckets_objlayer_set_locker(boot.layer, NULL, NULL, NULL);
  buckets_dsync_free(topo.dsync);
  buckets_objlayer_free(boot.layer);
  buckets_storage_server_free(storage_srv);
  topology_free(&topo);
  buckets_tls_client_free(topo.tls_client);
  buckets_io_pool_set(NULL);
  buckets_pool_free(io_pool);
  free(host);
  buckets_log_info("bucketsd stopped");
  return rc == 0 ? 0 : 1;
}
