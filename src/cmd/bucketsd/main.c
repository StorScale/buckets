/* bucketsd - Buckets storage server.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "core/log.h"
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

static void usage(FILE *f) {
  fprintf(f,
          "Usage: bucketsd server [--address [HOST]:PORT] DRIVE...\n"
          "  DRIVE may use MinIO ellipses, e.g. /mnt/disk{1...16}\n"
          "\n"
          "Environment:\n"
          "  BUCKETS_ROOT_USER / MINIO_ROOT_USER          root access key (default minioadmin)\n"
          "  BUCKETS_ROOT_PASSWORD / MINIO_ROOT_PASSWORD  root secret key (default minioadmin)\n"
          "  BUCKETS_REGION / MINIO_REGION                server region (default: accept any)\n"
          "  BUCKETS_LOG_LEVEL                            debug|info|warn|error\n"
          "  BUCKETS_API_THREADS                          request handler threads (default: 2 x CPUs, min 8)\n"
          "  BUCKETS_IO_THREADS                           drive I/O threads (default: set size - 1)\n");
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

int main(int argc, char **argv) {
  const char *level_s = getenv("BUCKETS_LOG_LEVEL");
  buckets_log_level level;
  if (level_s && buckets_log_parse_level(level_s, &level)) buckets_log_set_level(level);

  if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
    printf("bucketsd %s\n", BUCKETS_VERSION);
    return 0;
  }
  if (argc < 3 || strcmp(argv[1], "server") != 0) {
    usage(stderr);
    return 2;
  }

  const char *address = ":9000";
  char **drive_args = buckets_xcalloc((size_t)argc, sizeof(char *));
  size_t ndrive_args = 0;
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--address") == 0 && i + 1 < argc) {
      address = argv[++i];
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

  const char *root_user = env2("BUCKETS_ROOT_USER", "MINIO_ROOT_USER");
  const char *root_password = env2("BUCKETS_ROOT_PASSWORD", "MINIO_ROOT_PASSWORD");
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
  const char *region = env2("BUCKETS_REGION", "MINIO_REGION");

  /* Drives -> erasure sets (MinIO's ellipses + set sizing), then format.json
   * negotiation places each drive by its UUID. */
  const char *sdc = env2("BUCKETS_ERASURE_SET_DRIVE_COUNT", "MINIO_ERASURE_SET_DRIVE_COUNT");
  char lerr[512];
  buckets_pool_layout layout;
  if (!buckets_layout_pool(drive_args, ndrive_args, sdc ? (size_t)strtoul(sdc, NULL, 10) : 0, &layout, lerr,
                           sizeof(lerr))) {
    buckets_log_error("invalid drive layout: %s", lerr);
    return 1;
  }
  free(drive_args);
  buckets_drive **drives = buckets_xcalloc(layout.ndrives, sizeof(buckets_drive *));
  for (size_t i = 0; i < layout.ndrives; i++) {
    if (strstr(layout.drives[i], "://")) {
      buckets_log_error("remote drives (%s) are not supported yet; distributed mode is in progress", layout.drives[i]);
      return 1;
    }
    if (buckets_drive_open_raw(layout.drives[i], &drives[i]) != BUCKETS_DRIVE_OK) {
      buckets_log_warn("drive %s is unavailable; continuing without it", layout.drives[i]);
      drives[i] = NULL;
    }
  }
  buckets_format_result fr;
  if (!buckets_format_negotiate(drives, layout.ndrives, layout.set_size, &fr, lerr, sizeof(lerr))) {
    buckets_log_error("%s", lerr);
    return 1;
  }
  free(drives);
  /* Parity: MINIO_STORAGE_CLASS_STANDARD=EC:N, else MinIO's default for the set size. */
  int parity = -1;
  const char *sc = env2("BUCKETS_STORAGE_CLASS_STANDARD", "MINIO_STORAGE_CLASS_STANDARD");
  if (sc && strncasecmp(sc, "EC:", 3) == 0) parity = atoi(sc + 3);
  buckets_objlayer *layer = buckets_objlayer_new(&fr, parity);
  buckets_log_info("%zu drive%s in %zu set%s of %zu (EC %d+%d), deployment %s%s", layout.ndrives,
                   layout.ndrives == 1 ? "" : "s", layer->nsets, layer->nsets == 1 ? "" : "s", layout.set_size,
                   (int)layout.set_size - layer->sets[0].parity, layer->sets[0].parity, layer->deployment_id_str,
                   fr.formatted_fresh ? " (newly formatted)" : "");
  if (buckets_objlayer_online(layer) < layout.ndrives) {
    buckets_log_warn("%zu of %zu drives are offline", layout.ndrives - buckets_objlayer_online(layer), layout.ndrives);
  }
  /* Drive I/O threads: by default one per drive of a set, so every drive in
   * a set is read and written at once (the event-loop thread takes part). */
  const char *iot = getenv("BUCKETS_IO_THREADS");
  long nio = iot ? strtol(iot, NULL, 10) : (long)layout.set_size - 1;
  buckets_pool *io_pool = NULL;
  if (nio > 0) {
    io_pool = buckets_pool_new((int)BUCKETS_MIN(nio, 1024L));
    buckets_io_pool_set(io_pool);
  }
  buckets_format_result_free(&fr);
  buckets_layout_free(&layout);

  buckets_healer *healer = buckets_healer_start(layer);

  buckets_s3_server s3;
  buckets_s3_server_init(&s3, layer, root_user, root_password, region);

  g_loop = buckets_loop_new();
  if (!g_loop) {
    buckets_log_error("create event loop failed");
    return 1;
  }
  char spool[4096];
  snprintf(spool, sizeof(spool), "%s/" BUCKETS_META_BUCKET "/tmp", buckets_objlayer_scratch(layer)->root);
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

  buckets_log_info("bucketsd %s listening on %s:%d", BUCKETS_VERSION, *host ? host : "*",
                   buckets_http_server_port(app.http));
  int rc = buckets_loop_run(g_loop);

  buckets_pool_free(api_pool); /* finishes in-flight handlers before their connections go */
  buckets_http_server_free(app.http);
  buckets_healer_stop(healer);
  buckets_loop_free(g_loop);
  buckets_objlayer_free(layer);
  buckets_io_pool_set(NULL);
  buckets_pool_free(io_pool);
  free(host);
  buckets_log_info("bucketsd stopped");
  return rc == 0 ? 0 : 1;
}
