/* bucketsd - Buckets storage server.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/log.h"
#include "core/loop.h"
#include "net/http.h"
#include "s3/server.h"
#include "storage/drive.h"

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
          "Usage: bucketsd server [--address [HOST]:PORT] DIR\n"
          "\n"
          "Environment:\n"
          "  BUCKETS_ROOT_USER / MINIO_ROOT_USER          root access key (default minioadmin)\n"
          "  BUCKETS_ROOT_PASSWORD / MINIO_ROOT_PASSWORD  root secret key (default minioadmin)\n"
          "  BUCKETS_REGION / MINIO_REGION                server region (default: accept any)\n"
          "  BUCKETS_LOG_LEVEL                            debug|info|warn|error\n");
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
  const char *dir = NULL;
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--address") == 0 && i + 1 < argc) {
      address = argv[++i];
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      usage(stdout);
      return 0;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "unknown flag: %s\n", argv[i]);
      return 2;
    } else if (!dir) {
      dir = argv[i];
    } else {
      fprintf(stderr, "multiple drives are not supported yet (erasure coding is a later milestone)\n");
      return 2;
    }
  }
  if (!dir) {
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

  buckets_drive *drive = NULL;
  buckets_drive_err derr = buckets_drive_open(dir, &drive);
  if (derr != BUCKETS_DRIVE_OK) {
    buckets_log_error("open drive %s: %s", dir, buckets_drive_strerror(derr));
    return 1;
  }
  buckets_log_info("drive %s %s (deployment %s)", dir, drive->freshly_formatted ? "formatted" : "opened",
                   drive->deployment_id);

  buckets_s3_server s3;
  buckets_s3_server_init(&s3, drive, root_user, root_password, region);

  g_loop = buckets_loop_new();
  if (!g_loop) {
    buckets_log_error("create event loop failed");
    return 1;
  }
  char spool[4096];
  snprintf(spool, sizeof(spool), "%s/" BUCKETS_META_BUCKET "/tmp", drive->root);
  buckets_http_config hcfg = {
      .host = host,
      .port = port,
      .max_body = MAX_BODY_BYTES,
      .mem_body_limit = MEM_BODY_BYTES,
      .spool_dir = spool,
      .idle_timeout_sec = 30,
      .server_header = "Buckets",
  };
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

  buckets_http_server_free(app.http);
  buckets_loop_free(g_loop);
  buckets_drive_close(drive);
  free(host);
  buckets_log_info("bucketsd stopped");
  return rc == 0 ? 0 : 1;
}
