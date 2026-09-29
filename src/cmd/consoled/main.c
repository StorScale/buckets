/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* consoled: the Buckets web console (the SPA and its backend), deployed
 * apart from the storage servers.
 *
 *   consoled [--address :9090] [--web-dir DIR] [--certs-dir DIR]
 *
 * Environment (MinIO console names are honored too):
 *   BUCKETS_CONSOLE_SERVER / CONSOLE_MINIO_SERVER       bucketsd URL (http://127.0.0.1:9000)
 *   BUCKETS_CONSOLE_PBKDF_PASSPHRASE / CONSOLE_PBKDF_PASSPHRASE, ..._SALT
 *                                                        cookie key (shared by replicas)
 *   BUCKETS_CONSOLE_STS_DURATION / CONSOLE_STS_DURATION  session length (3600, or 30m / 12h)
 *   BUCKETS_CONSOLE_REGION / CONSOLE_MINIO_REGION        region to sign for
 *   BUCKETS_CONSOLE_CA_DIR                                CAs for an https bucketsd */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "console/console.h"
#include "core/log.h"
#include "core/loop.h"
#include "core/pool.h"

#define SHUTDOWN_GRACE_SECONDS 20

static buckets_loop *g_loop;
static volatile sig_atomic_t g_signal;

typedef struct {
  buckets_http_server *http;
  bool draining;
  time_t deadline;
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
  app->deadline = time(NULL) + SHUTDOWN_GRACE_SECONDS;
  buckets_http_server_shutdown(app->http);
  if (buckets_http_server_connections(app->http) == 0) buckets_loop_stop(loop);
}

static void on_tick(buckets_loop *loop, void *ud) {
  app_state *app = ud;
  if (app->draining && (buckets_http_server_connections(app->http) == 0 || time(NULL) >= app->deadline))
    buckets_loop_stop(loop);
}

static const char *env2(const char *a, const char *b) {
  const char *v = getenv(a);
  if (v && *v) return v;
  v = b ? getenv(b) : NULL;
  return v && *v ? v : NULL;
}

/* "3600", "90s", "30m" or "12h". */
static int parse_duration(const char *s) {
  if (!s) return 0;
  char *end;
  long v = strtol(s, &end, 10);
  if (*end == 'h') v *= 3600;
  else if (*end == 'm') v *= 60;
  return v > 0 && v < 7 * 24 * 3600 ? (int)v : 0;
}

/* http(s)://host[:port] */
static bool parse_url(const char *url, char *host, size_t cap, int *port, bool *tls) {
  *tls = strncasecmp(url, "https://", 8) == 0;
  const char *p = *tls ? url + 8 : strncasecmp(url, "http://", 7) == 0 ? url + 7 : NULL;
  if (!p) return false;
  const char *end = p + strcspn(p, "/");
  const char *colon = memchr(p, ':', (size_t)(end - p));
  size_t hn = (size_t)((colon ? colon : end) - p);
  if (!hn || hn >= cap) return false;
  memcpy(host, p, hn);
  host[hn] = '\0';
  *port = colon ? atoi(colon + 1) : *tls ? 443 : 80;
  return *port > 0;
}

int main(int argc, char **argv) {
  const char *address = ":9090", *web_dir = NULL, *certs_dir = NULL;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--address") == 0 && i + 1 < argc) address = argv[++i];
    else if (strcmp(argv[i], "--web-dir") == 0 && i + 1 < argc) web_dir = argv[++i];
    else if (strcmp(argv[i], "--certs-dir") == 0 && i + 1 < argc) certs_dir = argv[++i];
    else if (strcmp(argv[i], "--version") == 0) {
      printf("consoled %s\n", BUCKETS_VERSION);
      return 0;
    } else {
      fprintf(stderr, "usage: consoled [--address HOST:PORT] [--web-dir DIR] [--certs-dir DIR]\n");
      return 2;
    }
  }
  if (!web_dir) web_dir = env2("BUCKETS_CONSOLE_WEB_DIR", NULL);
  const char *server = env2("BUCKETS_CONSOLE_SERVER", "CONSOLE_MINIO_SERVER");
  if (!server) server = "http://127.0.0.1:9000";
  char up_host[256];
  int up_port;
  bool up_tls;
  if (!parse_url(server, up_host, sizeof(up_host), &up_port, &up_tls)) {
    buckets_log_error("invalid storage server URL %s", server);
    return 2;
  }
  buckets_tls_client *up_tlsc = NULL;
  if (up_tls) {
    char err[512];
    if (!(up_tlsc = buckets_tls_client_new(env2("BUCKETS_CONSOLE_CA_DIR", NULL), err, sizeof(err)))) {
      buckets_log_error("TLS client: %s", err);
      return 1;
    }
  }
  char host[256] = "";
  const char *colon = strrchr(address, ':');
  int port = colon ? atoi(colon + 1) : 9090;
  if (colon) snprintf(host, sizeof(host), "%.*s", (int)(colon - address), address);

  buckets_tls *tls = NULL;
  if (certs_dir) {
    char err[512];
    if (!(tls = buckets_tls_server_new(certs_dir, err, sizeof(err)))) {
      buckets_log_error("TLS: %s", err);
      return 1;
    }
  }
  buckets_console_config cfg = {
      .upstream_host = up_host,
      .upstream_port = up_port,
      .upstream_tls = up_tlsc,
      .web_dir = web_dir,
      .passphrase = env2("BUCKETS_CONSOLE_PBKDF_PASSPHRASE", "CONSOLE_PBKDF_PASSPHRASE"),
      .salt = env2("BUCKETS_CONSOLE_PBKDF_SALT", "CONSOLE_PBKDF_SALT"),
      .sts_duration = parse_duration(env2("BUCKETS_CONSOLE_STS_DURATION", "CONSOLE_STS_DURATION")),
      .secure_cookie = tls != NULL || env2("BUCKETS_CONSOLE_SECURE_COOKIE", NULL) != NULL,
      .region = env2("BUCKETS_CONSOLE_REGION", "CONSOLE_MINIO_REGION"),
  };
  buckets_console *console = buckets_console_new(&cfg);

  g_loop = buckets_loop_new();
  buckets_pool *workers = buckets_pool_new(32);
  buckets_http_config hcfg = {
      .host = host,
      .port = port,
      .max_body = 5LL * 1024 * 1024 * 1024,
      .mem_body_limit = 1024 * 1024,
      .spool_dir = "/tmp",
      .idle_timeout_sec = 60,
      .server_header = "Buckets-Console",
      .workers = workers,
      .tls = tls,
  };
  app_state app = {0};
  app.http = buckets_http_server_start(g_loop, &hcfg, buckets_console_handle, console);
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
  buckets_log_info("consoled %s listening on %s://%s:%d for %s", BUCKETS_VERSION, tls ? "https" : "http",
                   *host ? host : "*", buckets_http_server_port(app.http), server);
  int rc = buckets_loop_run(g_loop);
  buckets_pool_free(workers);
  buckets_http_server_free(app.http);
  buckets_loop_free(g_loop);
  buckets_console_free(console);
  buckets_tls_free(tls);
  buckets_tls_client_free(up_tlsc);
  return rc;
}
