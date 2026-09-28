/* buckets-operator: reconciles BucketsCluster objects into StatefulSets,
 * Services, PodDisruptionBudgets and credentials.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/log.h"
#include "lease.h"
#include "reconcile.h"

#ifndef BUCKETS_VERSION
#define BUCKETS_VERSION "dev"
#endif

#define LEASE_NAME "buckets-operator"
#define LEASE_SECONDS 15

static volatile sig_atomic_t g_stop;
static void on_signal(int sig) { g_stop = sig; }

static const char *env_or(const char *name, const char *dflt) {
  const char *v = getenv(name);
  return v && *v ? v : dflt;
}

/* Sleeps up to ms, returning early on a signal. */
static void nap(int ms) {
  for (int waited = 0; waited < ms && !g_stop; waited += 100) {
    struct timespec ts = {0, 100 * 1000000L};
    nanosleep(&ts, NULL);
  }
}

int main(int argc, char **argv) {
  if (argc > 1 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
    printf("buckets-operator %s\n", BUCKETS_VERSION);
    return 0;
  }
  buckets_log_level level;
  if (getenv("BUCKETS_LOG_LEVEL") && buckets_log_parse_level(getenv("BUCKETS_LOG_LEVEL"), &level)) {
    buckets_log_set_level(level);
  }
  char err[512];
  kube *k = kube_from_env(err, sizeof(err));
  if (!k) {
    buckets_log_error("Kubernetes API: %s", err);
    return 1;
  }
  op_ctx o = {
      .k = k,
      .namespace = getenv("BUCKETS_OPERATOR_NAMESPACE") && *getenv("BUCKETS_OPERATOR_NAMESPACE")
                       ? getenv("BUCKETS_OPERATOR_NAMESPACE")
                       : NULL,
      .cluster_domain = env_or("BUCKETS_CLUSTER_DOMAIN", "cluster.local"),
  };
  const char *lease_ns = env_or("POD_NAMESPACE", o.namespace ? o.namespace : "default");
  char host[256] = "buckets-operator";
  gethostname(host, sizeof(host));
  const char *identity = env_or("POD_NAME", host);
  bool elect = strcmp(env_or("BUCKETS_LEADER_ELECT", "true"), "false") != 0;
  int resync_ms = atoi(env_or("BUCKETS_OPERATOR_RESYNC_MS", "5000"));
  if (resync_ms < 200) resync_ms = 200;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_signal;
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);

  buckets_log_info("buckets-operator %s starting (watching %s, identity %s%s)", BUCKETS_VERSION,
                   o.namespace ? o.namespace : "all namespaces", identity, elect ? "" : ", leader election off");
  bool leader = !elect;
  while (!g_stop) {
    if (elect) {
      bool now = lease_acquire_or_renew(k, lease_ns, LEASE_NAME, identity, LEASE_SECONDS);
      if (now != leader) buckets_log_info(now ? "became the leader" : "lost the leadership");
      leader = now;
    }
    if (leader) op_reconcile_all(&o);
    /* Leaders resync on the interval; followers retry the lease a bit more often. */
    nap(leader ? resync_ms : 2000);
  }
  if (elect && leader) lease_release(k, lease_ns, LEASE_NAME, identity);
  buckets_log_info("buckets-operator stopped");
  kube_free(k);
  return 0;
}
