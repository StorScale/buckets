/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "notify/targets.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"

static const buckets_target_kind *const k_kinds[] = {&buckets_target_webhook, &buckets_target_redis, &buckets_target_nsq, &buckets_target_nats, &buckets_target_mqtt, &buckets_target_elasticsearch, &buckets_target_postgres, &buckets_target_mysql, &buckets_target_amqp, &buckets_target_kafka};

/* A target's value, resolved (env, config, default); caller frees. */
static char *get(const buckets_config *cfg, const char *subsys, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, subsys, target, key);
  return v ? v : buckets_xstrdup("");
}

static _Thread_local const char *g_probe_subsys;
static _Thread_local char *const *g_probe;
static _Thread_local size_t g_nprobe;

void buckets_targets_probe_set(const char *subsys, char *const *names, size_t n) {
  g_probe_subsys = subsys;
  g_probe = names;
  g_nprobe = names ? n : 0;
}

static bool probed(const char *subsys, const char *name) {
  if (!g_probe_subsys || strcmp(g_probe_subsys, subsys) != 0) return false;
  for (size_t i = 0; i < g_nprobe; i++)
    if (strcmp(g_probe[i], name) == 0) return true;
  return false;
}

static bool run(const buckets_config *cfg, const char *ca_file, buckets_target ***out, size_t *n, char *err, size_t errlen) {
  buckets_target **t = NULL;
  size_t k = 0;
  bool ok = true;
  for (size_t i = 0; ok && i < BUCKETS_ARRAY_LEN(k_kinds); i++) {
    const buckets_target_kind *kind = k_kinds[i];
    if (!buckets_config_check_notify_keys(cfg, kind->subsys, err, errlen)) {
      ok = false;
      break;
    }
    char **names;
    size_t nn = buckets_config_targets(cfg, kind->subsys, &names);
    for (size_t j = 0; j < nn; j++) {
      char *en = get(cfg, kind->subsys, names[j], "enable");
      int on = buckets_config_parse_bool(en);
      free(en);
      if (on < 0) {
        snprintf(err, errlen, "%s:%s: invalid value for enable", kind->subsys, names[j]);
        ok = false;
      }
      if (on != 1 || !ok) continue;
      void *impl = NULL;
      bool probe = !out && probed(kind->subsys, names[j]);
      if (!kind->create(cfg, names[j], ca_file, out || probe ? &impl : NULL, err, errlen)) {
        ok = false;
        continue;
      }
      if (probe) { /* a target just set must be online */
        char why[512] = "";
        bool up = !kind->ops->is_active || kind->ops->is_active(impl, why, sizeof(why));
        kind->ops->free(impl);
        if (!up) {
          snprintf(err, errlen, "error (%s:%s): %s", names[j], kind->ops->type, *why ? why : "not connected to target server/service");
          ok = false;
        }
        continue;
      }
      if (!out) continue;
      char qerr[512] = "";
      char *qdir = get(cfg, kind->subsys, names[j], "queue_dir");
      char *qlim = get(cfg, kind->subsys, names[j], "queue_limit");
      buckets_target *tg = buckets_target_new(names[j], kind->ops, impl, qdir, strtoull(qlim, NULL, 10), qerr, sizeof(qerr));
      free(qdir);
      free(qlim);
      if (!tg) {
        snprintf(err, errlen, "%s", qerr);
        ok = false;
        continue;
      }
      t = buckets_xrealloc(t, (k + 1) * sizeof(*t));
      t[k++] = tg;
    }
    for (size_t j = 0; j < nn; j++) free(names[j]);
    free(names);
  }
  if (!ok || !out) {
    for (size_t i = 0; i < k; i++) buckets_target_free(t[i]);
    free(t);
    return ok;
  }
  *out = t;
  *n = k;
  return true;
}

bool buckets_targets_build(const buckets_config *cfg, const char *ca_file, buckets_target ***out, size_t *n, char *err,
                           size_t errlen) {
  *out = NULL;
  *n = 0;
  return run(cfg, ca_file, out, n, err, errlen);
}

bool buckets_targets_check(const buckets_config *cfg, char *err, size_t errlen) { return run(cfg, NULL, NULL, NULL, err, errlen); }
