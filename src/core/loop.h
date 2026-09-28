/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_LOOP_H
#define BUCKETS_CORE_LOOP_H

#include "core/common.h"

/* Readiness-based event loop: epoll on Linux, kqueue on macOS/BSD.
 * An io_uring backend for disk and network I/O is planned; this interface is
 * deliberately small so the backend can change underneath it. */

enum {
  BUCKETS_EV_READ = 1u << 0,
  BUCKETS_EV_WRITE = 1u << 1,
  BUCKETS_EV_ERROR = 1u << 2, /* hangup or error; delivered with READ */
};

typedef struct buckets_loop buckets_loop;
typedef void (*buckets_io_cb)(buckets_loop *loop, int fd, unsigned events, void *ud);
typedef void (*buckets_tick_cb)(buckets_loop *loop, void *ud);

buckets_loop *buckets_loop_new(void);
void buckets_loop_free(buckets_loop *loop);

/* Registers or updates interest in fd. events == 0 keeps fd registered but idle. */
int buckets_loop_watch(buckets_loop *loop, int fd, unsigned events, buckets_io_cb cb, void *ud);
void buckets_loop_unwatch(buckets_loop *loop, int fd);

/* Registers a callback run roughly once per second on the loop thread (idle
 * timeouts, shutdown drains). Up to BUCKETS_LOOP_MAX_TICKS may be added. */
#define BUCKETS_LOOP_MAX_TICKS 8
int buckets_loop_add_tick(buckets_loop *loop, buckets_tick_cb cb, void *ud);

/* Runs until buckets_loop_stop(). Returns 0 on clean stop. */
int buckets_loop_run(buckets_loop *loop);
void buckets_loop_stop(buckets_loop *loop);

/* Async-signal-safe: wakes the loop from a signal handler or another thread.
 * The wake callback runs on the loop thread. */
void buckets_loop_set_wake(buckets_loop *loop, buckets_tick_cb cb, void *ud);
void buckets_loop_wake(buckets_loop *loop);

/* Thread-safe: runs cb(loop, ud) on the loop thread, in posting order. This is
 * how worker threads hand results back to the loop. Posts still queued when
 * the loop is freed are dropped. */
void buckets_loop_post(buckets_loop *loop, buckets_tick_cb cb, void *ud);

#endif
