/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/loop.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/epoll.h>
#define BUCKETS_USE_EPOLL 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/event.h>
#define BUCKETS_USE_KQUEUE 1
#else
#error "unsupported platform: need epoll or kqueue"
#endif

typedef struct post {
  buckets_tick_cb cb;
  void *ud;
  struct post *next;
} post;

typedef struct {
  buckets_io_cb cb;
  void *ud;
  unsigned events;
  bool active;
} watcher;

struct buckets_loop {
  int pfd; /* epoll or kqueue descriptor */
  watcher *watchers;
  size_t nwatchers;
  int wake_pipe[2];
  buckets_tick_cb wake_cb;
  void *wake_ud;
  struct {
    buckets_tick_cb cb;
    void *ud;
  } ticks[BUCKETS_LOOP_MAX_TICKS];
  size_t nticks;
  pthread_mutex_t post_mu;
  bool post_wake_pending; /* the pipe already has a wake for the queue */
  post *post_head, *post_tail;
  volatile bool stopping;
};

static void set_nonblock_cloexec(int fd) {
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static watcher *get_watcher(buckets_loop *loop, int fd) {
  if ((size_t)fd >= loop->nwatchers) {
    size_t n = loop->nwatchers ? loop->nwatchers : 64;
    while (n <= (size_t)fd) n *= 2;
    loop->watchers = buckets_xrealloc(loop->watchers, n * sizeof(watcher));
    memset(loop->watchers + loop->nwatchers, 0, (n - loop->nwatchers) * sizeof(watcher));
    loop->nwatchers = n;
  }
  return &loop->watchers[fd];
}

static void drain_wake_pipe(buckets_loop *loop, int fd, unsigned events, void *ud) {
  char tmp[64];
  while (read(fd, tmp, sizeof(tmp)) == (ssize_t)sizeof(tmp)) {
  }
  pthread_mutex_lock(&loop->post_mu);
  loop->post_wake_pending = false; /* posts from here on wake the loop again */
  post *p = loop->post_head;
  loop->post_head = loop->post_tail = NULL;
  pthread_mutex_unlock(&loop->post_mu);
  while (p) {
    post *next = p->next;
    p->cb(loop, p->ud);
    free(p);
    p = next;
  }
  if (loop->wake_cb) loop->wake_cb(loop, loop->wake_ud);
}

buckets_loop *buckets_loop_new(void) {
  buckets_loop *loop = buckets_xcalloc(1, sizeof(*loop));
#ifdef BUCKETS_USE_EPOLL
  loop->pfd = epoll_create1(EPOLL_CLOEXEC);
#else
  loop->pfd = kqueue();
  if (loop->pfd >= 0) fcntl(loop->pfd, F_SETFD, FD_CLOEXEC);
#endif
  if (loop->pfd < 0) {
    free(loop);
    return NULL;
  }
  if (pipe(loop->wake_pipe) != 0) {
    close(loop->pfd);
    free(loop);
    return NULL;
  }
  pthread_mutex_init(&loop->post_mu, NULL);
  set_nonblock_cloexec(loop->wake_pipe[0]);
  set_nonblock_cloexec(loop->wake_pipe[1]);
  buckets_loop_watch(loop, loop->wake_pipe[0], BUCKETS_EV_READ, drain_wake_pipe, NULL);
  return loop;
}

void buckets_loop_free(buckets_loop *loop) {
  if (!loop) return;
  for (post *p = loop->post_head, *next; p; p = next) {
    next = p->next;
    free(p);
  }
  pthread_mutex_destroy(&loop->post_mu);
  close(loop->wake_pipe[0]);
  close(loop->wake_pipe[1]);
  close(loop->pfd);
  free(loop->watchers);
  free(loop);
}

#ifdef BUCKETS_USE_EPOLL
static int backend_update(buckets_loop *loop, int fd, unsigned old_ev, unsigned new_ev, bool was_active) {
  if (was_active && old_ev == new_ev) return 0; /* nothing to change: no syscall */
  struct epoll_event ev = {0};
  ev.data.fd = fd;
  if (new_ev & BUCKETS_EV_READ) ev.events |= EPOLLIN | EPOLLRDHUP;
  if (new_ev & BUCKETS_EV_WRITE) ev.events |= EPOLLOUT;
  return epoll_ctl(loop->pfd, was_active ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &ev);
}

static void backend_remove(buckets_loop *loop, int fd, unsigned old_ev) {
  epoll_ctl(loop->pfd, EPOLL_CTL_DEL, fd, NULL);
}
#else
static int backend_update(buckets_loop *loop, int fd, unsigned old_ev, unsigned new_ev, bool was_active) {
  struct kevent ch[2];
  int n = 0;
  if ((new_ev ^ old_ev) & BUCKETS_EV_READ) {
    EV_SET(&ch[n++], fd, EVFILT_READ, (new_ev & BUCKETS_EV_READ) ? EV_ADD : EV_DELETE, 0, 0, NULL);
  }
  if ((new_ev ^ old_ev) & BUCKETS_EV_WRITE) {
    EV_SET(&ch[n++], fd, EVFILT_WRITE, (new_ev & BUCKETS_EV_WRITE) ? EV_ADD : EV_DELETE, 0, 0, NULL);
  }
  return n ? kevent(loop->pfd, ch, n, NULL, 0, NULL) : 0;
}

static void backend_remove(buckets_loop *loop, int fd, unsigned old_ev) {
  backend_update(loop, fd, old_ev, 0, true);
}
#endif

int buckets_loop_watch(buckets_loop *loop, int fd, unsigned events, buckets_io_cb cb, void *ud) {
  watcher *w = get_watcher(loop, fd);
  unsigned old = w->active ? w->events : 0;
  if (backend_update(loop, fd, old, events, w->active) != 0) return -1;
  w->cb = cb;
  w->ud = ud;
  w->events = events;
  w->active = true;
  return 0;
}

void buckets_loop_unwatch(buckets_loop *loop, int fd) {
  if ((size_t)fd >= loop->nwatchers || !loop->watchers[fd].active) return;
  watcher *w = &loop->watchers[fd];
  backend_remove(loop, fd, w->events);
  memset(w, 0, sizeof(*w));
}

int buckets_loop_add_tick(buckets_loop *loop, buckets_tick_cb cb, void *ud) {
  if (loop->nticks == BUCKETS_LOOP_MAX_TICKS) return -1;
  loop->ticks[loop->nticks].cb = cb;
  loop->ticks[loop->nticks].ud = ud;
  loop->nticks++;
  return 0;
}

void buckets_loop_set_wake(buckets_loop *loop, buckets_tick_cb cb, void *ud) {
  loop->wake_cb = cb;
  loop->wake_ud = ud;
}

void buckets_loop_wake(buckets_loop *loop) {
  int saved = errno;
  ssize_t r = write(loop->wake_pipe[1], "x", 1);
  (void)r;
  errno = saved;
}

void buckets_loop_post(buckets_loop *loop, buckets_tick_cb cb, void *ud) {
  post *p = buckets_xcalloc(1, sizeof(*p));
  p->cb = cb;
  p->ud = ud;
  pthread_mutex_lock(&loop->post_mu);
  if (loop->post_tail) loop->post_tail->next = p;
  else loop->post_head = p;
  loop->post_tail = p;
  /* One wake per batch: posts made before the loop drains share it. */
  bool wake = !loop->post_wake_pending;
  loop->post_wake_pending = true;
  pthread_mutex_unlock(&loop->post_mu);
  if (wake) buckets_loop_wake(loop);
}

void buckets_loop_stop(buckets_loop *loop) {
  loop->stopping = true;
  buckets_loop_wake(loop);
}

static void dispatch(buckets_loop *loop, int fd, unsigned events) {
  if ((size_t)fd >= loop->nwatchers) return;
  watcher *w = &loop->watchers[fd];
  if (!w->active || !w->cb) return;
  w->cb(loop, fd, events, w->ud);
}

int buckets_loop_run(buckets_loop *loop) {
  enum { MAX_EVENTS = 256 };
  time_t last_tick = time(NULL);
  while (!loop->stopping) {
#ifdef BUCKETS_USE_EPOLL
    struct epoll_event evs[MAX_EVENTS];
    int n = epoll_wait(loop->pfd, evs, MAX_EVENTS, 1000);
    if (n < 0 && errno != EINTR) return -1;
    for (int i = 0; i < n; i++) {
      unsigned e = 0;
      if (evs[i].events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) e |= BUCKETS_EV_READ;
      if (evs[i].events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) e |= BUCKETS_EV_ERROR;
      if (evs[i].events & EPOLLOUT) e |= BUCKETS_EV_WRITE;
      dispatch(loop, evs[i].data.fd, e);
    }
#else
    struct kevent evs[MAX_EVENTS];
    struct timespec ts = {1, 0};
    int n = kevent(loop->pfd, NULL, 0, evs, MAX_EVENTS, &ts);
    if (n < 0 && errno != EINTR) return -1;
    for (int i = 0; i < n; i++) {
      unsigned e = 0;
      if (evs[i].filter == EVFILT_READ) e |= BUCKETS_EV_READ;
      if (evs[i].filter == EVFILT_WRITE) e |= BUCKETS_EV_WRITE;
      if (evs[i].flags & (EV_EOF | EV_ERROR)) e |= BUCKETS_EV_ERROR;
      dispatch(loop, (int)evs[i].ident, e);
    }
#endif
    time_t now = time(NULL);
    if (now != last_tick) {
      last_tick = now;
      for (size_t i = 0; i < loop->nticks; i++) loop->ticks[i].cb(loop, loop->ticks[i].ud);
    }
  }
  return 0;
}
