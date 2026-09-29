/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/prof.h"

#include <dirent.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <malloc/malloc.h>
#else
#include <link.h>
#include <malloc.h>
#endif

#include "core/common.h"

#define HZ 100
#define MAX_FRAMES 48
#define MAX_SAMPLES 32768

/* ---- the sampler -------------------------------------------------------------------------------------- */

typedef struct {
  int n;
  void *pc[MAX_FRAMES];
} stack;

static stack *g_samples;
static _Atomic size_t g_nsamples;
static _Atomic bool g_running;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct sigaction g_old;
static int64_t g_start_ns;

static void on_prof(int sig) {
  (void)sig;
  if (!atomic_load(&g_running)) return;
  size_t i = atomic_fetch_add(&g_nsamples, 1);
  if (i >= MAX_SAMPLES) return;
  stack *s = &g_samples[i];
  s->n = backtrace(s->pc, MAX_FRAMES);
}

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

bool buckets_prof_cpu_start(char *err, size_t errcap) {
  pthread_mutex_lock(&g_mu);
  if (atomic_load(&g_running)) {
    pthread_mutex_unlock(&g_mu);
    snprintf(err, errcap, "%s", "cpu profiling already in use");
    return false;
  }
  if (!g_samples) g_samples = buckets_xcalloc(MAX_SAMPLES, sizeof(stack));
  void *warm[4];
  backtrace(warm, 4); /* loads what backtrace needs outside the handler */
  atomic_store(&g_nsamples, 0);
  g_start_ns = now_ns();
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_prof;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGPROF, &sa, &g_old);
  atomic_store(&g_running, true);
  struct itimerval it = {{0, 1000000 / HZ}, {0, 1000000 / HZ}};
  setitimer(ITIMER_PROF, &it, NULL);
  pthread_mutex_unlock(&g_mu);
  return true;
}

/* ---- protobuf -------------------------------------------------------------------------------------------- */

static void pb_varint(buckets_buf *b, uint64_t v) {
  while (v >= 0x80) {
    buckets_buf_append_char(b, (char)(v | 0x80));
    v >>= 7;
  }
  buckets_buf_append_char(b, (char)v);
}

static void pb_key(buckets_buf *b, int field, int wire) { pb_varint(b, (uint64_t)field << 3 | (uint64_t)wire); }

static void pb_uint(buckets_buf *b, int field, uint64_t v) {
  if (!v) return;
  pb_key(b, field, 0);
  pb_varint(b, v);
}

static void pb_bytes(buckets_buf *b, int field, const void *data, size_t n) {
  pb_key(b, field, 2);
  pb_varint(b, n);
  buckets_buf_append(b, data, n);
}

typedef struct {
  char **v;
  size_t n;
} strtab;

static uint64_t str_index(strtab *t, const char *s) {
  for (size_t i = 0; i < t->n; i++)
    if (strcmp(t->v[i], s) == 0) return i;
  t->v = buckets_xrealloc(t->v, (t->n + 1) * sizeof(char *));
  t->v[t->n] = buckets_xstrdup(s);
  return t->n++;
}

static void value_type(buckets_buf *b, int field, strtab *t, const char *type, const char *unit) {
  buckets_buf vt = BUCKETS_BUF_INIT;
  pb_uint(&vt, 1, str_index(t, type));
  pb_uint(&vt, 2, str_index(t, unit));
  pb_bytes(b, field, vt.data ? vt.data : "", vt.len);
  buckets_buf_free(&vt);
}

/* The mappings of the process's images (their text), for symbolization. */
typedef struct {
  uint64_t start, limit, offset;
  char file[1024];
} mapping;

typedef struct {
  mapping *v;
  size_t n;
} mappings;

#ifdef __APPLE__
static void load_mappings(mappings *m) {
  uint32_t n = _dyld_image_count();
  for (uint32_t i = 0; i < n; i++) {
    const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
    if (!h || h->magic != MH_MAGIC_64) continue;
    intptr_t slide = _dyld_get_image_vmaddr_slide(i);
    const struct load_command *lc = (const struct load_command *)(h + 1);
    for (uint32_t k = 0; k < h->ncmds; k++) {
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *seg = (const struct segment_command_64 *)(const void *)lc;
        if (strcmp(seg->segname, "__TEXT") == 0) {
          m->v = buckets_xrealloc(m->v, (m->n + 1) * sizeof(mapping));
          mapping *x = &m->v[m->n++];
          x->start = seg->vmaddr + (uint64_t)slide;
          x->limit = x->start + seg->vmsize;
          x->offset = seg->fileoff;
          snprintf(x->file, sizeof(x->file), "%s", _dyld_get_image_name(i));
        }
      }
      lc = (const struct load_command *)(const void *)((const char *)lc + lc->cmdsize);
    }
  }
}
#else
static int phdr_cb(struct dl_phdr_info *info, size_t size, void *ud) {
  (void)size;
  mappings *m = ud;
  for (int k = 0; k < info->dlpi_phnum; k++) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[k];
    if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X)) continue;
    m->v = buckets_xrealloc(m->v, (m->n + 1) * sizeof(mapping));
    mapping *x = &m->v[m->n++];
    x->start = info->dlpi_addr + ph->p_vaddr;
    x->limit = x->start + ph->p_memsz;
    x->offset = ph->p_offset;
    const char *name = info->dlpi_name && *info->dlpi_name ? info->dlpi_name : NULL;
    char self[1024];
    if (!name) {
      ssize_t l = readlink("/proc/self/exe", self, sizeof(self) - 1);
      self[l > 0 ? l : 0] = '\0';
      name = self;
    }
    snprintf(x->file, sizeof(x->file), "%s", name);
  }
  return 0;
}
static void load_mappings(mappings *m) { dl_iterate_phdr(phdr_cb, m); }
#endif

typedef struct {
  const void *pc;
  uint64_t id, mapping, func;
} loc;

/* Encodes a profile: samples are stacks with their values. */
typedef struct {
  const stack *stacks;
  const int64_t *values; /* nvalues per sample */
  size_t n;
  int nvalues;
  const char *types[4], *units[4];
  const char *period_type, *period_unit;
  int64_t period, time_ns, duration_ns;
  const char *pseudo_frame; /* a single named frame per sample, when stacks is NULL */
} profile;

static void gzip_into(const buckets_buf *raw, buckets_buf *out) {
  z_stream zs;
  memset(&zs, 0, sizeof(zs));
  deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY); /* gzip */
  size_t bound = deflateBound(&zs, raw->len) + 64;
  size_t at = out->len;
  buckets_buf_reserve(out, bound);
  zs.next_in = (Bytef *)(raw->data ? raw->data : "");
  zs.avail_in = (uInt)raw->len;
  zs.next_out = (Bytef *)out->data + at;
  zs.avail_out = (uInt)bound;
  deflate(&zs, Z_FINISH);
  out->len = at + zs.total_out;
  deflateEnd(&zs);
}

static void encode(const profile *p, buckets_buf *out) {
  strtab t = {0};
  str_index(&t, "");
  buckets_buf b = BUCKETS_BUF_INIT;
  for (int k = 0; k < p->nvalues; k++) value_type(&b, 1, &t, p->types[k], p->units[k]);
  mappings maps = {0};
  if (p->stacks) load_mappings(&maps);
  loc *locs = NULL;
  size_t nlocs = 0;
  char **funcs = NULL;
  size_t nfuncs = 0;
  for (size_t i = 0; i < p->n; i++) {
    buckets_buf s = BUCKETS_BUF_INIT, ids = BUCKETS_BUF_INIT, vals = BUCKETS_BUF_INIT;
    if (p->stacks) {
      /* skip the signal handler's own frames */
      for (int f = 2; f < p->stacks[i].n; f++) {
        const void *pc = p->stacks[i].pc[f];
        uint64_t id = 0;
        for (size_t k = 0; k < nlocs && !id; k++)
          if (locs[k].pc == pc) id = locs[k].id;
        if (!id) {
          locs = buckets_xrealloc(locs, (nlocs + 1) * sizeof(loc));
          loc *l = &locs[nlocs++];
          l->pc = pc;
          l->id = nlocs;
          l->mapping = 0;
          for (size_t mm = 0; mm < maps.n; mm++)
            if ((uint64_t)pc >= maps.v[mm].start && (uint64_t)pc < maps.v[mm].limit) l->mapping = mm + 1;
          /* names the dynamic linker knows (exported symbols) */
          Dl_info di;
          l->func = 0;
          if (dladdr(pc, &di) && di.dli_sname) {
            for (size_t k = 0; k < nfuncs && !l->func; k++)
              if (strcmp(funcs[k], di.dli_sname) == 0) l->func = k + 1;
            if (!l->func) {
              funcs = buckets_xrealloc(funcs, (nfuncs + 1) * sizeof(char *));
              funcs[nfuncs++] = buckets_xstrdup(di.dli_sname);
              l->func = nfuncs;
            }
          }
          id = l->id;
        }
        pb_varint(&ids, id);
      }
    } else if (p->pseudo_frame) {
      if (!nfuncs) {
        funcs = buckets_xcalloc(1, sizeof(char *));
        funcs[nfuncs++] = buckets_xstrdup(p->pseudo_frame);
        locs = buckets_xcalloc(1, sizeof(loc));
        locs[0] = (loc){NULL, 1, 0, 1};
        nlocs = 1;
      }
      pb_varint(&ids, 1);
    }
    for (int k = 0; k < p->nvalues; k++) pb_varint(&vals, (uint64_t)p->values[i * (size_t)p->nvalues + (size_t)k]);
    if (ids.len) pb_bytes(&s, 1, ids.data, ids.len);
    if (vals.len) pb_bytes(&s, 2, vals.data, vals.len);
    pb_bytes(&b, 2, s.data ? s.data : "", s.len);
    buckets_buf_free(&s);
    buckets_buf_free(&ids);
    buckets_buf_free(&vals);
  }
  for (size_t mm = 0; mm < maps.n; mm++) {
    buckets_buf m = BUCKETS_BUF_INIT;
    pb_uint(&m, 1, mm + 1);
    pb_uint(&m, 2, maps.v[mm].start);
    pb_uint(&m, 3, maps.v[mm].limit);
    pb_uint(&m, 4, maps.v[mm].offset);
    pb_uint(&m, 5, str_index(&t, maps.v[mm].file));
    pb_bytes(&b, 3, m.data, m.len);
    buckets_buf_free(&m);
  }
  for (size_t k = 0; k < nlocs; k++) {
    buckets_buf l = BUCKETS_BUF_INIT;
    pb_uint(&l, 1, locs[k].id);
    pb_uint(&l, 2, locs[k].mapping);
    pb_uint(&l, 3, (uint64_t)locs[k].pc);
    if (locs[k].func) {
      buckets_buf line = BUCKETS_BUF_INIT;
      pb_uint(&line, 1, locs[k].func);
      pb_bytes(&l, 4, line.data, line.len);
      buckets_buf_free(&line);
    }
    pb_bytes(&b, 4, l.data, l.len);
    buckets_buf_free(&l);
  }
  for (size_t k = 0; k < nfuncs; k++) {
    buckets_buf f = BUCKETS_BUF_INIT;
    pb_uint(&f, 1, k + 1);
    pb_uint(&f, 2, str_index(&t, funcs[k]));
    pb_uint(&f, 3, str_index(&t, funcs[k]));
    pb_bytes(&b, 5, f.data, f.len);
    buckets_buf_free(&f);
    free(funcs[k]);
  }
  free(funcs);
  free(locs);
  free(maps.v);
  /* strings must be complete before they are written: period type first */
  uint64_t pt_type = 0, pt_unit = 0;
  if (p->period_type) pt_type = str_index(&t, p->period_type), pt_unit = str_index(&t, p->period_unit);
  for (size_t k = 0; k < t.n; k++) {
    pb_bytes(&b, 6, t.v[k], strlen(t.v[k]));
    free(t.v[k]);
  }
  free(t.v);
  pb_uint(&b, 9, (uint64_t)p->time_ns);
  pb_uint(&b, 10, (uint64_t)p->duration_ns);
  if (p->period_type) {
    buckets_buf vt = BUCKETS_BUF_INIT;
    pb_uint(&vt, 1, pt_type);
    pb_uint(&vt, 2, pt_unit);
    pb_bytes(&b, 11, vt.data, vt.len);
    buckets_buf_free(&vt);
    pb_uint(&b, 12, (uint64_t)p->period);
  }
  gzip_into(&b, out);
  buckets_buf_free(&b);
}

static int stack_cmp(const void *a, const void *b) {
  const stack *x = a, *y = b;
  if (x->n != y->n) return x->n < y->n ? -1 : 1;
  return memcmp(x->pc, y->pc, (size_t)x->n * sizeof(void *));
}

void buckets_prof_cpu_stop(buckets_buf *out) {
  pthread_mutex_lock(&g_mu);
  struct itimerval off = {{0, 0}, {0, 0}};
  setitimer(ITIMER_PROF, &off, NULL);
  atomic_store(&g_running, false);
  usleep(20000); /* a handler still running finishes */
  sigaction(SIGPROF, &g_old, NULL);
  size_t n = atomic_load(&g_nsamples);
  if (n > MAX_SAMPLES) n = MAX_SAMPLES;
  /* identical stacks become one sample with their count */
  stack *s = buckets_xcalloc(n ? n : 1, sizeof(stack));
  if (n) memcpy(s, g_samples, n * sizeof(stack));
  qsort(s, n, sizeof(stack), stack_cmp);
  stack *u = buckets_xcalloc(n ? n : 1, sizeof(stack));
  int64_t *vals = buckets_xcalloc(2 * (n ? n : 1), sizeof(int64_t));
  size_t k = 0;
  for (size_t i = 0; i < n; i++) {
    if (k && stack_cmp(&u[k - 1], &s[i]) == 0) {
      vals[2 * (k - 1)]++;
      vals[2 * (k - 1) + 1] += 1000000000LL / HZ;
      continue;
    }
    u[k] = s[i];
    vals[2 * k] = 1;
    vals[2 * k + 1] = 1000000000LL / HZ;
    k++;
  }
  profile p = {.stacks = u, .values = vals, .n = k, .nvalues = 2, .types = {"samples", "cpu"},
               .units = {"count", "nanoseconds"}, .period_type = "cpu", .period_unit = "nanoseconds",
               .period = 1000000000LL / HZ, .time_ns = g_start_ns, .duration_ns = now_ns() - g_start_ns};
  encode(&p, out);
  free(s);
  free(u);
  free(vals);
  pthread_mutex_unlock(&g_mu);
}

static uint64_t heap_in_use(void) {
#ifdef __APPLE__
  malloc_statistics_t st;
  malloc_zone_statistics(NULL, &st);
  return st.size_in_use;
#else
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
  struct mallinfo2 mi = mallinfo2();
  return mi.uordblks + mi.hblkhd;
#else
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  return (uint64_t)ru.ru_maxrss * 1024;
#endif
#endif
}

void buckets_prof_heap(buckets_buf *out) {
  int64_t v[4] = {1, (int64_t)heap_in_use(), 1, (int64_t)heap_in_use()};
  profile p = {.values = v, .n = 1, .nvalues = 4,
               .types = {"alloc_objects", "alloc_space", "inuse_objects", "inuse_space"},
               .units = {"count", "bytes", "count", "bytes"}, .period_type = "space", .period_unit = "bytes",
               .period = 524288, .time_ns = now_ns(), .pseudo_frame = "[heap in use]"};
  encode(&p, out);
}

static size_t thread_count(void) {
#ifdef __APPLE__
  thread_act_array_t th;
  mach_msg_type_number_t n = 0;
  if (task_threads(mach_task_self(), &th, &n) != KERN_SUCCESS) return 0;
  for (mach_msg_type_number_t i = 0; i < n; i++) mach_port_deallocate(mach_task_self(), th[i]);
  vm_deallocate(mach_task_self(), (vm_address_t)th, n * sizeof(thread_act_t));
  return n;
#else
  size_t n = 0;
  DIR *d = opendir("/proc/self/task");
  struct dirent *e;
  while (d && (e = readdir(d))) n += e->d_name[0] != '.';
  if (d) closedir(d);
  return n;
#endif
}

void buckets_prof_threads(buckets_buf *out) {
  size_t n = thread_count();
  int64_t *v = buckets_xcalloc(n ? n : 1, sizeof(int64_t));
  for (size_t i = 0; i < n; i++) v[i] = 1;
  profile p = {.values = v, .n = n, .nvalues = 1, .types = {"threadcreate"}, .units = {"count"},
               .period_type = "threadcreate", .period_unit = "count", .period = 1, .time_ns = now_ns(),
               .pseudo_frame = "[thread]"};
  encode(&p, out);
  free(v);
}

void buckets_prof_empty(const char *type1, const char *unit1, const char *type2, const char *unit2, buckets_buf *out) {
  profile p = {.nvalues = 2, .types = {type1, type2}, .units = {unit1, unit2}, .period_type = type1,
               .period_unit = unit1, .period = 1, .time_ns = now_ns()};
  encode(&p, out);
}

void buckets_prof_threads_text(buckets_buf *out) {
  buckets_buf_appendf(out, "thread profile: total %zu\n", thread_count());
}
