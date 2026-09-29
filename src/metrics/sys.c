/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "metrics/sys.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <malloc/malloc.h>
#include <sys/sysctl.h>
#endif
#ifdef __linux__
#include <malloc.h>
#include <sys/sysmacros.h>
#endif

static double g_start_time;

__attribute__((constructor)) static void note_start(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  g_start_time = (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static uint64_t count_dir(const char *path) {
  DIR *d = opendir(path);
  if (!d) return 0;
  uint64_t n = 0;
  struct dirent *e;
  while ((e = readdir(d)))
    if (e->d_name[0] != '.') n++;
  closedir(d);
  return n > 0 ? n - 1 : 0; /* the directory stream's own descriptor */
}

void buckets_proc_stats_get(buckets_proc_stats *out) {
  memset(out, 0, sizeof(*out));
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) == 0)
    out->cpu_seconds = (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1e6 + (double)ru.ru_stime.tv_sec +
                       (double)ru.ru_stime.tv_usec / 1e6;
  out->start_time = g_start_time;
  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0) out->max_fds = rl.rlim_cur == RLIM_INFINITY ? 0 : (uint64_t)rl.rlim_cur;
  if (getrlimit(RLIMIT_AS, &rl) == 0)
    out->vm_max = rl.rlim_cur == RLIM_INFINITY ? 9223372036854775807.0 : (double)rl.rlim_cur;
#ifdef __linux__
  out->open_fds = count_dir("/proc/self/fd");
  FILE *f = fopen("/proc/self/statm", "r");
  if (f) {
    unsigned long long vsz, rss;
    if (fscanf(f, "%llu %llu", &vsz, &rss) == 2) {
      long page = sysconf(_SC_PAGESIZE);
      out->virtual_size = vsz * (uint64_t)page;
      out->resident = rss * (uint64_t)page;
      out->have_memory = true;
    }
    fclose(f);
  }
  f = fopen("/proc/self/status", "r");
  if (f) {
    char line[256];
    while (fgets(line, sizeof(line), f))
      if (strncmp(line, "Threads:", 8) == 0) out->threads = strtoull(line + 8, NULL, 10);
    fclose(f);
  }
  f = fopen("/proc/self/io", "r");
  if (f) {
    char key[64];
    unsigned long long v;
    while (fscanf(f, "%63[^:]: %llu\n", key, &v) == 2) {
      if (!strcmp(key, "rchar")) out->rchar = v;
      else if (!strcmp(key, "wchar")) out->wchar = v;
      else if (!strcmp(key, "syscr")) out->syscr = v;
      else if (!strcmp(key, "syscw")) out->syscw = v;
      else if (!strcmp(key, "read_bytes")) out->read_bytes = v;
      else if (!strcmp(key, "write_bytes")) out->write_bytes = v;
    }
    out->have_io = true;
    fclose(f);
  }
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
  struct mallinfo2 mi = mallinfo2();
  out->heap_in_use = mi.uordblks;
  out->heap_system = mi.arena + mi.hblkhd;
#endif
#elif defined(__APPLE__)
  out->open_fds = count_dir("/dev/fd");
  mach_task_basic_info_data_t info;
  mach_msg_type_number_t cnt = MACH_TASK_BASIC_INFO_COUNT;
  if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &cnt) == KERN_SUCCESS) {
    out->resident = info.resident_size;
    out->virtual_size = info.virtual_size;
    out->have_memory = true;
  }
  thread_act_array_t threads;
  mach_msg_type_number_t nthreads;
  if (task_threads(mach_task_self(), &threads, &nthreads) == KERN_SUCCESS) {
    out->threads = nthreads;
    for (mach_msg_type_number_t i = 0; i < nthreads; i++) mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, nthreads * sizeof(*threads));
  }
  malloc_statistics_t ms;
  malloc_zone_statistics(NULL, &ms);
  out->heap_in_use = ms.size_in_use;
  out->heap_system = ms.size_allocated;
  out->allocations = ms.blocks_in_use;
#endif
}

bool buckets_mem_stats_get(buckets_mem_stats *out) {
  memset(out, 0, sizeof(*out));
#ifdef __linux__
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f) return false;
  char key[64];
  unsigned long long kb;
  uint64_t sreclaimable = 0;
  bool have_avail = false;
  while (fscanf(f, "%63[^:]: %llu%*[^\n]\n", key, &kb) == 2) {
    uint64_t b = kb * 1024;
    if (!strcmp(key, "MemTotal")) out->total = b;
    else if (!strcmp(key, "MemFree")) out->free = b;
    else if (!strcmp(key, "MemAvailable")) out->available = b, have_avail = true;
    else if (!strcmp(key, "Buffers")) out->buffers = b;
    else if (!strcmp(key, "Cached")) out->cache += b;
    else if (!strcmp(key, "SReclaimable")) sreclaimable = b;
    else if (!strcmp(key, "Shmem")) out->shared = b;
  }
  fclose(f);
  out->cache += sreclaimable; /* gopsutil's Cached */
  if (!have_avail) out->available = out->free + out->buffers + out->cache;
  out->used = out->total - out->free - out->buffers - out->cache;
  return out->total > 0;
#elif defined(__APPLE__)
  uint64_t total = 0;
  size_t len = sizeof(total);
  if (sysctlbyname("hw.memsize", &total, &len, NULL, 0) != 0) return false;
  vm_statistics64_data_t vm;
  mach_msg_type_number_t cnt = HOST_VM_INFO64_COUNT;
  if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vm, &cnt) != KERN_SUCCESS) return false;
  uint64_t page = (uint64_t)getpagesize();
  out->total = total;
  out->free = (uint64_t)vm.free_count * page;
  out->available = ((uint64_t)vm.free_count + vm.inactive_count) * page; /* gopsutil on darwin */
  out->used = total - out->available;
  return true;
#else
  return false;
#endif
}

bool buckets_cpu_stats_get(buckets_cpu_stats *out) {
  memset(out, 0, sizeof(*out));
  double la[3];
  if (getloadavg(la, 3) != 3) return false;
  out->load1 = la[0], out->load5 = la[1], out->load15 = la[2];
  out->cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
#ifdef __linux__
  FILE *f = fopen("/proc/stat", "r");
  if (f) {
    unsigned long long u, n, s, i, w, irq, sirq, st;
    if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &u, &n, &s, &i, &w, &irq, &sirq, &st) == 8) {
      double hz = (double)sysconf(_SC_CLK_TCK);
      out->user = (double)u / hz, out->nice = (double)n / hz, out->system = (double)s / hz;
      out->idle = (double)i / hz, out->iowait = (double)w / hz, out->steal = (double)st / hz;
      out->have_times = true;
    }
    fclose(f);
  }
#endif
  return true;
}

bool buckets_disk_io_get(const char *path, buckets_disk_io *out) {
  memset(out, 0, sizeof(*out));
#ifdef __linux__
  struct stat st;
  if (stat(path, &st) != 0) return false;
  unsigned maj = major(st.st_dev), min = minor(st.st_dev);
  FILE *f = fopen("/proc/diskstats", "r");
  if (!f) return false;
  char line[512];
  bool found = false;
  while (!found && fgets(line, sizeof(line), f)) {
    unsigned a, b;
    char name[64];
    unsigned long long r, rm, rs, rt, w, wm, ws, wt, inflight, busy;
    if (sscanf(line, "%u %u %63s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", &a, &b, name, &r, &rm, &rs, &rt, &w,
               &wm, &ws, &wt, &inflight, &busy) == 13 &&
        a == maj && b == min) {
      *out = (buckets_disk_io){r, rs, rt, w, ws, wt, busy};
      found = true;
    }
  }
  fclose(f);
  return found;
#else
  (void)path;
  return false;
#endif
}

bool buckets_net_stats_get(buckets_net_stats *out) {
  memset(out, 0, sizeof(*out));
#ifdef __linux__
  FILE *f = fopen("/proc/net/dev", "r");
  if (!f) return false;
  char line[512];
  bool found = false;
  while (!found && fgets(line, sizeof(line), f)) {
    char *colon = strchr(line, ':');
    if (!colon) continue;
    *colon = '\0';
    char *name = line;
    while (*name == ' ') name++;
    if (!strcmp(name, "lo")) continue;
    unsigned long long v[16];
    if (sscanf(colon + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", &v[0], &v[1], &v[2], &v[3],
               &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10], &v[11]) == 12) {
      snprintf(out->name, sizeof(out->name), "%s", name);
      out->rx_bytes = v[0], out->rx_errors = v[2], out->tx_bytes = v[8], out->tx_errors = v[10];
      found = true;
    }
  }
  fclose(f);
  return found;
#else
  return false;
#endif
}
