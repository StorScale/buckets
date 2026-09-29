/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc support diag (HealthInfoHandler): madmin.HealthInfo, sent again after
 * each section it gathers (every node's CPUs, partitions, network, OS,
 * memory, process, system errors, services and configuration, then the
 * server's configuration, redacted, and its info), with whitespace every 5
 * seconds meanwhile. The sections carry what gopsutil gives MinIO on Linux
 * (from /proc and /sys), and elsewhere the errors MinIO reports there.
 * Replaces HealthInfoHandler and fetchHealthInfo (cmd/admin-handlers.go)
 * and madmin's collectors. */
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>

#ifdef __APPLE__
#include <libproc.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#endif
#ifdef __linux__
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#endif

#include "admin/admin.h"
#include "admin/info.h"
#include "admin/jobstream.h"
#include "config/config.h"
#include "config/sys.h"
#include "core/timefmt.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "notify/event.h"
#include "object/nslock.h"
#include "s3/xml.h"

#define NOT_LINUX "Not implemented for non-linux platforms"
#define UNSUPPORTED_OS "unsupported operating system " BUCKETS_OS_NAME

#ifdef __APPLE__
#define BUCKETS_OS_NAME "darwin"
#elif defined(__linux__)
#define BUCKETS_OS_NAME "linux"
#else
#define BUCKETS_OS_NAME "unknown"
#endif

extern char **environ;

static char *read_file(const char *path, size_t max) {
  FILE *f = fopen(path, "r");
  if (!f) return NULL;
  char *buf = buckets_xmalloc(max + 1);
  size_t n = fread(buf, 1, max, f);
  fclose(f);
  buf[n] = '\0';
  return buf;
}

static void trim(char *s) {
  size_t n = strlen(s);
  while (n && (s[n - 1] == '\n' || s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
}

static yyjson_mut_val *node_common(yyjson_mut_doc *d, const char *addr, const char *err) {
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, o, "addr", addr);
  if (err && *err) yyjson_mut_obj_add_strcpy(d, o, "error", err);
  return o;
}

/* ---- sections (this node) ------------------------------------------------------------------------ */

static yyjson_mut_val *sec_cpus(yyjson_mut_doc *d, const char *addr) {
#ifdef __linux__
  yyjson_mut_val *o = node_common(d, addr, NULL);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, o, "cpus");
  char *info = read_file("/proc/cpuinfo", 1 << 22);
  char seen[64][32];
  size_t nseen = 0;
  for (char *blk = info; blk && *blk;) {
    char *next = strstr(blk, "\n\n");
    if (next) *next = '\0';
    char vendor[128] = "", family[32] = "", model[32] = "", phys[32] = "", name[256] = "", micro[64] = "",
         flags[8192] = "";
    int stepping = 0, cores = 0;
    double mhz = 0;
    int cache = 0;
    for (char *line = strtok(blk, "\n"); line; line = strtok(NULL, "\n")) {
      char *colon = strchr(line, ':');
      if (!colon) continue;
      *colon = '\0';
      char *k = line, *v = colon + 1;
      trim(k);
      while (*v == ' ') v++;
      if (!strcmp(k, "vendor_id")) snprintf(vendor, sizeof(vendor), "%s", v);
      else if (!strcmp(k, "cpu family")) snprintf(family, sizeof(family), "%s", v);
      else if (!strcmp(k, "model")) snprintf(model, sizeof(model), "%s", v);
      else if (!strcmp(k, "stepping")) stepping = atoi(v);
      else if (!strcmp(k, "physical id")) snprintf(phys, sizeof(phys), "%s", v);
      else if (!strcmp(k, "model name")) snprintf(name, sizeof(name), "%s", v);
      else if (!strcmp(k, "cpu MHz")) mhz = atof(v);
      else if (!strcmp(k, "cache size")) cache = atoi(v);
      else if (!strcmp(k, "flags") || !strcmp(k, "Features")) snprintf(flags, sizeof(flags), "%s", v);
      else if (!strcmp(k, "microcode")) snprintf(micro, sizeof(micro), "%s", v);
      else if (!strcmp(k, "cpu cores")) cores = atoi(v);
    }
    /* one entry per physical CPU (madmin.GetCPUs) */
    bool dup = false;
    for (size_t i = 0; i < nseen && !dup; i++) dup = !strcmp(seen[i], phys);
    if (!dup && nseen < 64) {
      snprintf(seen[nseen++], 32, "%s", phys);
      yyjson_mut_val *c = yyjson_mut_arr_add_obj(d, arr);
      yyjson_mut_obj_add_strcpy(d, c, "vendor_id", vendor);
      yyjson_mut_obj_add_strcpy(d, c, "family", *family ? family : "0");
      yyjson_mut_obj_add_strcpy(d, c, "model", *model ? model : "0");
      yyjson_mut_obj_add_int(d, c, "stepping", stepping);
      yyjson_mut_obj_add_strcpy(d, c, "physical_id", phys);
      yyjson_mut_obj_add_strcpy(d, c, "model_name", name);
      yyjson_mut_obj_add_real(d, c, "mhz", mhz);
      yyjson_mut_obj_add_int(d, c, "cache_size", cache);
      yyjson_mut_val *fl = *flags ? yyjson_mut_obj_add_arr(d, c, "flags") : NULL;
      if (!fl) yyjson_mut_obj_add_null(d, c, "flags");
      for (char *f = fl ? strtok(flags, " ") : NULL; f; f = strtok(NULL, " ")) yyjson_mut_arr_add_strcpy(d, fl, f);
      yyjson_mut_obj_add_strcpy(d, c, "microcode", micro);
      yyjson_mut_obj_add_int(d, c, "cores", cores ? cores : 1);
    }
    blk = next ? next + 2 : NULL;
  }
  free(info);
  return o;
#else
  yyjson_mut_val *o = node_common(d, addr, NOT_LINUX);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, o, "cpus");
  yyjson_mut_val *c = yyjson_mut_arr_add_obj(d, arr);
  char brand[256] = "";
#ifdef __APPLE__
  size_t bl = sizeof(brand);
  sysctlbyname("machdep.cpu.brand_string", brand, &bl, NULL, 0);
#endif
  yyjson_mut_obj_add_str(d, c, "vendor_id", "");
  yyjson_mut_obj_add_str(d, c, "family", "0");
  yyjson_mut_obj_add_str(d, c, "model", "0");
  yyjson_mut_obj_add_int(d, c, "stepping", 0);
  yyjson_mut_obj_add_str(d, c, "physical_id", "");
  yyjson_mut_obj_add_strcpy(d, c, "model_name", brand);
  yyjson_mut_obj_add_int(d, c, "mhz", 0);
  yyjson_mut_obj_add_int(d, c, "cache_size", 0);
  yyjson_mut_obj_add_null(d, c, "flags");
  yyjson_mut_obj_add_str(d, c, "microcode", "");
  yyjson_mut_obj_add_int(d, c, "cores", 1);
  return o;
#endif
}

static yyjson_mut_val *sec_partitions(yyjson_mut_doc *d, const char *addr, const buckets_cluster_info *ci) {
#ifdef __linux__
  yyjson_mut_val *o = node_common(d, addr, NULL);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, o, "partitions");
  char *mi = read_file("/proc/self/mountinfo", 1 << 22);
  dev_t done[256];
  size_t ndone = 0;
  for (size_t i = 0; ci && i < ci->neps; i++) {
    if (!ci->eps[i].local) continue;
    struct stat st;
    struct statvfs sv;
    if (stat(ci->eps[i].path, &st) != 0 || statvfs(ci->eps[i].path, &sv) != 0) continue;
    bool dup = false;
    for (size_t k = 0; k < ndone && !dup; k++) dup = done[k] == st.st_dev;
    if (dup || ndone >= 256) continue;
    done[ndone++] = st.st_dev;
    /* the mount of that device: "id parent maj:min root mountpoint options ... - fstype source superopts" */
    char device[512] = "", mountpoint[1024] = "", options[1024] = "", fstype[64] = "", super[1024] = "";
    char want[32];
    snprintf(want, sizeof(want), "%u:%u", major(st.st_dev), minor(st.st_dev));
    for (char *line = mi; line && *line;) {
      char *eol = strchr(line, '\n');
      if (eol) *eol = '\0';
      char id[32], parent[32], mm[32], root[1024], mp[1024], opts[1024];
      if (sscanf(line, "%31s %31s %31s %1023s %1023s %1023s", id, parent, mm, root, mp, opts) == 6 && !strcmp(mm, want)) {
        char *dash = strstr(line, " - ");
        if (dash) sscanf(dash + 3, "%63s %511s %1023s", fstype, device, super);
        snprintf(mountpoint, sizeof(mountpoint), "%s", mp);
        snprintf(options, sizeof(options), "%s", opts);
      }
      if (eol) *eol = '\n';
      line = eol ? eol + 1 : NULL;
    }
    yyjson_mut_val *p = yyjson_mut_arr_add_obj(d, arr);
    if (*device) yyjson_mut_obj_add_strcpy(d, p, "device", device);
    yyjson_mut_obj_add_uint(d, p, "major", major(st.st_dev));
    yyjson_mut_obj_add_uint(d, p, "minor", minor(st.st_dev));
    const char *base = strrchr(device, '/');
    char path[1100];
    snprintf(path, sizeof(path), "/sys/class/block/%s/device/model", base ? base + 1 : device);
    char *model = read_file(path, 256);
    if (model) {
      trim(model);
      if (*model) yyjson_mut_obj_add_strcpy(d, p, "model", model);
      free(model);
    }
    if (*mountpoint) yyjson_mut_obj_add_strcpy(d, p, "mountpoint", mountpoint);
    if (*fstype) yyjson_mut_obj_add_strcpy(d, p, "fs_type", fstype);
    if (*options) yyjson_mut_obj_add_strcpy(d, p, "mount_options", options);
    if (*super) yyjson_mut_obj_add_strcpy(d, p, "mount_fs_type", super);
    uint64_t total = (uint64_t)sv.f_blocks * sv.f_frsize;
    if (total) yyjson_mut_obj_add_uint(d, p, "space_total", total);
    if (sv.f_bavail) yyjson_mut_obj_add_uint(d, p, "space_free", (uint64_t)sv.f_bavail * sv.f_frsize);
    if (sv.f_files) yyjson_mut_obj_add_uint(d, p, "inode_total", (uint64_t)sv.f_files);
    if (sv.f_ffree) yyjson_mut_obj_add_uint(d, p, "inode_free", (uint64_t)sv.f_ffree);
  }
  free(mi);
  return o;
#else
  (void)ci;
  return node_common(d, addr, UNSUPPORTED_OS);
#endif
}

/* the interface carrying this node's address (globalInternodeInterface) */
static void node_interface(const char *addr, char *out, size_t cap) {
  *out = '\0';
  char host[256];
  snprintf(host, sizeof(host), "%s", addr);
  char *colon = strrchr(host, ':');
  if (colon) *colon = '\0';
  struct in_addr want;
  bool v4 = inet_pton(AF_INET, host, &want) == 1;
  struct ifaddrs *ifs = NULL, *first = NULL;
  if (getifaddrs(&ifs) != 0) return;
  for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
    if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
    if (!first && (i->ifa_flags & IFF_LOOPBACK) == 0) first = i;
    if (v4 && ((struct sockaddr_in *)(void *)i->ifa_addr)->sin_addr.s_addr == want.s_addr) {
      snprintf(out, cap, "%s", i->ifa_name);
      break;
    }
  }
  if (!*out && first) snprintf(out, cap, "%s", first->ifa_name);
  freeifaddrs(ifs);
}

static yyjson_mut_val *sec_netinfo(yyjson_mut_doc *d, const char *addr) {
  char ifname[64];
  node_interface(addr, ifname, sizeof(ifname));
#ifdef __linux__
  char err[256] = "", driver[64] = "", fw[64] = "";
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct ethtool_drvinfo di;
  memset(&di, 0, sizeof(di));
  di.cmd = ETHTOOL_GDRVINFO;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
  ifr.ifr_data = (void *)&di;
  if (fd < 0 || ioctl(fd, SIOCETHTOOL, &ifr) != 0) snprintf(err, sizeof(err), "%s", strerror(errno));
  else snprintf(driver, sizeof(driver), "%s", di.driver), snprintf(fw, sizeof(fw), "%s", di.fw_version);
  if (fd >= 0) close(fd);
  yyjson_mut_val *o = node_common(d, addr, err);
  if (*ifname) yyjson_mut_obj_add_strcpy(d, o, "interface", ifname);
  if (*driver) yyjson_mut_obj_add_strcpy(d, o, "driver", driver);
  if (*fw) yyjson_mut_obj_add_strcpy(d, o, "firmware_version", fw);
  return o;
#else
  yyjson_mut_val *o = node_common(d, addr, NOT_LINUX);
  if (*ifname) yyjson_mut_obj_add_strcpy(d, o, "interface", ifname);
  return o;
#endif
}

#ifdef __linux__
static void os_release(const char *key, char *out, size_t cap) {
  *out = '\0';
  char *rel = read_file("/etc/os-release", 1 << 16);
  size_t kl = strlen(key);
  for (char *line = rel ? strtok(rel, "\n") : NULL; line; line = strtok(NULL, "\n")) {
    if (strncmp(line, key, kl) || line[kl] != '=') continue;
    char *v = line + kl + 1;
    if (*v == '"') v++;
    snprintf(out, cap, "%s", v);
    size_t n = strlen(out);
    if (n && out[n - 1] == '"') out[n - 1] = '\0';
  }
  free(rel);
}
#endif

static yyjson_mut_val *sec_osinfo(yyjson_mut_doc *d, const char *addr) {
#ifdef __linux__
  yyjson_mut_val *o = node_common(d, addr, NULL);
  yyjson_mut_val *i = yyjson_mut_obj_add_obj(d, o, "info");
  struct utsname u;
  uname(&u);
  char host[256] = "";
  gethostname(host, sizeof(host));
  char *up = read_file("/proc/uptime", 128);
  uint64_t uptime = up ? (uint64_t)atof(up) : 0;
  free(up);
  uint64_t boot = (uint64_t)time(NULL) - uptime;
  size_t procs = 0;
  DIR *pd = opendir("/proc");
  struct dirent *e;
  while (pd && (e = readdir(pd))) procs += e->d_name[0] >= '0' && e->d_name[0] <= '9';
  if (pd) closedir(pd);
  char id[128], ver[128], like[128], family[64] = "";
  os_release("ID", id, sizeof(id));
  os_release("VERSION_ID", ver, sizeof(ver));
  os_release("ID_LIKE", like, sizeof(like));
  if (strstr(id, "debian") || strstr(id, "ubuntu") || strstr(like, "debian")) snprintf(family, sizeof(family), "debian");
  else if (strstr(id, "rhel") || strstr(id, "centos") || strstr(id, "fedora") || strstr(like, "rhel"))
    snprintf(family, sizeof(family), "rhel");
  else if (strstr(id, "suse") || strstr(like, "suse")) snprintf(family, sizeof(family), "suse");
  else if (strstr(id, "alpine")) snprintf(family, sizeof(family), "alpine");
  char *mid = read_file("/etc/machine-id", 128);
  if (mid) trim(mid);
  yyjson_mut_obj_add_strcpy(d, i, "hostname", host);
  yyjson_mut_obj_add_uint(d, i, "uptime", uptime);
  yyjson_mut_obj_add_uint(d, i, "bootTime", boot);
  yyjson_mut_obj_add_uint(d, i, "procs", procs);
  yyjson_mut_obj_add_str(d, i, "os", "linux");
  yyjson_mut_obj_add_strcpy(d, i, "platform", id);
  yyjson_mut_obj_add_strcpy(d, i, "platformFamily", family);
  yyjson_mut_obj_add_strcpy(d, i, "platformVersion", ver);
  yyjson_mut_obj_add_strcpy(d, i, "kernelVersion", u.release);
  yyjson_mut_obj_add_strcpy(d, i, "kernelArch", u.machine);
  bool docker = access("/.dockerenv", F_OK) == 0;
  yyjson_mut_obj_add_str(d, i, "virtualizationSystem", docker ? "docker" : "");
  yyjson_mut_obj_add_str(d, i, "virtualizationRole", docker ? "guest" : "");
  yyjson_mut_obj_add_strcpy(d, i, "hostId", mid ? mid : "");
  free(mid);
  return o;
#else
  yyjson_mut_val *o = node_common(d, addr, UNSUPPORTED_OS);
  yyjson_mut_val *i = yyjson_mut_obj_add_obj(d, o, "info");
  yyjson_mut_obj_add_str(d, i, "hostname", "");
  yyjson_mut_obj_add_uint(d, i, "uptime", 0);
  yyjson_mut_obj_add_uint(d, i, "bootTime", 0);
  yyjson_mut_obj_add_uint(d, i, "procs", 0);
  static const char *const rest[] = {"os", "platform", "platformFamily", "platformVersion", "kernelVersion",
                                     "kernelArch", "virtualizationSystem", "virtualizationRole", "hostId"};
  for (size_t k = 0; k < BUCKETS_ARRAY_LEN(rest); k++) yyjson_mut_obj_add_str(d, i, rest[k], "");
  return o;
#endif
}

static yyjson_mut_val *sec_meminfo(yyjson_mut_doc *d, const char *addr) {
  uint64_t total = 0, freeb = 0, avail = 0, shared = 0, cache = 0, buffers = 0, swap_t = 0, swap_f = 0, limit = 0;
#ifdef __linux__
  char *mi = read_file("/proc/meminfo", 1 << 16);
  for (char *line = mi ? strtok(mi, "\n") : NULL; line; line = strtok(NULL, "\n")) {
    char k[64];
    unsigned long long v;
    if (sscanf(line, "%63[^:]: %llu", k, &v) != 2) continue;
    v *= 1024;
    if (!strcmp(k, "MemTotal")) total = v;
    else if (!strcmp(k, "MemFree")) freeb = v;
    else if (!strcmp(k, "MemAvailable")) avail = v;
    else if (!strcmp(k, "Shmem")) shared = v;
    else if (!strcmp(k, "Cached")) cache = v;
    else if (!strcmp(k, "Buffers")) buffers = v;
    else if (!strcmp(k, "SwapTotal")) swap_t = v;
    else if (!strcmp(k, "SwapFree")) swap_f = v;
  }
  free(mi);
  /* a cgroup's limit, when lower */
  char *cg = read_file("/sys/fs/cgroup/memory.max", 64);
  if (!cg) cg = read_file("/sys/fs/cgroup/memory/memory.limit_in_bytes", 64);
  limit = total;
  if (cg && strncmp(cg, "max", 3)) {
    uint64_t l = strtoull(cg, NULL, 10);
    if (l && l < total) limit = l;
  }
  free(cg);
  uint64_t used = total - freeb - buffers - cache;
#else
#ifdef __APPLE__
  size_t sz = sizeof(total);
  sysctlbyname("hw.memsize", &total, &sz, NULL, 0);
  vm_statistics64_data_t vm;
  mach_msg_type_number_t cnt = HOST_VM_INFO64_COUNT;
  host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vm, &cnt);
  vm_size_t page = 0;
  host_page_size(mach_host_self(), &page);
  freeb = (uint64_t)vm.free_count * page;
  avail = ((uint64_t)vm.free_count + vm.inactive_count) * page;
  struct xsw_usage sw;
  sz = sizeof(sw);
  if (sysctlbyname("vm.swapusage", &sw, &sz, NULL, 0) == 0) swap_t = sw.xsu_total, swap_f = sw.xsu_avail;
#endif
  limit = total;
  uint64_t used = total > avail ? total - avail : 0;
#endif
  yyjson_mut_val *o = node_common(d, addr, NULL);
#define U(k, v) \
  if (v) yyjson_mut_obj_add_uint(d, o, k, v)
  U("total", total);
  U("used", used);
  U("free", freeb);
  U("available", avail);
  U("shared", shared);
  U("cache", cache);
  U("buffer", buffers);
  U("swap_space_total", swap_t);
  U("swap_space_free", swap_f);
  U("limit", limit);
#undef U
  return o;
}

static yyjson_mut_val *sec_procinfo(yyjson_mut_doc *d, const char *addr) {
  pid_t pid = getpid();
  char cmdline[8192] = "";
  int64_t create_ms = 0;
  double cpu_pct = 0;
#ifdef __linux__
  char *cl = read_file("/proc/self/cmdline", sizeof(cmdline) - 1);
  size_t cn = 0;
  if (cl) {
    FILE *f = fopen("/proc/self/cmdline", "r");
    cn = f ? fread(cmdline, 1, sizeof(cmdline) - 1, f) : 0;
    if (f) fclose(f);
    for (size_t i = 0; i + 1 < cn; i++)
      if (!cmdline[i]) cmdline[i] = ' ';
    cmdline[cn ? cn - 1 : 0] = '\0';
    free(cl);
  }
  /* /proc/self/stat: times, faults, threads, start time */
  char *st = read_file("/proc/self/stat", 4096);
  unsigned long long minflt = 0, cminflt = 0, majflt = 0, cmajflt = 0, utime = 0, stime = 0, starttime = 0, vsize = 0;
  long long rss = 0, nice = 0, threads = 0, ppid = 0;
  char state = 'R';
  char *rp = st ? strrchr(st, ')') : NULL;
  if (rp)
    sscanf(rp + 2, "%c %lld %*d %*d %*d %*d %*u %llu %llu %llu %llu %llu %llu %*d %*d %*d %lld %lld %*d %llu %llu %lld",
           &state, &ppid, &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime, &nice, &threads, &starttime, &vsize,
           &rss);
  free(st);
  long hz = sysconf(_SC_CLK_TCK), pagesz = sysconf(_SC_PAGESIZE);
  char *upt = read_file("/proc/uptime", 128);
  double uptime = upt ? atof(upt) : 0;
  free(upt);
  double started = (double)time(NULL) - uptime + (double)starttime / (double)hz;
  create_ms = (int64_t)(started * 1000);
  double elapsed = (double)time(NULL) - started;
  cpu_pct = elapsed > 0 ? ((double)(utime + stime) / (double)hz) / elapsed * 100 : 0;
  /* status: context switches, uids, gids, hwm, data, stack, locked, swap */
  unsigned long long vol = 0, invol = 0, hwm = 0, data = 0, stk = 0, lck = 0, swp = 0;
  int uids[4] = {0}, gids[4] = {0};
  char *ss = read_file("/proc/self/status", 1 << 16);
  for (char *line = ss ? strtok(ss, "\n") : NULL; line; line = strtok(NULL, "\n")) {
    sscanf(line, "voluntary_ctxt_switches: %llu", &vol);
    sscanf(line, "nonvoluntary_ctxt_switches: %llu", &invol);
    sscanf(line, "VmHWM: %llu", &hwm);
    sscanf(line, "VmData: %llu", &data);
    sscanf(line, "VmStk: %llu", &stk);
    sscanf(line, "VmLck: %llu", &lck);
    sscanf(line, "VmSwap: %llu", &swp);
    sscanf(line, "Uid: %d %d %d %d", &uids[0], &uids[1], &uids[2], &uids[3]);
    sscanf(line, "Gid: %d %d %d %d", &gids[0], &gids[1], &gids[2], &gids[3]);
  }
  free(ss);
  unsigned long long rc = 0, wc = 0, rb = 0, wb = 0;
  char *io = read_file("/proc/self/io", 4096);
  for (char *line = io ? strtok(io, "\n") : NULL; line; line = strtok(NULL, "\n")) {
    sscanf(line, "syscr: %llu", &rc);
    sscanf(line, "syscw: %llu", &wc);
    sscanf(line, "read_bytes: %llu", &rb);
    sscanf(line, "write_bytes: %llu", &wb);
  }
  free(io);
  size_t nfds = 0, nconn = 0;
  DIR *fdd = opendir("/proc/self/fd");
  struct dirent *e;
  while (fdd && (e = readdir(fdd))) {
    if (e->d_name[0] == '.') continue;
    nfds++;
    char lp[64], tgt[128];
    snprintf(lp, sizeof(lp), "/proc/self/fd/%s", e->d_name);
    ssize_t l = readlink(lp, tgt, sizeof(tgt) - 1);
    if (l > 0 && strncmp(tgt, "socket:", 7) == 0) nconn++;
  }
  if (fdd) closedir(fdd);
  char cwd[4096] = "", exe[4096] = "";
  if (!getcwd(cwd, sizeof(cwd))) cwd[0] = '\0';
  ssize_t el = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  exe[el > 0 ? el : 0] = '\0';
  const char *name = strrchr(exe, '/');
  yyjson_mut_val *o = node_common(d, addr, NULL);
  yyjson_mut_obj_add_int(d, o, "pid", pid);
  yyjson_mut_obj_add_bool(d, o, "is_background", true);
  if (cpu_pct > 0) yyjson_mut_obj_add_real(d, o, "cpu_percent", cpu_pct);
  yyjson_mut_obj_add_strcpy(d, o, "cmd_line", cmdline);
  if (nconn) yyjson_mut_obj_add_uint(d, o, "num_connections", nconn);
  yyjson_mut_obj_add_int(d, o, "create_time", create_ms);
  if (*cwd) yyjson_mut_obj_add_strcpy(d, o, "cwd", cwd);
  if (*exe) yyjson_mut_obj_add_strcpy(d, o, "exec_path", exe);
  yyjson_mut_val *g = yyjson_mut_obj_add_arr(d, o, "gids");
  for (int k = 0; k < 4; k++) yyjson_mut_arr_add_int(d, g, gids[k]);
  yyjson_mut_val *ioc = yyjson_mut_obj_add_obj(d, o, "iocounters");
  yyjson_mut_obj_add_uint(d, ioc, "readCount", rc);
  yyjson_mut_obj_add_uint(d, ioc, "writeCount", wc);
  yyjson_mut_obj_add_uint(d, ioc, "readBytes", rb);
  yyjson_mut_obj_add_uint(d, ioc, "writeBytes", wb);
  yyjson_mut_obj_add_bool(d, o, "is_running", true);
  yyjson_mut_val *mem = yyjson_mut_obj_add_obj(d, o, "mem_info");
  yyjson_mut_obj_add_uint(d, mem, "rss", (uint64_t)rss * (uint64_t)pagesz);
  yyjson_mut_obj_add_uint(d, mem, "vms", vsize);
  yyjson_mut_obj_add_uint(d, mem, "hwm", hwm * 1024);
  yyjson_mut_obj_add_uint(d, mem, "data", data * 1024);
  yyjson_mut_obj_add_uint(d, mem, "stack", stk * 1024);
  yyjson_mut_obj_add_uint(d, mem, "locked", lck * 1024);
  yyjson_mut_obj_add_uint(d, mem, "swap", swp * 1024);
  if (name) yyjson_mut_obj_add_strcpy(d, o, "name", name + 1);
  if (nice) yyjson_mut_obj_add_int(d, o, "nice", nice);
  yyjson_mut_val *cs = yyjson_mut_obj_add_obj(d, o, "num_ctx_switches");
  yyjson_mut_obj_add_uint(d, cs, "voluntary", vol);
  yyjson_mut_obj_add_uint(d, cs, "involuntary", invol);
  if (nfds) yyjson_mut_obj_add_uint(d, o, "num_fds", nfds);
  if (threads) yyjson_mut_obj_add_int(d, o, "num_threads", threads);
  yyjson_mut_val *pf = yyjson_mut_obj_add_obj(d, o, "page_faults");
  yyjson_mut_obj_add_uint(d, pf, "minorFaults", minflt);
  yyjson_mut_obj_add_uint(d, pf, "majorFaults", majflt);
  yyjson_mut_obj_add_uint(d, pf, "childMinorFaults", cminflt);
  yyjson_mut_obj_add_uint(d, pf, "childMajorFaults", cmajflt);
  if (ppid) yyjson_mut_obj_add_int(d, o, "ppid", ppid);
  char stat_s[2] = {state, 0};
  yyjson_mut_obj_add_strcpy(d, o, "status", stat_s);
  yyjson_mut_obj_add_int(d, o, "tgid", pid);
  yyjson_mut_val *t = yyjson_mut_obj_add_obj(d, o, "times");
  yyjson_mut_obj_add_str(d, t, "cpu", "cpu");
  yyjson_mut_obj_add_real(d, t, "user", (double)utime / (double)hz);
  yyjson_mut_obj_add_real(d, t, "system", (double)stime / (double)hz);
  static const char *const zeros[] = {"idle", "nice", "iowait", "irq", "softirq", "steal", "guest", "guestNice"};
  for (size_t k = 0; k < BUCKETS_ARRAY_LEN(zeros); k++) yyjson_mut_obj_add_int(d, t, zeros[k], 0);
  yyjson_mut_val *u = yyjson_mut_obj_add_arr(d, o, "uids");
  for (int k = 0; k < 4; k++) yyjson_mut_arr_add_int(d, u, uids[k]);
  return o;
#else
#ifdef __APPLE__
  struct proc_bsdinfo bi;
  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof(bi)) == (int)sizeof(bi)) {
    create_ms = (int64_t)bi.pbi_start_tvsec * 1000 + bi.pbi_start_tvusec / 1000;
  }
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  double cpu = (double)ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 + ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
  struct timeval now;
  gettimeofday(&now, NULL);
  double elapsed = (double)now.tv_sec + now.tv_usec / 1e6 - (double)create_ms / 1000;
  cpu_pct = elapsed > 0 ? cpu / elapsed * 100 : 0;
  char args[PROC_PIDPATHINFO_MAXSIZE];
  if (proc_pidpath(pid, args, sizeof(args)) > 0) snprintf(cmdline, sizeof(cmdline), "%s", args);
  /* the process's sockets (gopsutil counts its connections) */
  size_t nconn = 0;
  int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
  if (bytes > 0) {
    struct proc_fdinfo *fds = buckets_xmalloc((size_t)bytes);
    bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, bytes);
    for (int i = 0; bytes > 0 && i < bytes / (int)sizeof(*fds); i++) nconn += fds[i].proc_fdtype == PROX_FDTYPE_SOCKET;
    free(fds);
  }
#else
  size_t nconn = 0;
#endif
  yyjson_mut_val *o = node_common(d, addr, "not implemented yet");
  yyjson_mut_obj_add_int(d, o, "pid", pid);
  yyjson_mut_obj_add_bool(d, o, "is_background", true);
  if (cpu_pct > 0) yyjson_mut_obj_add_real(d, o, "cpu_percent", cpu_pct);
  yyjson_mut_obj_add_strcpy(d, o, "cmd_line", cmdline);
  if (nconn) yyjson_mut_obj_add_uint(d, o, "num_connections", nconn);
  yyjson_mut_obj_add_int(d, o, "create_time", create_ms);
  yyjson_mut_val *ioc = yyjson_mut_obj_add_obj(d, o, "iocounters");
  static const char *const iok[] = {"readCount", "writeCount", "readBytes", "writeBytes"};
  for (size_t k = 0; k < 4; k++) yyjson_mut_obj_add_uint(d, ioc, iok[k], 0);
  yyjson_mut_val *mem = yyjson_mut_obj_add_obj(d, o, "mem_info");
  static const char *const memk[] = {"rss", "vms", "hwm", "data", "stack", "locked", "swap"};
  for (size_t k = 0; k < 7; k++) yyjson_mut_obj_add_uint(d, mem, memk[k], 0);
  yyjson_mut_val *cs = yyjson_mut_obj_add_obj(d, o, "num_ctx_switches");
  yyjson_mut_obj_add_uint(d, cs, "voluntary", 0);
  yyjson_mut_obj_add_uint(d, cs, "involuntary", 0);
  yyjson_mut_val *pf = yyjson_mut_obj_add_obj(d, o, "page_faults");
  static const char *const pfk[] = {"minorFaults", "majorFaults", "childMinorFaults", "childMajorFaults"};
  for (size_t k = 0; k < 4; k++) yyjson_mut_obj_add_uint(d, pf, pfk[k], 0);
  yyjson_mut_val *t = yyjson_mut_obj_add_obj(d, o, "times");
  yyjson_mut_obj_add_str(d, t, "cpu", "");
  static const char *const tk[] = {"user", "system", "idle", "nice", "iowait", "irq", "softirq", "steal", "guest",
                                   "guestNice"};
  for (size_t k = 0; k < BUCKETS_ARRAY_LEN(tk); k++) yyjson_mut_obj_add_int(d, t, tk[k], 0);
  return o;
#endif
}

static yyjson_mut_val *sec_errors(yyjson_mut_doc *d, const char *addr) {
#ifdef __linux__
  yyjson_mut_val *errs = yyjson_mut_arr(d);
  char err[256] = "";
  char *cl = read_file("/proc/cmdline", 1 << 16);
  bool audit = cl && strstr(cl, "audit=1");
  free(cl);
  if (!audit) { /* the kauditd kernel thread */
    DIR *pd = opendir("/proc");
    struct dirent *e;
    while (pd && (e = readdir(pd)) && !audit) {
      if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
      char p[64];
      snprintf(p, sizeof(p), "/proc/%s/comm", e->d_name);
      char *comm = read_file(p, 64);
      if (comm) {
        trim(comm);
        audit = !strcmp(comm, "kauditd");
        free(comm);
      }
    }
    if (pd) closedir(pd);
  }
  if (audit) yyjson_mut_arr_add_str(d, errs, "audit is enabled");
  /* updatedb on the PATH */
  const char *path = getenv("PATH");
  char *pcopy = buckets_xstrdup(path ? path : "");
  for (char *dir = strtok(pcopy, ":"); dir; dir = strtok(NULL, ":")) {
    char p[4096];
    snprintf(p, sizeof(p), "%s/updatedb", dir);
    if (access(p, X_OK) == 0) {
      yyjson_mut_arr_add_str(d, errs, "updatedb is installed");
      break;
    }
  }
  free(pcopy);
  yyjson_mut_val *o = node_common(d, addr, err);
  if (yyjson_mut_arr_size(errs)) yyjson_mut_obj_add_val(d, o, "errors", errs);
  return o;
#else
  return node_common(d, addr, NULL);
#endif
}

static yyjson_mut_val *sec_services(yyjson_mut_doc *d, const char *addr) {
  yyjson_mut_val *o = node_common(d, addr, NULL);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, o, "services");
  yyjson_mut_val *sv = yyjson_mut_arr_add_obj(d, arr);
  yyjson_mut_obj_add_str(d, sv, "name", "selinux");
  char status[64] = "not-installed";
  char *cfg = read_file("/etc/selinux/config", 1 << 16);
  for (char *line = cfg ? strtok(cfg, "\n") : NULL; line; line = strtok(NULL, "\n"))
    if (!strncmp(line, "SELINUX=", 8)) snprintf(status, sizeof(status), "%s", line + 8);
  free(cfg);
  yyjson_mut_obj_add_strcpy(d, sv, "status", status);
  return o;
}

static void thp(yyjson_mut_doc *d, yyjson_mut_val *o, const char *file, const char *name) {
  char *v = read_file(file, 4096);
  char key[64];
  if (!v) {
    snprintf(key, sizeof(key), "%s_error", name);
    char err[1200];
    snprintf(err, sizeof(err), "open %s: %s", file, "no such file or directory");
    yyjson_mut_obj_add(o, yyjson_mut_strcpy(d, key), yyjson_mut_strcpy(d, err));
    return;
  }
  trim(v);
  yyjson_mut_obj_add(o, yyjson_mut_strcpy(d, name), yyjson_mut_strcpy(d, v));
  free(v);
}

static yyjson_mut_val *sec_sysconfig(yyjson_mut_doc *d, const char *addr) {
  char err[512] = "";
  /* map keys as Go writes them: sorted */
  yyjson_mut_val *cfg = yyjson_mut_obj(d);
#ifdef __linux__
  char *cl = read_file("/proc/cmdline", 1 << 16);
  if (cl) {
    trim(cl);
    yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, cfg, "proc-cmdline");
    for (char *w = strtok(cl, " "); w; w = strtok(NULL, " ")) yyjson_mut_arr_add_strcpy(d, arr, w);
    free(cl);
  }
  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0) yyjson_mut_obj_add_uint(d, cfg, "rlimit-max", (uint64_t)rl.rlim_cur);
#else
  snprintf(err, sizeof(err),
           "rlimit: could not read \"/proc\": stat /proc: no such file or directory, proc-cmdline: could not read "
           "\"/proc\": stat /proc: no such file or directory");
#endif
  yyjson_mut_val *t = yyjson_mut_obj_add_obj(d, cfg, "thp-config");
  /* its keys sorted too */
  thp(d, t, "/sys/kernel/mm/transparent_hugepage/defrag", "defrag");
  thp(d, t, "/sys/kernel/mm/transparent_hugepage/enabled", "enabled");
  thp(d, t, "/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none", "max_ptes_none");
  yyjson_mut_val *ti = yyjson_mut_obj_add_obj(d, cfg, "time-info");
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  char when[64];
  buckets_time_rfc3339_nano(ts.tv_sec, ts.tv_nsec, when);
  yyjson_mut_obj_add_strcpy(d, ti, "current_time", when);
  yyjson_mut_obj_add_int(d, ti, "roundtrip_duration", 0);
  time_t now = time(NULL);
  struct tm lt;
  localtime_r(&now, &lt);
  yyjson_mut_obj_add_strcpy(d, ti, "time_zone", lt.tm_zone ? lt.tm_zone : "UTC");
#ifdef __linux__
  glob_t g;
  if (glob("/sys/fs/xfs/*/error/metadata/*/max_retries", 0, NULL, &g) == 0) {
    yyjson_mut_val *x = yyjson_mut_obj_add_obj(d, cfg, "xfs-error-config");
    yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, x, "configs");
    for (size_t i = 0; i < g.gl_pathc; i++) {
      char *v = read_file(g.gl_pathv[i], 64);
      yyjson_mut_val *c = yyjson_mut_arr_add_obj(d, arr);
      yyjson_mut_obj_add_strcpy(d, c, "config_file", g.gl_pathv[i]);
      yyjson_mut_obj_add_int(d, c, "max_retries", v ? atoi(v) : 0);
      free(v);
    }
    globfree(&g);
  }
#endif
  yyjson_mut_val *o = node_common(d, addr, err);
  yyjson_mut_obj_add_val(d, o, "config", cfg);
  return o;
}

typedef yyjson_mut_val *(*section_fn)(yyjson_mut_doc *, const char *);

typedef struct {
  const char *query, *key, *peer;
  section_fn fn;
} section;

static yyjson_mut_val *sec_partitions_local(yyjson_mut_doc *d, const char *addr);

static const section k_sections[] = {
    {"syscpu", "cpus", "cpus", sec_cpus},
    {"sysdrivehw", "partitions", "partitions", sec_partitions_local},
    {"sysnet", "netinfo", "netinfo", sec_netinfo},
    {"sysosinfo", "osinfo", "osinfo", sec_osinfo},
    {"sysmem", "meminfo", "meminfo", sec_meminfo},
    {"sysprocess", "procinfo", "procinfo", sec_procinfo},
};
static const section k_late_sections[] = {
    {"syserrors", "errors", "errors", sec_errors},
    {"sysservices", "services", "services", sec_services},
    {"sysconfig", "config", "config", sec_sysconfig},
};

static const buckets_cluster_info *g_ci; /* for the partitions section */
static yyjson_mut_val *sec_partitions_local(yyjson_mut_doc *d, const char *addr) {
  return sec_partitions(d, addr, g_ci);
}

static const section *find_section(const char *peer_name) {
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_sections); i++)
    if (!strcmp(k_sections[i].peer, peer_name)) return &k_sections[i];
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_late_sections); i++)
    if (!strcmp(k_late_sections[i].peer, peer_name)) return &k_late_sections[i];
  return NULL;
}

/* ---- the job ----------------------------------------------------------------------------------------- */

typedef struct {
  buckets_s3_server *s;
  buckets_query q;
  bool want[16];
  int64_t deadline_ns;
  char req_url[1024];
} health_job;

static bool q_true(const buckets_query *q, const char *k) {
  const char *v = buckets_query_get(q, k);
  return v && !strcmp(v, "true");
}

/* sys's keys in madmin.SysInfo's order */
static void order_sys(yyjson_mut_doc *d) {
  static const char *const order[] = {"cpus", "partitions", "osinfo", "meminfo", "procinfo", "netinfo",
                                      "errors", "services", "config", "productinfo", "kubernetes"};
  yyjson_mut_val *sys = yyjson_mut_obj_get(yyjson_mut_doc_get_root(d), "sys");
  yyjson_mut_val *vals[BUCKETS_ARRAY_LEN(order)];
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(order); i++) vals[i] = yyjson_mut_obj_remove_key(sys, order[i]);
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(order); i++)
    if (vals[i]) yyjson_mut_obj_add(sys, yyjson_mut_str(d, order[i]), vals[i]);
}

static void emit(buckets_jobstream *j, yyjson_mut_doc *d) {
  order_sys(d);
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  buckets_jobstream_emit(j, json, n);
  buckets_jobstream_emit(j, "\n", 1);
  free(json);
}

/* the section from every peer, appended */
static void peers_section(buckets_s3_server *s, yyjson_mut_doc *d, yyjson_mut_val *arr, const char *name) {
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  for (size_t i = 0; i < np; i++) {
    char node[300], target[256];
    snprintf(node, sizeof(node), "%s:%d", buckets_http_client_host(pcs[i]), buckets_http_client_port(pcs[i]));
    snprintf(target, sizeof(target), BUCKETS_INTERNODE_PREFIX "peer/admin?op=health&section=%s", name);
    buckets_buf body = BUCKETS_BUF_INIT;
    int status = 0;
    yyjson_doc *pd = NULL;
    if (buckets_peer_call(s->peers, node, target, &status, &body) && status == 200 &&
        (pd = yyjson_read(body.data ? body.data : "", body.len, 0)))
      yyjson_mut_arr_append(arr, yyjson_val_mut_copy(d, yyjson_doc_get_root(pd)));
    else
      yyjson_mut_arr_append(arr, node_common(d, node, "peer not reachable"));
    yyjson_doc_free(pd);
    buckets_buf_free(&body);
  }
}

/* sys.<key>: this node's section, then the peers' */
static void add_section(health_job *h, buckets_jobstream *j, yyjson_mut_doc *d, yyjson_mut_val *sys, const section *sec,
                        bool write_twice) {
  const char *self = h->s->cluster ? h->s->cluster->self : "";
  yyjson_mut_val *arr = yyjson_mut_obj_get(sys, sec->key);
  if (!arr) arr = yyjson_mut_obj_add_arr(d, sys, sec->key);
  yyjson_mut_arr_append(arr, sec->fn(d, self));
  if (write_twice) emit(j, d);
  peers_section(h->s, d, arr, sec->peer);
  emit(j, d);
}

/* The first message: the version, the time, the deployment. */
static yyjson_mut_doc *base_doc(buckets_s3_server *s, const char *error) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "version", "3");
  if (error) yyjson_mut_obj_add_strcpy(d, root, "error", error);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  char when[64];
  buckets_time_rfc3339_nano(ts.tv_sec, ts.tv_nsec, when);
  yyjson_mut_obj_add_strcpy(d, root, "timestamp", when);
  yyjson_mut_val *sys = yyjson_mut_obj_add_obj(d, root, "sys");
  yyjson_mut_val *kube = yyjson_mut_obj_add_obj(d, sys, "kubernetes");
  yyjson_mut_obj_add_str(d, kube, "buildDate", "0001-01-01T00:00:00Z");
  yyjson_mut_val *minio = yyjson_mut_obj_add_obj(d, root, "minio");
  yyjson_mut_obj_add_obj(d, minio, "config");
  yyjson_mut_val *info = yyjson_mut_obj_add_obj(d, minio, "info");
  yyjson_mut_obj_add_str(d, info, "deploymentID", s->layer ? s->layer->deployment_id_str : "");
  yyjson_mut_val *b = yyjson_mut_obj_add_obj(d, info, "buckets");
  yyjson_mut_obj_add_int(d, b, "count", 0);
  b = yyjson_mut_obj_add_obj(d, info, "objects");
  yyjson_mut_obj_add_int(d, b, "count", 0);
  b = yyjson_mut_obj_add_obj(d, info, "usage");
  yyjson_mut_obj_add_int(d, b, "size", 0);
  b = yyjson_mut_obj_add_obj(d, info, "services");
  yyjson_mut_obj_add_obj(d, b, "kms");
  yyjson_mut_obj_add_obj(d, b, "ldap");
  yyjson_mut_obj_add_null(d, info, "tls");
  yyjson_mut_obj_add_null(d, info, "is_kubernetes");
  yyjson_mut_obj_add_null(d, info, "is_docker");
  return d;
}

static void health_run(buckets_jobstream *j, void *ud) {
  health_job *h = ud;
  buckets_s3_server *s = h->s;
  g_ci = s->cluster;
  yyjson_mut_doc *d = base_doc(s, NULL);
  yyjson_mut_val *root = yyjson_mut_doc_get_root(d);
  yyjson_mut_val *sys = yyjson_mut_obj_get(root, "sys");
  yyjson_mut_val *minio = yyjson_mut_obj_get(root, "minio");
  emit(j, d);

  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_sections); i++)
    if (q_true(&h->q, k_sections[i].query)) add_section(h, j, d, sys, &k_sections[i], false);

  if (q_true(&h->q, "minioconfig")) {
    buckets_config *cfg = s->config ? buckets_config_sys_snapshot(s->config) : NULL;
    char *json = cfg ? buckets_config_to_json_redacted(cfg) : NULL;
    yyjson_doc *cd = json ? yyjson_read(json, strlen(json), 0) : NULL;
    yyjson_mut_val *mc = yyjson_mut_obj(d);
    if (cd) yyjson_mut_obj_add_val(d, mc, "config", yyjson_val_mut_copy(d, yyjson_doc_get_root(cd)));
    else yyjson_mut_obj_add_str(d, mc, "error", "unable to read the server configuration");
    yyjson_mut_obj_replace(minio, yyjson_mut_str(d, "config"), mc);
    yyjson_doc_free(cd);
    free(json);
    if (cfg) buckets_config_free(cfg);
    emit(j, d);
  }

  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_late_sections); i++)
    if (q_true(&h->q, k_late_sections[i].query)) add_section(h, j, d, sys, &k_late_sections[i], true);

  if (q_true(&h->q, "minioinfo")) {
    /* getServerInfo, reshaped as madmin.MinioInfo */
    s3_ctx c;
    memset(&c, 0, sizeof(c));
    buckets_http_response resp = {.status = 200, .content_length = -1};
    c.s = s;
    c.resp = &resp;
    buckets_query_parse((buckets_str){"metrics=true", 12}, &c.q); /* with drive metrics */
    buckets_admin_server_info(&c);
    buckets_query_free(&c.q);
    yyjson_doc *sd = yyjson_read(resp.body.data ? resp.body.data : "{}", resp.body.len, 0);
    yyjson_val *si = yyjson_doc_get_root(sd);
    yyjson_mut_val *mi = yyjson_mut_obj(d);
    static const char *const copy[] = {"mode", "region", "sqsARN", "deploymentID", "buckets", "objects", "usage",
                                       "services", "backend"};
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(copy); k++) {
      yyjson_val *v = yyjson_obj_get(si, copy[k]);
      if (v) yyjson_mut_obj_add(mi, yyjson_mut_strcpy(d, copy[k]), yyjson_val_mut_copy(d, v));
    }
    yyjson_mut_val *servers = yyjson_mut_obj_add_arr(d, mi, "servers");
    size_t idx, max;
    yyjson_val *sv;
    static const char *const skeys[] = {"state", "endpoint", "uptime", "version", "commitID", "network", "drives",
                                        "poolNumber", "poolNumbers", "mem_stats", "go_max_procs", "num_cpu",
                                        "runtime_version", "gc_stats", "minio_env_vars", "edition"};
    yyjson_arr_foreach(yyjson_obj_get(si, "servers"), idx, max, sv) {
      yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, servers);
      for (size_t k = 0; k < BUCKETS_ARRAY_LEN(skeys); k++) {
        yyjson_val *v = yyjson_obj_get(sv, skeys[k]);
        if (!strcmp(skeys[k], "poolNumber")) {
          /* math.MaxInt when the server has several pools (unset) */
          yyjson_val *pn = yyjson_obj_get(sv, "poolNumbers");
          if (yyjson_arr_size(pn) == 1) yyjson_mut_obj_add_int(d, o, "poolNumber", yyjson_get_int(yyjson_arr_get(pn, 0)));
          else yyjson_mut_obj_add_int(d, o, "poolNumber", INT64_MAX);
          continue;
        }
        if (v) yyjson_mut_obj_add(o, yyjson_mut_strcpy(d, skeys[k]), yyjson_val_mut_copy(d, v));
      }
    }
    yyjson_mut_val *tls = yyjson_mut_obj_add_obj(d, mi, "tls");
    yyjson_mut_obj_add_bool(d, tls, "tls_enabled", s->cluster && s->cluster->secure);
    yyjson_mut_obj_add_bool(d, mi, "is_kubernetes", getenv("KUBERNETES_SERVICE_HOST") != NULL);
    yyjson_mut_obj_add_bool(d, mi, "is_docker", access("/.dockerenv", F_OK) == 0);
    yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, mi, "metrics");
    yyjson_mut_obj_add_null(d, m, "errors");
    yyjson_mut_val *hosts = yyjson_mut_obj_add_arr(d, m, "hosts");
    yyjson_mut_arr_add_strcpy(d, hosts, s->cluster ? s->cluster->self : "");
    yyjson_mut_obj_add_obj(d, m, "aggregated");
    yyjson_mut_obj_add_bool(d, m, "final", false);
    yyjson_mut_obj_replace(minio, yyjson_mut_str(d, "info"), mi);
    yyjson_doc_free(sd);
    buckets_buf_free(&resp.body);
    buckets_buf_free(&resp.headers);
    emit(j, d);
  }
  yyjson_mut_doc_free(d);
}

static void health_free(void *ud) {
  health_job *h = ud;
  buckets_query_free(&h->q);
  free(h);
}

void buckets_admin_health_info(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:OBDInfo")) return;
  health_job *h = buckets_xcalloc(1, sizeof(*h));
  h->s = c->s;
  buckets_query_parse(c->req->query, &h->q);
  const char *dl = buckets_query_get(&h->q, "deadline");
  int64_t ns = 10000000000LL;
  if (dl && *dl && !buckets_go_duration_parse(dl, &ns)) {
    /* errResp: the HealthInfo with the error response (XML) in it */
    char err[512];
    buckets_go_duration_error(dl, err, sizeof(err));
    buckets_buf msg = BUCKETS_BUF_INIT, x = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&msg, "We encountered an internal error, please try again. (%s)", err);
    buckets_buf_append_c(&x, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InternalError</Code><Message>");
    buckets_xml_text(&x, msg.data, msg.len);
    buckets_buf_append_c(&x, "</Message><Resource>");
    buckets_xml_text(&x, c->path ? c->path : "", c->path ? strlen(c->path) : 0);
    buckets_buf_appendf(&x, "</Resource><RequestId>%s</RequestId><HostId></HostId></Error>", c->request_id);
    buckets_buf_append_char(&x, '\0');
    yyjson_mut_doc *d = base_doc(c->s, x.data);
    size_t n;
    char *json = yyjson_mut_write(d, 0, &n);
    buckets_buf_reset(&c->resp->body);
    buckets_buf_append(&c->resp->body, json, n);
    buckets_buf_append_char(&c->resp->body, '\n');
    free(json);
    yyjson_mut_doc_free(d);
    buckets_buf_free(&msg);
    buckets_buf_free(&x);
    c->resp->status = 200;
    buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
    health_free(h);
    return;
  }
  h->deadline_ns = ns;
  buckets_http_resp_header(c->resp, "Content-Type", "text/event-stream");
  buckets_jobstream_start(c->resp, health_run, h, health_free, 5000, " ");
}

bool buckets_admin_health_peer(buckets_s3_server *s, const char *op, const buckets_query *q,
                               buckets_http_response *resp) {
  if (strcmp(op, "health") != 0) return false;
  const char *name = buckets_query_get(q, "section");
  const section *sec = name ? find_section(name) : NULL;
  if (!sec) {
    resp->status = 400;
    return true;
  }
  g_ci = s->cluster;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(d, sec->fn(d, s->cluster ? s->cluster->self : ""));
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  buckets_buf_append(&resp->body, json, n);
  free(json);
  yyjson_mut_doc_free(d);
  return true;
}
