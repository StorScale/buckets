/* Replays inputs through LLVMFuzzerTestOneInput when libFuzzer is unavailable.
 * usage: fuzz_x FILE_OR_DIR...
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int run_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror(path);
    return 1;
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *buf = malloc(n > 0 ? (size_t)n : 1);
  size_t got = fread(buf, 1, (size_t)(n > 0 ? n : 0), f);
  fclose(f);
  LLVMFuzzerTestOneInput(buf, got);
  free(buf);
  return 0;
}

int main(int argc, char **argv) {
  int runs = 0;
  for (int i = 1; i < argc; i++) {
    struct stat st;
    if (stat(argv[i], &st) != 0) {
      perror(argv[i]);
      return 1;
    }
    if (!S_ISDIR(st.st_mode)) {
      if (run_file(argv[i])) return 1;
      runs++;
      continue;
    }
    DIR *d = opendir(argv[i]);
    struct dirent *e;
    while (d && (e = readdir(d))) {
      if (e->d_name[0] == '.') continue;
      char p[4096];
      snprintf(p, sizeof(p), "%s/%s", argv[i], e->d_name);
      if (run_file(p)) return 1;
      runs++;
    }
    if (d) closedir(d);
  }
  printf("replayed %d inputs\n", runs);
  return 0;
}
