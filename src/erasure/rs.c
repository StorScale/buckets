/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "erasure/rs.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* ---- GF(2^8) ----------------------------------------------------------------- */

static uint8_t g_exp[512], g_log[256];
static uint8_t g_mul[256][256];
/* Split-nibble tables for SIMD multiply: c*x = lo[c][x & 15] ^ hi[c][x >> 4]. */
static uint8_t g_nib[256][2][16];
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static void gf_init(void) {
  unsigned x = 1;
  for (int i = 0; i < 255; i++) {
    g_exp[i] = (uint8_t)x;
    g_log[x] = (uint8_t)i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (int i = 255; i < 512; i++) g_exp[i] = g_exp[i - 255];
  for (int a = 0; a < 256; a++) {
    for (int b = 0; b < 256; b++) {
      g_mul[a][b] = (a && b) ? g_exp[g_log[a] + g_log[b]] : 0;
    }
  }
  for (int c = 0; c < 256; c++) {
    for (int i = 0; i < 16; i++) {
      g_nib[c][0][i] = g_mul[c][i];
      g_nib[c][1][i] = g_mul[c][i << 4];
    }
  }
}

static uint8_t gf_div(uint8_t a, uint8_t b) {
  if (a == 0) return 0;
  int l = g_log[a] - g_log[b];
  if (l < 0) l += 255;
  return g_exp[l];
}

/* galExp(a, n) */
static uint8_t gf_pow(uint8_t a, int n) {
  if (n == 0) return 1;
  if (a == 0) return 0;
  int l = (g_log[a] * n) % 255;
  return g_exp[l];
}

/* ---- matrices (row-major, rows x cols) --------------------------------------- */

static uint8_t *mat_new(int rows, int cols) { return buckets_xcalloc((size_t)rows * (size_t)cols, 1); }

static void mat_mul(const uint8_t *a, int ar, int ac, const uint8_t *b, int bc, uint8_t *out) {
  for (int r = 0; r < ar; r++) {
    for (int c = 0; c < bc; c++) {
      uint8_t v = 0;
      for (int i = 0; i < ac; i++) v ^= g_mul[a[r * ac + i]][b[i * bc + c]];
      out[r * bc + c] = v;
    }
  }
}

/* Gauss-Jordan inversion of an n x n matrix in place. Returns false if singular. */
static bool mat_invert(uint8_t *m, int n) {
  uint8_t *aug = mat_new(n, 2 * n);
  for (int r = 0; r < n; r++) {
    memcpy(aug + r * 2 * n, m + r * n, (size_t)n);
    aug[r * 2 * n + n + r] = 1;
  }
  bool ok = true;
  for (int col = 0; col < n && ok; col++) {
    int pivot = -1;
    for (int r = col; r < n; r++) {
      if (aug[r * 2 * n + col]) {
        pivot = r;
        break;
      }
    }
    if (pivot < 0) {
      ok = false;
      break;
    }
    if (pivot != col) {
      for (int k = 0; k < 2 * n; k++) {
        uint8_t t = aug[col * 2 * n + k];
        aug[col * 2 * n + k] = aug[pivot * 2 * n + k];
        aug[pivot * 2 * n + k] = t;
      }
    }
    uint8_t inv = gf_div(1, aug[col * 2 * n + col]);
    for (int k = 0; k < 2 * n; k++) aug[col * 2 * n + k] = g_mul[aug[col * 2 * n + k]][inv];
    for (int r = 0; r < n; r++) {
      if (r == col) continue;
      uint8_t f = aug[r * 2 * n + col];
      if (!f) continue;
      for (int k = 0; k < 2 * n; k++) aug[r * 2 * n + k] ^= g_mul[f][aug[col * 2 * n + k]];
    }
  }
  if (ok) {
    for (int r = 0; r < n; r++) memcpy(m + r * n, aug + r * 2 * n + n, (size_t)n);
  }
  free(aug);
  return ok;
}

/* ---- codec ------------------------------------------------------------------- */

struct buckets_rs {
  int data, parity, total;
  uint8_t *matrix; /* total x data encoding matrix */
};

int buckets_rs_data(const buckets_rs *rs) { return rs->data; }
int buckets_rs_parity(const buckets_rs *rs) { return rs->parity; }

buckets_rs *buckets_rs_new(int data, int parity) {
  if (data <= 0 || parity < 0 || data + parity > BUCKETS_RS_MAX_SHARDS) return NULL;
  pthread_once(&g_once, gf_init);
  buckets_rs *rs = buckets_xcalloc(1, sizeof(*rs));
  rs->data = data;
  rs->parity = parity;
  rs->total = data + parity;
  /* buildMatrix: vandermonde(total, data) x inverse(top data x data square). */
  uint8_t *vm = mat_new(rs->total, data);
  for (int r = 0; r < rs->total; r++) {
    for (int c = 0; c < data; c++) vm[r * data + c] = gf_pow((uint8_t)r, c);
  }
  uint8_t *top = mat_new(data, data);
  memcpy(top, vm, (size_t)data * (size_t)data);
  if (!mat_invert(top, data)) buckets_fatal("reed-solomon: vandermonde top square is singular");
  rs->matrix = mat_new(rs->total, data);
  mat_mul(vm, rs->total, data, top, data, rs->matrix);
  free(vm);
  free(top);
  return rs;
}

void buckets_rs_free(buckets_rs *rs) {
  if (!rs) return;
  free(rs->matrix);
  free(rs);
}

/* out[o][i] = XOR_j coeff[o][j] * in[j][i] */
static void code_some_scalar(const uint8_t *coeff, int ncoeff_cols, uint8_t *const *in, int nin, uint8_t *const *out,
                      int nout, size_t len) {
  for (int o = 0; o < nout; o++) {
    uint8_t *dst = out[o];
    memset(dst, 0, len);
    for (int j = 0; j < nin; j++) {
      uint8_t c = coeff[o * ncoeff_cols + j];
      if (c == 0) continue;
      const uint8_t *src = in[j];
      if (c == 1) {
        for (size_t i = 0; i < len; i++) dst[i] ^= src[i];
      } else {
        const uint8_t *row = g_mul[c];
        for (size_t i = 0; i < len; i++) dst[i] ^= row[src[i]];
      }
    }
  }
}

/* The same in 128-bit SIMD, 16 bytes at a time (klauspost's technique):
 * each input chunk is loaded once and split into nibbles, each output is
 * accumulated in a register and stored once. Bytes past the last whole
 * chunk go through the scalar code. */
#if defined(__aarch64__)
#include <arm_neon.h>
#define HAVE_SIMD 1
static void code_some_simd(const uint8_t *coeff, int ncoeff_cols, uint8_t *const *in, int nin, uint8_t *const *out,
                           int nout, size_t len) {
  uint8x16_t lo[BUCKETS_RS_MAX_SHARDS], hi[BUCKETS_RS_MAX_SHARDS], raw[BUCKETS_RS_MAX_SHARDS];
  const uint8x16_t mask = vdupq_n_u8(0x0f);
  for (size_t i = 0; i + 16 <= len; i += 16) {
    for (int j = 0; j < nin; j++) {
      raw[j] = vld1q_u8(in[j] + i);
      lo[j] = vandq_u8(raw[j], mask);
      hi[j] = vshrq_n_u8(raw[j], 4);
    }
    for (int o = 0; o < nout; o++) {
      const uint8_t *row = coeff + o * ncoeff_cols;
      uint8x16_t acc = vdupq_n_u8(0);
      for (int j = 0; j < nin; j++) {
        uint8_t c = row[j];
        if (c == 0) continue;
        if (c == 1) {
          acc = veorq_u8(acc, raw[j]);
        } else {
          acc = veorq_u8(acc, veorq_u8(vqtbl1q_u8(vld1q_u8(g_nib[c][0]), lo[j]),
                                       vqtbl1q_u8(vld1q_u8(g_nib[c][1]), hi[j])));
        }
      }
      vst1q_u8(out[o] + i, acc);
    }
  }
}
static bool simd_ok(void) { return true; }
#elif defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define HAVE_SIMD 1
__attribute__((target("ssse3"))) static void code_some_simd(const uint8_t *coeff, int ncoeff_cols, uint8_t *const *in,
                                                           int nin, uint8_t *const *out, int nout, size_t len) {
  __m128i lo[BUCKETS_RS_MAX_SHARDS], hi[BUCKETS_RS_MAX_SHARDS], raw[BUCKETS_RS_MAX_SHARDS];
  const __m128i mask = _mm_set1_epi8(0x0f);
  for (size_t i = 0; i + 16 <= len; i += 16) {
    for (int j = 0; j < nin; j++) {
      raw[j] = _mm_loadu_si128((const __m128i *)(in[j] + i));
      lo[j] = _mm_and_si128(raw[j], mask);
      hi[j] = _mm_and_si128(_mm_srli_epi64(raw[j], 4), mask);
    }
    for (int o = 0; o < nout; o++) {
      const uint8_t *row = coeff + o * ncoeff_cols;
      __m128i acc = _mm_setzero_si128();
      for (int j = 0; j < nin; j++) {
        uint8_t c = row[j];
        if (c == 0) continue;
        if (c == 1) {
          acc = _mm_xor_si128(acc, raw[j]);
        } else {
          acc = _mm_xor_si128(acc, _mm_xor_si128(
              _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)g_nib[c][0]), lo[j]),
              _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)g_nib[c][1]), hi[j])));
        }
      }
      _mm_storeu_si128((__m128i *)(out[o] + i), acc);
    }
  }
}
static bool simd_ok(void) { return __builtin_cpu_supports("ssse3"); }
#endif

static _Atomic int g_simd = -1; /* -1: decide on first use */

void buckets_rs_set_simd(bool on) { g_simd = on; }

static void code_some(const uint8_t *coeff, int ncoeff_cols, uint8_t *const *in, int nin, uint8_t *const *out,
                      int nout, size_t len) {
#ifdef HAVE_SIMD
  int simd = atomic_load_explicit(&g_simd, memory_order_relaxed);
  if (simd < 0) {
    simd = simd_ok() && !getenv("BUCKETS_NO_SIMD");
    atomic_store_explicit(&g_simd, simd, memory_order_relaxed);
  }
  if (simd && len >= 16) {
    size_t whole = len & ~(size_t)15;
    code_some_simd(coeff, ncoeff_cols, in, nin, out, nout, whole);
    if (whole == len) return;
    uint8_t *tin[BUCKETS_RS_MAX_SHARDS], *tout[BUCKETS_RS_MAX_SHARDS];
    for (int j = 0; j < nin; j++) tin[j] = in[j] + whole;
    for (int o = 0; o < nout; o++) tout[o] = out[o] + whole;
    code_some_scalar(coeff, ncoeff_cols, tin, nin, tout, nout, len - whole);
    return;
  }
#endif
  code_some_scalar(coeff, ncoeff_cols, in, nin, out, nout, len);
}

void buckets_rs_encode(const buckets_rs *rs, uint8_t *const *shards, size_t len) {
  if (rs->parity == 0) return;
  code_some(rs->matrix + rs->data * rs->data, rs->data, shards, rs->data, shards + rs->data, rs->parity, len);
}

bool buckets_rs_reconstruct(const buckets_rs *rs, uint8_t *const *shards, const bool *present, size_t len,
                            bool data_only) {
  int d = rs->data, have = 0;
  for (int i = 0; i < rs->total; i++) have += present[i];
  if (have < d) return false;
  bool data_missing = false;
  for (int i = 0; i < d; i++) data_missing |= !present[i];

  if (data_missing) {
    /* Rows of the first d available shards, inverted, map them back to data. */
    int rows[BUCKETS_RS_MAX_SHARDS];
    uint8_t *in[BUCKETS_RS_MAX_SHARDS];
    int n = 0;
    for (int i = 0; i < rs->total && n < d; i++) {
      if (present[i]) {
        rows[n] = i;
        in[n] = shards[i];
        n++;
      }
    }
    uint8_t *sub = mat_new(d, d);
    for (int r = 0; r < d; r++) memcpy(sub + r * d, rs->matrix + rows[r] * d, (size_t)d);
    if (!mat_invert(sub, d)) {
      free(sub);
      return false;
    }
    uint8_t *coeff = mat_new(d, d);
    uint8_t *out[BUCKETS_RS_MAX_SHARDS];
    int nout = 0;
    for (int i = 0; i < d; i++) {
      if (present[i]) continue;
      memcpy(coeff + nout * d, sub + i * d, (size_t)d);
      out[nout++] = shards[i];
    }
    code_some(coeff, d, in, d, out, nout, len);
    free(coeff);
    free(sub);
  }
  if (!data_only) {
    uint8_t *out[BUCKETS_RS_MAX_SHARDS];
    uint8_t *coeff = mat_new(rs->parity ? rs->parity : 1, d);
    int nout = 0;
    for (int p = 0; p < rs->parity; p++) {
      if (present[d + p]) continue;
      memcpy(coeff + nout * d, rs->matrix + (d + p) * d, (size_t)d);
      out[nout++] = shards[d + p];
    }
    if (nout) code_some(coeff, d, shards, d, out, nout, len);
    free(coeff);
  }
  return true;
}
