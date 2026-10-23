#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <stdint.h>

#define WORDS 128

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t fblamka(uint64_t x, uint64_t y) {
    return x + y + 2 * (uint64_t)(uint32_t)x * (uint32_t)y;
}

static inline void gb(uint64_t *v, int a, int b, int c, int d) {
    v[a] = fblamka(v[a], v[b]);
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = fblamka(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = fblamka(v[a], v[b]);
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = fblamka(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 63);
}

static inline void round16(uint64_t *v) {
    gb(v, 0, 4,  8, 12); gb(v, 1, 5,  9, 13);
    gb(v, 2, 6, 10, 14); gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15); gb(v, 1, 6, 11, 12);
    gb(v, 2, 7,  8, 13); gb(v, 3, 4,  9, 14);
}

static void compress_blocks(const uint64_t *x, const uint64_t *y, uint64_t *out) {
    uint64_t z[WORDS], tmp[16];
    int i, g, j, k;
    for (i = 0; i < WORDS; i++) z[i] = x[i] ^ y[i];
    for (g = 0; g < 8; g++) {
        for (k = 0; k < 16; k++) tmp[k] = z[g * 16 + k];
        round16(tmp);
        for (k = 0; k < 16; k++) z[g * 16 + k] = tmp[k];
    }
    for (j = 0; j < 8; j++) {
        for (k = 0; k < 16; k++) tmp[k] = z[j + 8 * k];
        round16(tmp);
        for (k = 0; k < 16; k++) z[j + 8 * k] = tmp[k];
    }
    for (i = 0; i < WORDS; i++) out[i] = z[i] ^ (x[i] ^ y[i]);
}

static int av_to_u64(pTHX_ AV *av, uint64_t *out, int n) {
    int i;
    if (av_len(av) + 1 < n) return 0;
    for (i = 0; i < n; i++) {
        SV **svp = av_fetch(av, i, 0);
        if (!svp || !SvOK(*svp)) return 0;
        out[i] = (uint64_t)SvUV(*svp);
    }
    return 1;
}

MODULE = HiatalaMrk    PACKAGE = HiatalaMrk

PROTOTYPES: DISABLE

void
compress(prev_av, ref_av, out_av)
    AV *prev_av
    AV *ref_av
    AV *out_av
  PREINIT:
    uint64_t prev[WORDS], ref[WORDS], out[WORDS];
    int i;
  PPCODE:
    if (!av_to_u64(aTHX_ prev_av, prev, WORDS) || !av_to_u64(aTHX_ ref_av, ref, WORDS))
        croak("HiatalaMrk::compress: expected two arrays of 128 integers");
    compress_blocks(prev, ref, out);
    av_clear(out_av);
    av_extend(out_av, WORDS - 1);
    for (i = 0; i < WORDS; i++) av_store(out_av, i, newSVuv(out[i]));
    XSRETURN_EMPTY;

SV *
xs_backend()
  CODE:
    RETVAL = newSVpvs("xs");
  OUTPUT:
    RETVAL
