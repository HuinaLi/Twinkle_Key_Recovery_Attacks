// -----------------------------------------------------------------------------
//  twinkle.hpp -- the low-latency PRF Twinkle
//
//        O = F_O( R^r ( F_I(IV) xor k0 ) xor k1 )
//
//  The 1280-bit state is a 4 x 4 x 80 array, stored as 16 lanes of 80 bits.
//  State bits are numbered lane-major, i = 80*Lambda + z, which is the numbering
//  used for the conditions C_117 and for the output-difference set S^1_117.
//  In this numbering
//
//    * the S-box acts on {c, c+320, c+640, c+960}, c+960 being the most
//      significant input bit;
//    * lane Lambda uses the LaneRotation offset and the MixSlice position of
//      lane tr(Lambda), where tr(4a+b) = 4b+a;
//    * block m of F_I (state bits 128m .. 128m+127) carries the bit permutation
//      j -> (a*j + b) mod 128 with (a,b) = param[9-m].
// -----------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <array>

namespace twinkle {

using u128 = unsigned __int128;

static constexpr int LANES     = 16;
static constexpr int SLICES    = 80;
static constexpr int STATEBITS = 1280;
static constexpr int IVBITS    = 128;
static constexpr int MAXROUNDS = 18;
static constexpr u128 LANE_MASK = ((u128)1 << SLICES) - 1;

struct State {
    u128 l[LANES];
    inline void clear() { for (int i = 0; i < LANES; ++i) l[i] = 0; }
    inline void operator^=(const State &o) { for (int i = 0; i < LANES; ++i) l[i] ^= o.l[i]; }
};

// LaneRotation offsets and F_I permutation parameters (Twinkle specification).
static constexpr int O0[LANES] = {20, 24, 38, 77, 49, 66, 30, 40,
                                  76, 15, 46, 50, 17, 18, 61, 62};
static constexpr int O1[LANES] = {63, 45, 34, 39, 32, 43, 60, 66,
                                  54, 26, 55, 36, 61, 12, 15, 35};
static constexpr int FI_A[10] = {1, 3, 5, 7, 11, 13, 17, 19, 23, 29};
static constexpr int FI_B[10] = {0, 1, 2, 3, 4,  5,  6,  7,  8,  9};

extern const uint16_t RC1D[MAXROUNDS * SLICES];   // pi-derived round constants

struct Layout {
    int sgrp[4][4];                   // S-box groups, most significant lane first
    int rot0[LANES], rot1[LANES];     // effective left-rotation amounts
    int mixa[LANES], mixb[LANES];     // new[L] = old[L] ^ old[a] ^ old[b]
    State rc[MAXROUNDS];
};
extern Layout LAY;
void init();

static inline u128 rotl80(u128 v, int r) {
    return r ? (((v << r) | (v >> (SLICES - r))) & LANE_MASK) : (v & LANE_MASK);
}
static inline int  get_bit(const State &s, int i) { return (int)((s.l[i / SLICES] >> (i % SLICES)) & 1); }
static inline void set_bit(State &s, int i, int v) {
    u128 m = (u128)1 << (i % SLICES);
    if (v) s.l[i / SLICES] |= m; else s.l[i / SLICES] &= ~m;
}

// Sb = [0,3,5,d,6,f,a,8,b,4,e,2,9,c,7,1], written as its ANF with a0 the most
// significant input bit.
static inline void sbox(State &s) {
    for (int g = 0; g < 4; ++g) {
        const int *q = LAY.sgrp[g];
        const u128 a0 = s.l[q[0]], a1 = s.l[q[1]], a2 = s.l[q[2]], a3 = s.l[q[3]];
        s.l[q[0]] = (a2 & a3) ^ (a1 & a3) ^ (a1 & a2) ^ a0 ^ (a0 & a3) ^ (a0 & a2 & a3);
        s.l[q[1]] = a2 ^ a1 ^ (a0 & a3) ^ (a0 & a1);
        s.l[q[2]] = a3 ^ (a2 & a3) ^ a1 ^ (a1 & a3) ^ a0 ^ (a0 & a1 & a2);
        s.l[q[3]] = a3 ^ a2 ^ (a2 & a3) ^ (a1 & a2) ^ a0;
    }
}
static inline void round_R(State &s, int r) {
    sbox(s);
    for (int L = 0; L < LANES; ++L) s.l[L] = rotl80(s.l[L], LAY.rot0[L]);
    u128 t[LANES];
    for (int L = 0; L < LANES; ++L) t[L] = s.l[L] ^ s.l[LAY.mixa[L]] ^ s.l[LAY.mixb[L]];
    for (int L = 0; L < LANES; ++L) s.l[L] = rotl80(t[L], LAY.rot1[L]);
    s ^= LAY.rc[r];
}

struct Ctx {
    State fi_col[IVBITS];       // F_I(e_j)
    State k0, k1;
    int   rounds, outbits;
};
void ctx_setup(Ctx &c, const std::array<uint64_t, 20> &K, int rounds, int outbits);

// F_O : O[t] = S[t] ^ S[t+128] for every t < 1152.
static inline void finish(const Ctx &c, State s, uint64_t *out) {
    for (int r = 0; r < c.rounds; ++r) round_R(s, r);
    s ^= c.k1;
    for (int w = 0; w < (c.outbits + 63) / 64; ++w) out[w] = 0;
    for (int t = 0; t < c.outbits; ++t)
        out[t >> 6] |= (uint64_t)(get_bit(s, t) ^ get_bit(s, t + 128)) << (t & 63);
}

} // namespace twinkle
