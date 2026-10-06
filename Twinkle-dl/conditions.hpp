// -----------------------------------------------------------------------------
//  conditions.hpp -- the difference-propagation conditions C_117 of the
//  conditional differential-linear attack on 3-round Twinkle.
//
//  Delta_in = e_117.  The 17 conditions below are transcribed verbatim from the
//  paper (Subsection 4.3, list "(0) ... (16)"), in the same order.  A condition
//  is *satisfied* iff the polynomial evaluates to 0.
//
//  Variables:  iv_j  (0 <= j < 128)   public IV bits
//              K_i   (0 <= i < 1280)  secret key bits (k0 = K)
// -----------------------------------------------------------------------------
#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <string>

namespace c117 {

enum VarKind { IV, KEY };
struct Var  { VarKind kind; int idx; };
using Monomial  = std::vector<Var>;          // product of variables ( {} = constant 1 )
using Condition = std::vector<Monomial>;     // sum (XOR) of monomials

static inline Var v(int j) { return Var{IV, j}; }
static inline Var k(int i) { return Var{KEY, i}; }
static inline Monomial ONE() { return Monomial{}; }

inline const std::vector<Condition> &conditions() {
    static const std::vector<Condition> C = {
        /*  0 */ { {v(44)}, {k(331)}, ONE() },
        /*  1 */ { {v(56)}, {k(779)}, {k(459)}, {k(139)}, ONE() },
        /*  2 */ { {v(40), v(58)}, {k(480), v(40)}, {k(160), v(58)},
                   {k(160), k(480)}, {v(40)}, {k(160)}, ONE() },
        /*  3 */ { {v(112)}, {v(2)}, {k(502)}, {k(182)} },
        /*  4 */ { {v(68)}, {k(394)}, ONE() },
        /*  5 */ { {v(48), v(90)}, {k(629), v(90)}, {k(309), v(48)},
                   {k(309), k(629)}, {v(90)}, {k(309)}, ONE() },
        /*  6 */ { {k(630), v(118)}, {k(630), k(1270)}, {k(310), v(118)},
                   {k(310), k(1270)}, {k(630)}, {k(310)}, ONE() },
        /*  7 */ { {v(2)}, {k(182)} },
        /*  8 */ { {v(18)}, {k(714)}, ONE() },
        /*  9 */ { {v(106)}, {k(11)} },
        /* 10 */ { {v(36)}, {k(950)} },
        /* 11 */ { {k(459), v(110)}, {k(459), k(1099)}, {k(139), v(110)},
                   {k(139), k(1099)}, {k(459)}, {k(139)}, ONE() },
        /* 12 */ { {k(971)}, {k(651)}, ONE() },
        /* 13 */ { {v(3)}, {k(1034)} },
        /* 14 */ { {v(59)}, {k(800)}, ONE() },
        /* 15 */ { {v(39)}, {k(1142)}, ONE() },
        /* 16 */ { {v(87)}, {k(949)}, ONE() },
    };
    return C;
}

// Input difference position and the conditional IV bits Phi_1 (all IV bits that
// occur in C_117), in increasing order.  |Phi_1| = 18.
static constexpr int DELTA_IN = 117;
inline const std::vector<int> &phi1() {
    static const std::vector<int> p = {2, 3, 18, 36, 39, 40, 44, 48, 56,
                                       58, 59, 68, 87, 90, 106, 110, 112, 118};
    return p;
}

// The three conditions that carry a key-only requirement (r_117 = 3):
//   (6)  K630 ^ K310 = 1,  (11)  K459 ^ K139 = 1,  (12)  K971 ^ K651 = 1.
struct KeyOnly { int cond; int a, b; int rhs; };
inline const std::vector<KeyOnly> &key_only() {
    static const std::vector<KeyOnly> ko = {
        {6, 630, 310, 1}, {11, 459, 139, 1}, {12, 971, 651, 1}};
    return ko;
}

// ---------------------------------------------------------------- evaluation -
template <class IvBit, class KeyBit>
inline int eval(const Condition &c, IvBit ivb, KeyBit kb) {
    int acc = 0;
    for (const Monomial &m : c) {
        int p = 1;
        for (const Var &x : m) p &= (x.kind == IV ? ivb(x.idx) : kb(x.idx));
        acc ^= p;
    }
    return acc;                       // 0 == condition satisfied
}

inline std::string to_string(const Condition &c) {
    std::string s;
    bool first = true;
    for (const Monomial &m : c) {
        if (!first) s += " + ";
        first = false;
        if (m.empty()) { s += "1"; continue; }
        bool f2 = true;
        for (const Var &x : m) {
            if (!f2) s += "*";
            f2 = false;
            s += (x.kind == IV ? "iv" : "K") + std::to_string(x.idx);
        }
    }
    return s;
}

} // namespace c117
