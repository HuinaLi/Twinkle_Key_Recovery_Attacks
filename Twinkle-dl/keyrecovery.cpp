// -----------------------------------------------------------------------------
//  keyrecovery.cpp
//
//  Partial key recovery on 3-round Twinkle with the 117-th conditional
//  differential-linear distinguisher, i.e. Algorithm 2 called with
//
//        ((Delta_in = e_117, Gamma_out), (Theta_1, Theta_2), C_117).
//
//  E_d covers 1 round, E_m covers 2 rounds and E_l = F_O; the output is
//  truncated to 64 bits (security level SL1).
//
//  The attack proceeds in four steps.
//
//   0.  Delta_m.  Imposing C_117 makes the difference after E_d deterministic
//       and equal to Delta_m = sum_{k in S^1_117} e_k.  This is checked once.
//
//   1.  Profile.  Twinkle is an Even-Mansour construction, so no key material
//       enters between E_d and the output.  The correlations
//           v[t] = corr( <e_t, F_O(E_m(X)) ^ F_O(E_m(X ^ Delta_m))> )
//       are therefore key-independent and are computed offline, without any
//       query.  They are the signature of the intended Delta_m.
//
//   2.  First pass.  For each of the 2^|Theta_1| assignments of IV[Theta_1] the
//       empirical correlations u_a[t] are measured on N' pairs, and the
//       structures are ranked by || u_a - v ||.  (Ranking by |u_a[t]| for a
//       single t is weaker: other assignments of IV[Theta_1] also make E_d
//       deterministic, towards a different Delta_m' whose correlation on that
//       single bit can be larger.)
//
//   3.  Second pass.  The best `topk` structures are re-measured with N'' fresh
//       pairs.  The winner is the assignment of IV[Theta_1] satisfying C_117;
//       substituting it into C_117 yields the key expressions.
//
//  The secret key is used only inside the oracle, and afterwards to report
//  whether the recovered key expressions are correct.
// -----------------------------------------------------------------------------
#include "twinkle.hpp"
#include "conditions.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <random>
#include <thread>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <chrono>

using namespace twinkle;

// ------------------------------------------------------------------ input ----
struct Key {
    std::array<uint64_t, 20> w{};
    int bit(int i) const { return (int)((w[i >> 6] >> (i & 63)) & 1); }
    void set(int i, int b) { uint64_t m = 1ull << (i & 63);
                             if (b) w[i >> 6] |= m; else w[i >> 6] &= ~m; }
};
struct IV {
    uint64_t w[2]{};
    int bit(int j) const { return (int)((w[j >> 6] >> (j & 63)) & 1); }
    void set(int j, int b) { uint64_t m = 1ull << (j & 63);
                             if (b) w[j >> 6] |= m; else w[j >> 6] &= ~m; }
};

static int eval_cond(const c117::Condition &c, const IV &iv, const Key &K) {
    return c117::eval(c, [&](int j) { return iv.bit(j); }, [&](int i) { return K.bit(i); });
}
static bool conditions_hold(const IV &iv, const Key &K) {
    for (const auto &c : c117::conditions()) if (eval_cond(c, iv, K)) return false;
    return true;
}

// A random key satisfying the r_117 = 3 conditions that involve key bits only;
// a random key does so with probability 2^-3, which is the 2^{r_117} repetition
// factor of the attack.
static Key random_key(uint64_t seed) {
    std::mt19937_64 rng(seed);
    Key K;
    for (auto &x : K.w) x = rng();
    for (const auto &ko : c117::key_only()) K.set(ko.a, K.bit(ko.b) ^ ko.rhs);
    return K;
}

// Delta_m, the output difference of E_d under C_117.
static const int S1_117[] = {132, 190, 238, 311, 325, 327, 348, 422, 430, 444,
    505, 506, 519, 541, 598, 599, 600, 632, 657, 658, 659, 715, 769, 790, 818,
    834, 918, 930, 952, 954, 1010, 1107, 1193};
static const int S1_117_N = (int)(sizeof(S1_117) / sizeof(int));

// -------------------------------------------------------------- bit split ----
struct Split { std::vector<int> phi1, theta2; };
static Split make_split() {
    Split L; L.phi1 = c117::phi1();
    std::vector<char> used(IVBITS, 0);
    for (int j : L.phi1) used[j] = 1;
    used[c117::DELTA_IN] = 1;
    for (int j = 0; j < IVBITS; ++j) if (!used[j]) L.theta2.push_back(j);
    return L;
}

// ------------------------------------------------------------------ step 0 ---
// Delta_m is deterministic under C_117 and equals S^1_117.
static bool check_delta_m(const Ctx &ctx, const Split &L, uint64_t sol, uint64_t seed) {
    std::mt19937_64 rng(seed);
    for (int s = 0; s < 64; ++s) {
        State a = ctx.k0;
        for (size_t b = 0; b < L.phi1.size(); ++b)
            if ((sol >> b) & 1) a ^= ctx.fi_col[L.phi1[b]];
        for (int j : L.theta2) if (rng() & 1) a ^= ctx.fi_col[j];
        State b = a; b ^= ctx.fi_col[c117::DELTA_IN];
        round_R(a, 0); round_R(b, 0); a ^= b;
        int n = 0;
        for (int i = 0; i < STATEBITS; ++i)
            if (get_bit(a, i)) { if (n >= S1_117_N || S1_117[n] != i) return false; ++n; }
        if (n != S1_117_N) return false;
    }
    return true;
}

// ------------------------------------------------------------------ step 1 ---
// Key-independent differential-linear profile of Delta_m over E_m o E_l.
static std::vector<double> profile(int rounds, int outbits, int logM, uint64_t seed) {
    Key zero;                                   // any key: the profile does not depend on it
    Ctx ctx; ctx_setup(ctx, zero.w, rounds - 1, outbits);   // E_m o E_l only
    State dm; dm.clear();
    for (int i = 0; i < S1_117_N; ++i) set_bit(dm, S1_117[i], 1);

    std::mt19937_64 rng(seed);
    const uint64_t M = 1ull << logM;
    const int nw = (outbits + 63) / 64;
    std::vector<uint64_t> o1(nw), o2(nw);
    std::vector<int64_t> bias(outbits, 0);
    for (uint64_t g = 0; g < M; ++g) {
        State x;
        for (int L = 0; L < LANES; ++L) x.l[L] = (((u128)rng() << 64) | rng()) & LANE_MASK;
        State y = x; y ^= dm;
        finish(ctx, x, o1.data());
        finish(ctx, y, o2.data());
        for (int t = 0; t < outbits; ++t)
            bias[t] += (((o1[t >> 6] ^ o2[t >> 6]) >> (t & 63)) & 1) ? -1 : 1;
    }
    std::vector<double> v(outbits);
    for (int t = 0; t < outbits; ++t) v[t] = (double)bias[t] / (double)M;
    return v;
}

// ------------------------------------------------------------- measurement ---
// N pairs for one structure; the same list of samples of the free bits Theta_2
// is used for every structure so that the counters are comparable.
static void measure(const Ctx &ctx, const State &s0, const State *off, uint64_t N,
                    const State &dcol, const std::vector<int> &bits,
                    int outbits, double *corr) {
    const int nw = (outbits + 63) / 64;
    uint64_t o1[32], o2[32];
    (void)nw;
    std::vector<int64_t> bias(outbits, 0);
    for (uint64_t g = 0; g < N; ++g) {
        State x = s0; x ^= off[g];
        State y = x;  y ^= dcol;
        finish(ctx, x, o1);
        finish(ctx, y, o2);
        for (int t : bits)
            bias[t] += (((o1[t >> 6] ^ o2[t >> 6]) >> (t & 63)) & 1) ? -1 : 1;
    }
    for (int t : bits) corr[t] = (double)bias[t] / (double)N;
}

static std::vector<State> free_samples(const Ctx &ctx, const std::vector<int> &theta2,
                                       uint64_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<State> v(n);
    for (uint64_t i = 0; i < n; ++i) {
        v[i].clear();
        for (int j : theta2) if (rng() & 1) v[i] ^= ctx.fi_col[j];
    }
    return v;
}

// ------------------------------------------------------- key expressions -----
// Substituting the recovered IV[Theta_1] into C_117 leaves, for every
// condition, a Boolean equation in at most four key bits.  Its solution set is
// an affine subspace; we extract all linear relations that hold on it and keep
// an independent set.
struct Relation { std::set<int> vars; int rhs; };

static std::vector<Relation> key_expressions(const IV &iv) {
    std::map<int, Relation> basis;               // pivot key index -> relation
    std::vector<Relation> kept;
    for (const auto &c : c117::conditions()) {
        std::vector<int> kv;
        for (const auto &m : c) for (const auto &x : m)
            if (x.kind == c117::KEY && std::find(kv.begin(), kv.end(), x.idx) == kv.end())
                kv.push_back(x.idx);
        std::sort(kv.begin(), kv.end());
        const int k = (int)kv.size();
        if (k == 0 || k > 20) continue;
        std::vector<uint32_t> sols;
        for (uint32_t a = 0; a < (1u << k); ++a) {
            Key K;
            for (int i = 0; i < k; ++i) K.set(kv[i], (a >> i) & 1);
            if (!c117::eval(c, [&](int j) { return iv.bit(j); },
                               [&](int i) { for (int t = 0; t < k; ++t) if (kv[t] == i) return (int)((a >> t) & 1);
                                            return 0; })) sols.push_back(a);
        }
        if (sols.empty()) continue;
        for (uint32_t l = 1; l < (1u << k); ++l) {
            int c0 = __builtin_parity(l & sols[0]);
            bool constant = true;
            for (uint32_t s : sols) if (__builtin_parity(l & s) != c0) { constant = false; break; }
            if (!constant) continue;
            Relation r; r.rhs = c0;
            for (int i = 0; i < k; ++i) if ((l >> i) & 1) r.vars.insert(kv[i]);
            // reduce against the basis
            Relation cur = r;
            while (!cur.vars.empty()) {
                int p = *cur.vars.begin();
                auto it = basis.find(p);
                if (it == basis.end()) { basis[p] = cur; kept.push_back(r); break; }
                std::set<int> nv;
                std::set_symmetric_difference(cur.vars.begin(), cur.vars.end(),
                                              it->second.vars.begin(), it->second.vars.end(),
                                              std::inserter(nv, nv.begin()));
                cur.vars = nv; cur.rhs ^= it->second.rhs;
            }
        }
    }
    return kept;
}

// ------------------------------------------------------------------- main ----
int main(int argc, char **argv) {
    int    rounds = 3, outbits = 64, logN = 11, logN2 = 16, logP = 20, topk = 1024;
    int    nthreads = 0;
    uint64_t seed = 1;
    for (int i = 1; i < argc; ++i) {
        auto eq = [&](const char *s) { return strcmp(argv[i], s) == 0; };
        if      (eq("--seed")    && i + 1 < argc) seed     = strtoull(argv[++i], nullptr, 0);
        else if (eq("--logN")    && i + 1 < argc) logN     = atoi(argv[++i]);
        else if (eq("--logN2")   && i + 1 < argc) logN2    = atoi(argv[++i]);
        else if (eq("--logP")    && i + 1 < argc) logP     = atoi(argv[++i]);
        else if (eq("--topk")    && i + 1 < argc) topk     = atoi(argv[++i]);
        else if (eq("--threads") && i + 1 < argc) nthreads = atoi(argv[++i]);
        else { fprintf(stderr, "usage: %s [--seed S] [--logN 11] [--logN2 16] "
                               "[--logP 20] [--topk 1024] [--threads T]\n", argv[0]); return 1; }
    }
    if (nthreads <= 0) nthreads = std::max(1u, std::thread::hardware_concurrency());
    init();

    const Key K = random_key(seed);                 // secret key, used only by the oracle
    Ctx ctx; ctx_setup(ctx, K.w, rounds, outbits);
    const Split L = make_split();
    const size_t P = L.phi1.size();
    const uint64_t NSTRUCT = 1ull << P, N1 = 1ull << logN, N2 = 1ull << logN2;

    printf("3-round Twinkle, Delta_in = e_117, output truncated to %d bits\n", outbits);
    printf("|Theta_1| = %zu, |Theta_2| = %zu, N' = 2^%d, N'' = 2^%d, %d threads\n\n",
           P, L.theta2.size(), logN, logN2, nthreads);

    // -- step 0 ---------------------------------------------------------------
    uint64_t sol = 0; bool have = false;
    for (uint64_t a = 0; a < NSTRUCT && !have; ++a) {
        IV iv{};
        for (size_t b = 0; b < P; ++b) iv.set(L.phi1[b], (int)((a >> b) & 1));
        if (conditions_hold(iv, K)) { sol = a; have = true; }
    }
    if (!have) { fprintf(stderr, "C_117 has no solution for this key\n"); return 1; }
    printf("[0] Delta_m: C_117 makes the difference after E_d deterministic and "
           "equal to S^1_117 : %s\n", check_delta_m(ctx, L, sol, seed ^ 0x51ull) ? "yes" : "NO");

    // -- step 1 ---------------------------------------------------------------
    std::vector<double> v = profile(rounds, outbits, logP, seed ^ 0x5bf03635ull);
    std::vector<int> sig;
    for (int t = 0; t < outbits; ++t) if (std::fabs(v[t]) > 0.02) sig.push_back(t);
    printf("[1] profile of Delta_m over E_m o E_l (2^%d pairs, key-independent):\n", logP);
    for (int t : sig)
        printf("      Gamma_out = e_%-3d   c = %+.5f = %s2^%.2f\n", t, v[t],
               v[t] < 0 ? "-" : "+", std::log2(std::fabs(v[t])));

    // -- step 2 ---------------------------------------------------------------
    std::vector<State> off1 = free_samples(ctx, L.theta2, N1, seed ^ 0xabcdef01ull);
    std::vector<State> pcol;
    for (int j : L.phi1) pcol.push_back(ctx.fi_col[j]);
    const State dcol = ctx.fi_col[c117::DELTA_IN];

    std::vector<float> dist1(NSTRUCT);
    auto t0 = std::chrono::steady_clock::now();
    auto pass1 = [&](int tid) {
        std::vector<double> corr(outbits, 0.0);
        for (uint64_t a = NSTRUCT * tid / nthreads; a < NSTRUCT * (tid + 1) / nthreads; ++a) {
            State s0 = ctx.k0;
            for (size_t b = 0; b < P; ++b) if ((a >> b) & 1) s0 ^= pcol[b];
            measure(ctx, s0, off1.data(), N1, dcol, sig, outbits, corr.data());
            double d = 0;
            for (int t : sig) { double e = corr[t] - v[t]; d += e * e; }
            dist1[a] = (float)std::sqrt(d);
        }
    };
    { std::vector<std::thread> th;
      for (int i = 0; i < nthreads; ++i) th.emplace_back(pass1, i);
      for (auto &t : th) t.join(); }
    double dt1 = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    std::vector<uint32_t> ord(NSTRUCT);
    for (uint64_t a = 0; a < NSTRUCT; ++a) ord[a] = (uint32_t)a;
    std::partial_sort(ord.begin(), ord.begin() + topk, ord.end(),
                      [&](uint32_t x, uint32_t y) { return dist1[x] < dist1[y]; });
    uint64_t r1 = 0; while (r1 < NSTRUCT && ord[r1] != sol) ++r1;
    printf("\n[2] first pass: 2^%zu structures x 2^%d pairs = 2^%.0f pairs, %.1f s\n",
           P, logN, std::log2((double)NSTRUCT * N1), dt1);
    printf("      the structure satisfying C_117 is ranked %llu of %llu\n",
           (unsigned long long)(r1 + 1), (unsigned long long)NSTRUCT);

    // -- step 3 ---------------------------------------------------------------
    std::vector<State> off2 = free_samples(ctx, L.theta2, N2, seed ^ 0x1234abcdull);
    std::vector<float> dist2(topk);
    t0 = std::chrono::steady_clock::now();
    auto pass2 = [&](int tid) {
        std::vector<double> corr(outbits, 0.0);
        for (int i = tid; i < topk; i += nthreads) {
            uint32_t a = ord[i];
            State s0 = ctx.k0;
            for (size_t b = 0; b < P; ++b) if ((a >> b) & 1) s0 ^= pcol[b];
            measure(ctx, s0, off2.data(), N2, dcol, sig, outbits, corr.data());
            double d = 0;
            for (int t : sig) { double e = corr[t] - v[t]; d += e * e; }
            dist2[i] = (float)std::sqrt(d);
        }
    };
    { std::vector<std::thread> th;
      for (int i = 0; i < nthreads; ++i) th.emplace_back(pass2, i);
      for (auto &t : th) t.join(); }
    double dt2 = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    std::vector<int> ord2(topk);
    for (int i = 0; i < topk; ++i) ord2[i] = i;
    std::sort(ord2.begin(), ord2.end(), [&](int x, int y) { return dist2[x] < dist2[y]; });
    printf("\n[3] second pass: %d structures x 2^%d pairs, %.1f s\n", topk, logN2, dt2);
    for (int i = 0; i < std::min(4, topk); ++i)
        printf("      #%d  IV[Theta_1] = 0x%05x   distance %.5f%s\n", i + 1,
               ord[ord2[i]], dist2[ord2[i]],
               ord[ord2[i]] == sol ? "   <-- satisfies C_117" : "");

    const uint32_t win = ord[ord2[0]];
    IV iv{};
    for (size_t b = 0; b < P; ++b) iv.set(L.phi1[b], (int)((win >> b) & 1));
    printf("\n[4] recovered IV[Theta_1] :");
    for (size_t b = 0; b < P; ++b) printf(" iv%d=%d", L.phi1[b], iv.bit(L.phi1[b]));
    printf("\n      C_117 satisfied by the recovered value : %s\n",
           conditions_hold(iv, K) ? "yes" : "no");

    std::vector<Relation> rel = key_expressions(iv);
    int wrong = 0;
    printf("      %zu independent key expressions:\n", rel.size());
    for (const auto &r : rel) {
        int lhs = 0; bool first = true;
        printf("        ");
        for (int i : r.vars) { printf("%sK%d", first ? "" : " + ", i); first = false; lhs ^= K.bit(i); }
        printf(" = %d   [%s]\n", r.rhs, lhs == r.rhs ? "correct" : "WRONG");
        wrong += (lhs != r.rhs);
    }
    printf("\n%s: %zu key expressions recovered, %d of them wrong.\n",
           wrong == 0 && conditions_hold(iv, K) ? "SUCCESS" : "FAILURE", rel.size(), wrong);
    return (wrong == 0) ? 0 : 1;
}
