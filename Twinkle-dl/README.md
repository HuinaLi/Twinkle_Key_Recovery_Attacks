# Partial key recovery on 3-round Twinkle

Reference implementation of the experiment reported in the paper: Algorithm 2 called with `((Delta_in = e_117, Gamma_out = e_40), (Theta_1, Theta_2), C_117)` on 3-round Twinkle at security level SL1 (`E_d` 1 round, `E_m` 2 rounds, `E_l = F_O`, output truncated to 64 bits).

## Build and run

```sh
make
./keyrecovery                 # default parameters, uses all cores
./keyrecovery --seed 7 --threads 8
```

No dependencies beyond a C++17 compiler.

## Files

| file | contents |
|---|---|
| `twinkle.hpp`, `twinkle.cpp` | Twinkle: `F_I`, `SBox`, `LaneRotation0/1`, `MixSlice`, `AC`, `F_O`, whitening keys `k0, k1` |
| `conditions.hpp` | the 17 conditions `C_117`, the conditional IV bits `Theta_1`, the 3 key-only conditions |
| `keyrecovery.cpp` | the attack |

State bits are numbered lane-major, `i = 80*Lambda + z`; this is the numbering in which `C_117` and `S^1_117` are written, and it is documented at the top of `twinkle.hpp`. The secret key is used only inside the oracle, and once more at the end to report whether the recovered key expressions are correct.

## The attack

**Step 0 — `Delta_m`.** Imposing `C_117` makes the difference after `E_d` deterministic and equal to `Delta_m = sum_{k in S^1_117} e_k`. The program checks this before attacking.

**Step 1 — profile (offline).** Twinkle is an Even–Mansour construction, so no key material enters between `E_d` and the output. The correlations `v[t] = corr( <e_t , F_O(E_m(X)) xor F_O(E_m(X xor Delta_m))> ),   t < 64` are therefore key-independent and are computed without any query. They are the signature of the intended `Delta_m`:

```
  Gamma_out = e_0     c = +2^-4.99
  Gamma_out = e_6     c = +2^-4.95
  Gamma_out = e_40    c = -2^-2.00
  Gamma_out = e_53    c = +2^-4.98
  Gamma_out = e_56    c = +2^-4.00
  Gamma_out = e_61    c = +2^-4.97
```

**Step 2 — first pass.** For each of the `2^18` assignments of `IV[Theta_1]` the empirical correlations `u_a[t]` are measured on `N' = 2^11` pairs and the structures are ranked by `|| u_a - v ||`.

Ranking by `|u_a[t]|` at the single bit `t = 40` is weaker: other assignments of `IV[Theta_1]` also make `E_d` deterministic, towards a different `Delta_m'` whose correlation on that one bit can be larger. With a threshold of `0.15` on `|u_a[40]|` the correct structure passes the test but 815 further structures do too. Comparing the whole profile against `v` costs nothing extra — `v` is known offline — and puts the correct structure in the first few.

**Step 3 — second pass.** The best `2^10` structures are re-measured with `N'' = 2^16` fresh pairs. The winner is the assignment satisfying `C_117`; substituted into `C_117` it yields the key expressions.

## Experimental results

Two cores, `g++ -O3 -march=native`; one evaluation of 3-round Twinkle takes about 0.47 µs.

| | |
|---|---|
| data, first pass | `2^18 x 2^11 = 2^29` chosen-plaintext pairs |
| data, second pass | `2^10 x 2^16 = 2^26` pairs |
| time | ≈ 420 s + 51 s on two cores |
| correlation of the structure satisfying `C_117` | `-2^-1.9` at `Gamma_out = e_40` (predicted `-2^-2.00`) |
| correlation of the other structures | 99 % below `2^-4` |
| rank after the first pass | 1, 3 and 21 of `2^18` for the three keys tried |
| rank after the second pass | 1 of `2^10` |
| output | 21 independent key expressions, all correct |

The 21 expressions are the 17 conditions of `C_117` together with the 4 extra ones obtained from the mixed `IV x K` terms; 3 of them (`K310 + K630 = 1`, `K139 + K459 = 1`, `K651 + K971 = 1`) are the key-only conditions, which hold for a random key with probability `2^-3` — the `2^{r_117}` repetition factor of the attack. The program draws keys that satisfy them, so that one run of Algorithm 2 is executed instead of `2^3`.

Sample output (`--seed 1`):

```
[0] Delta_m: C_117 makes the difference after E_d deterministic and equal to S^1_117 : yes
[2] first pass: 2^18 structures x 2^11 pairs = 2^29 pairs, 423.5 s
      the structure satisfying C_117 is ranked 1 of 262144
[3] second pass: 1024 structures x 2^16 pairs, 51.4 s
      #1  IV[Theta_1] = 0x0ef16   distance 0.01000   <-- satisfies C_117
      #2  IV[Theta_1] = 0x0ef06   distance 0.01435
[4] recovered IV[Theta_1] : iv2=0 iv3=1 iv18=1 iv36=0 iv39=1 ...
      C_117 satisfied by the recovered value : yes
      21 independent key expressions:
        K331 = 1                  [correct]
        K139 + K459 + K779 = 0    [correct]
        ...
        K949 = 1                  [correct]

SUCCESS: 21 key expressions recovered, 0 of them wrong.
```

Full logs for two keys are in `run_seed1.log` and `run_seed2.log`.
