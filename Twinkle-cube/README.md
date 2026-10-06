# Twinkle

## About

SAT-based Twinkle cryptanalysis toolkit for PA key recovery, forgery attacks, without-IO cube search, and practical forgery simulations.

## Project Structure

```text
Twinkle/
├── code/
│   ├── run_solve_twinkle_cube.sh              # General shell wrapper for SAT cube-search runs.
│   ├── run_cube_sat_search.py                 # Main SAT search driver.
│   ├── run_key_recovery.sh                    # PA key-recovery review run: 1280 1 9 5 1, bounds=1177.
│   ├── run_forgery_attack.sh                  # PA forgery cube-search review run: 1280 1 28 5 2.
│   ├── run_practical_forgery_attack.sh        # Wrapper for the PA practical forgery simulator.
│   ├── verify_package.sh                      # Static/result verification helper.
│   ├── pa_cube_search_model.py                # PA cube-search model.
│   ├── without_io_cube_search_model.py        # Without-IO r-round cube-search model.
│   ├── pa_sat_result_printer.py               # PA result printer.
│   ├── without_io_sat_result_printer.py       # Without-IO result printer.
│   ├── practical_forgery_attack.py            # Practical PA forgery simulator.
│   ├── practical_forgery_fast.c               # C backend for practical PA forgery.
│   ├── practical_without_io_forgery_attack.py # Practical without-IO forgery simulator.
│   ├── practical_without_io_forgery_fast.c    # C backend for practical without-IO forgery.
│   ├── twinkle_round_function.py              # Twinkle round-function and state-index helpers.
│   ├── generate_twinkle_operator_cnf.py       # Operator CNF generation utility.
│   ├── sbox_anf_tools.py                      # S-box helper utilities.
│   └── constraints/                           # JSON truth-table constraints for CNF generation.
├── cube_like_attack/
│   ├── cons/key_recovery_bounds1177_ivstart9/   # PA key-recovery CNFs and solver logs.
│   ├── logs/key_recovery_bounds1177_ivstart9/   # PA key-recovery wrapper logs.
│   └── result/key_recovery_bounds1177_ivstart9/ # PA key-recovery result, rejected, and checkpoint logs.
├── forgery_attack/
│   ├── cons/forgery_attack_single_ivstart28/    # PA 28-cube forgery CNF and solver log.
│   ├── cons/forgery_attack_single_ivstart9/     # PA 9-cube demonstration CNF and solver log.
│   ├── logs/forgery_attack_single_ivstart28/    # PA 28-cube wrapper log.
│   ├── logs/forgery_attack_single_ivstart9/     # PA 9-cube wrapper log.
│   └── result/
│       ├── forgery_attack_single_ivstart28/     # PA 28-cube result log.
│       ├── forgery_attack_single_ivstart9/      # PA 9-cube result log.
│       ├── practical_forgery_attack_single_ivstart28/ # Practical 4-round PA forgery outputs.
│       └── practical_forgery_attack_single_ivstart9/  # Complete 3-round PA forgery demo outputs.
├── without_io/
│   ├── cons/                                  # Without-IO CNFs and solver logs.
│   ├── logs/                                  # Without-IO wrapper logs.
│   └── result/
│       ├── result_without-io_*.log            # Without-IO cube-search result logs.
│       └── practical_without_io_forgery_single_ivstart28/ # Practical 5-round without-IO outputs.
├── property_check/                            # Property-check logs and experiment outputs.
├── operator_espresso.cnf                      # Espresso-derived operator CNF artifact.
├── operator_espresso.pla                      # Espresso PLA artifact.
└── operator_sympy.cnf                         # SymPy-derived operator CNF artifact.
```

## Environment

Use a Sage-capable Python environment:

```bash
conda activate sage
```

or pass it explicitly to the wrappers:

```bash
export TWINKLE_PYTHON=/home/author/miniforge3/envs/sage/bin/python
```

## SAT Solver

The SAT solver is resolved in this order:

```text
--solver <path> > TWINKLE_SAT_SOLVER > /home/author/sat-solvers/lingeling/treengeling
```

Example:

```bash
bash code/run_key_recovery.sh --solver /home/author/sat-solvers/lingeling/treengeling
```

## PA Key Recovery

This is the cube-like key-recovery run used for the review results. It performs continuous search until the number of unique auxiliary expressions plus unique involved key bits reaches `1177`.

```bash
cd /home/author/Twinkle
bash code/run_key_recovery.sh --solver /home/author/sat-solvers/lingeling/treengeling
```

Internal parameters:

```text
variant      = pa
attack mode  = key_recovery
cipher       = 1280
rounds       = 1
ivstart      = 9
sat threads  = 5
task id      = 1
bounds       = 1177
```

Outputs are written under:

```text
cube_like_attack/cons/key_recovery_bounds1177_ivstart9/
cube_like_attack/logs/key_recovery_bounds1177_ivstart9/
cube_like_attack/result/key_recovery_bounds1177_ivstart9/
```

Accepted key-recovery result logs contain `Continuous_search_summary` and the auxiliary/key summary table. Low-gain solutions are saved as `rejected_low_gain_*.log` and are not counted as accepted results.

## PA Forgery Cube Search

This workflow searches a single PA forgery cube and prints only the cube variables and symbolic state matrices/checks.

```bash
cd /home/author/Twinkle
bash code/run_forgery_attack.sh --solver /home/author/sat-solvers/lingeling/treengeling
```

Internal parameters:

```text
variant      = pa
attack mode  = forgery_attack
cipher       = 1280
rounds       = 1
ivstart      = 28
sat threads  = 5
task id      = 2
```

Outputs are written under:

```text
forgery_attack/cons/forgery_attack_single_ivstart28/
forgery_attack/logs/forgery_attack_single_ivstart28/
forgery_attack/result/forgery_attack_single_ivstart28/
```

A smaller 9-dimensional PA forgery cube used by the practical demonstration is generated with:

```bash
cd /home/author/Twinkle
TWINKLE_PYTHON=/home/author/miniforge3/envs/sage/bin/python \
bash code/run_solve_twinkle_cube.sh \
  --variant pa \
  --attack-mode forgery_attack \
  --solver /home/author/sat-solvers/lingeling/treengeling \
  --output-root /home/author/Twinkle/forgery_attack \
  --output-subdir forgery_attack_single_ivstart9 \
  --run-id pa_forgery_attack_twinkle1280_1r_ivstart9_sat5_task3_review_<timestamp> \
  1280 1 9 5 3
```

## Without-IO Cube Search

The without-IO model supports r-round propagation:

```text
A[i] --Sbox--> B[i] --LR0--> C[i] --MS--> D[i] --LR1--> A[i+1]
```

for every `i = 0 .. rounds-2`. The primary state variables follow:

```text
A[0..rounds-1], B[0..rounds-2], C[0..rounds-2], D[0..rounds-2]
```

so the primary variable count is:

```text
4 * (rounds - 1) * STATE_SIZE + STATE_SIZE
```

The existing 2-round ivstart28 run can be regenerated with:

```bash
cd /home/author/Twinkle
TWINKLE_PYTHON=/home/author/miniforge3/envs/sage/bin/python \
bash code/run_solve_twinkle_cube.sh --variant without-io 1280 2 28 5 3
```

A smaller 3-round ivstart9 run is:

```bash
cd /home/author/Twinkle
TWINKLE_PYTHON=/home/author/miniforge3/envs/sage/bin/python \
bash code/run_solve_twinkle_cube.sh --variant without-io 1280 3 9 5 12
```

Without-IO outputs are written under:

```text
without_io/cons/
without_io/logs/
without_io/result/
```

For `rounds = 3`, the result log prints both transition layers:

```text
A[0]_matrix:
B[0]_matrix:
B0_symbolic_check: OK
C[0]_matrix:
C0_symbolic_check: OK
D[0]_matrix:
D0_symbolic_check: OK
A[1]_matrix:
A1_symbolic_check: OK
B[1]_matrix:
B1_symbolic_check: OK
C[1]_matrix:
C1_symbolic_check: OK
D[1]_matrix:
D1_symbolic_check: OK
A[2]_matrix:
A2_symbolic_check: OK
```

## Result Log Format

PA forgery-attack and without-IO result logs use a compact matrix/check format:

```text
cube_variables:
A[0]_matrix:
B[0]_matrix:
B0_symbolic_check: OK
C[0]_matrix:
C0_symbolic_check: OK
D[0]_matrix:
D0_symbolic_check: OK
A[1]_matrix:
A1_symbolic_check: OK
```

For more than two without-IO states, the same `B[i]`, `C[i]`, `D[i]`, `A[i+1]` pattern is repeated for each propagation layer.

PA key-recovery result logs additionally contain:

```text
Independent_auxiliary_check: OK count=90
Max_independent_auxiliary_original_IV_bits: 90 / 90
| Auxiliary_original_IV | auxiliary: ki + kj | involved_key_bit |
Continuous_search_summary:
Total_unique_auxiliary_and_involved_key_bits: <n> / 1177
```

## Practical PA Forgery Attack

The PA practical forgery simulator uses the cube found by PA forgery cube search and treats the authentication input as a single 128-bit pointer `P`:

```text
T = Twinkle64_t(P, K), |P| = 128 bits, |K| = 1280 bits
```

The tool computes the target tag `T' = Twinkle64_t(P, K)`, enumerates all non-target pointers in the cube, XORs their tags to obtain the forged tag `T`, and verifies:

```text
verification_xor = T' XOR T
verification_xor == 0...0
```

The tag-length rule is strict:

```text
cube_dimension < tag_length <= 32
```

Therefore a 28-dimensional cube must use `tag_length = 29`, `30`, `31`, or `32`. The default practical 28-cube run uses `tag_length = 29`.

A dry-run parses the cube, constructs the target pointer, computes `target_tag`, and prints query samples without enumerating the full cube:

```bash
cd /home/author/Twinkle
KEY=$(/home/author/miniforge3/envs/sage/bin/python -c 'print("0"*1280)')

/home/author/miniforge3/envs/sage/bin/python code/practical_forgery_attack.py \
  --result-log forgery_attack/result/forgery_attack_single_ivstart28/result_pa_forgery_attack_twinkle1280_1r_ivstart28_sat5_task2_review_20260429_222903_no1.log \
  --rounds 4 \
  --target-assignment 0 \
  --tag-length 29 \
  --key-bits "$KEY"
```

Full execution requires `2^28 - 1` simulated oracle queries. Use the C backend and checkpointing for long runs:

```bash
cd /home/author/Twinkle
KEY=$(/home/author/miniforge3/envs/sage/bin/python -c 'print("0"*1280)')

nice -n 10 /home/author/miniforge3/envs/sage/bin/python code/practical_forgery_attack.py \
  --result-log forgery_attack/result/forgery_attack_single_ivstart28/result_pa_forgery_attack_twinkle1280_1r_ivstart28_sat5_task2_review_20260429_222903_no1.log \
  --rounds 4 \
  --target-assignment 0 \
  --tag-length 29 \
  --key-bits "$KEY" \
  --execute \
  --backend c \
  --checkpoint-interval 1048576 \
  --output-dir forgery_attack/result/practical_forgery_attack_single_ivstart28
```

If interrupted, resume from the checkpoint. The resumed run appends progress to the original log:

```bash
cd /home/author/Twinkle
nice -n 10 /home/author/miniforge3/envs/sage/bin/python code/practical_forgery_attack.py \
  --resume forgery_attack/result/practical_forgery_attack_single_ivstart28/<timestamp>.checkpoint.json
```

Useful execution fields:

```text
processed_queries  # Number of non-target cube points already queried.
skipped_target_queries  # Usually 1, because the target assignment is excluded.
partial: true      # The run stopped early, for example due to --max-queries.
partial: false     # The full cube was enumerated.
verification: OK   # Only meaningful for a complete run.
```

### Complete 3-Round PA Demonstration

The ivstart9 demonstration is small enough to run completely. It uses `cube_dimension = 9`, `tag_length = 10`, `rounds = 3`, `target_assignment = 0`, and exactly `2^9 - 1 = 511` non-target queries:

```bash
cd /home/author/Twinkle
KEY=$(/home/author/miniforge3/envs/sage/bin/python -c 'print("0"*1280)')

/home/author/miniforge3/envs/sage/bin/python code/practical_forgery_attack.py \
  --result-log forgery_attack/result/forgery_attack_single_ivstart9/result_pa_forgery_attack_twinkle1280_1r_ivstart9_sat5_task3_review_20260430_010333_no1.log \
  --rounds 3 \
  --target-assignment 0 \
  --tag-length 10 \
  --key-bits "$KEY" \
  --execute
```

A successful complete log contains:

```text
processed_queries: 511
partial: false
verification: OK
Forgery attack succeeded.
```

## Practical Without-IO Forgery Attack

The without-IO practical simulator is separate from the PA simulator. It has no FI input expansion: the pointer/state `P` is already 1280 bits. The oracle is:

```text
state = P XOR K
repeat rounds: Sbox -> LR0 -> MS -> LR1 -> AddConstant
tag = FO(state, tag_length)
```

Here `P` is parsed from the without-IO `A[0]_matrix`, `K` is a 1280-bit key, and the 28 cube variables are the only positions varied during enumeration. The remaining `1280 - 28 = 1252` fixed positions are constant for the whole run.

The tag-length rule is:

```text
cube_dimension < tag_length <= 1152
```

For the 28-cube 5-round practical run, use `tag_length = 29`.

Run with the fixed constants from the without-IO result log:

```bash
cd /home/author/Twinkle
KEY=$(/home/author/miniforge3/envs/sage/bin/python -c 'print("0"*1280)')

nice -n 10 /home/author/miniforge3/envs/sage/bin/python code/practical_without_io_forgery_attack.py \
  --result-log without_io/result/result_without-io_twinkle1280_2r_ivstart28_sat5_task3_20260429_224313_no1.log \
  --rounds 5 \
  --target-assignment 0 \
  --tag-length 29 \
  --key-bits "$KEY" \
  --execute \
  --backend c \
  --checkpoint-interval 1048576 \
  --output-dir without_io/result/practical_without_io_forgery_single_ivstart28
```

To use a reproducible mixed fixed-constant vector for the 1252 non-cube positions, provide a seed:

```bash
/home/author/miniforge3/envs/sage/bin/python code/practical_without_io_forgery_attack.py \
  --result-log without_io/result/result_without-io_twinkle1280_2r_ivstart28_sat5_task3_20260429_224313_no1.log \
  --rounds 5 \
  --target-assignment 0 \
  --tag-length 29 \
  --key-bits "$KEY" \
  --fixed-constants-seed without_io_5r28_mixed_constants_example \
  --execute \
  --backend c \
  --checkpoint-interval 1048576 \
  --output-dir without_io/result/practical_without_io_forgery_single_ivstart28_mixed_constants
```

`--fixed-constants-seed` deterministically derives the 1252 fixed bits once before enumeration. `--fixed-constants-bits <1252-bit-string>` can be used instead for an explicit vector. The fixed bits must not be all zeros or all ones when one of these override options is used.

Resume an interrupted without-IO practical run with:

```bash
cd /home/author/Twinkle
nice -n 10 /home/author/miniforge3/envs/sage/bin/python code/practical_without_io_forgery_attack.py \
  --resume without_io/result/practical_without_io_forgery_single_ivstart28/<timestamp>.checkpoint.json
```

For long `2^28 - 1` runs, use `tmux` plus `nice` so the process survives SSH disconnection and is less intrusive to other users:

```bash
tmux new -s without_io_5r28
# run the command inside tmux, then detach with Ctrl-b d
```

## Verification

Run the package verification helper:

```bash
cd /home/author/Twinkle
bash code/verify_package.sh
```

This currently checks the PA key-recovery review output and the PA forgery cube-search review output. For practical backends, also run:

```bash
cd /home/author/Twinkle
/home/author/miniforge3/envs/sage/bin/python -m py_compile \
  code/practical_forgery_attack.py \
  code/practical_without_io_forgery_attack.py

gcc -O3 -std=c11 -Wall -Wextra -o /tmp/practical_forgery_fast code/practical_forgery_fast.c
gcc -O3 -std=c11 -Wall -Wextra -o /tmp/practical_without_io_forgery_fast code/practical_without_io_forgery_fast.c
```

Manual syntax checks for the shell entry points:

```bash
bash -n code/run_solve_twinkle_cube.sh
bash -n code/run_key_recovery.sh
bash -n code/run_forgery_attack.sh
bash -n code/run_practical_forgery_attack.sh
```

## Cleanup

Generated CNFs, solver logs, wrapper logs, result logs, JSON files, and checkpoints are timestamped. Delete only generated artifacts for the same run family and timestamp when cleaning old experiments. Do not delete source files, unrelated experiment outputs, or long-running checkpoints unless intentionally resetting that experiment.