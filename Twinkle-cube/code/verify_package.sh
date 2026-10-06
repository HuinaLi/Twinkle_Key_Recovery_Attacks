#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
sage_python="${TWINKLE_PYTHON:-/home/author/miniforge3/envs/sage/bin/python}"
bash -n code/run_solve_twinkle_cube.sh
bash -n code/run_key_recovery.sh
bash -n code/run_forgery_attack.sh
"$sage_python" -m py_compile code/run_cube_sat_search.py code/pa_cube_search_model.py code/pa_sat_result_printer.py code/twinkle_round_function.py
find code -type d -name __pycache__ -prune -exec rm -rf {} +
key_dir=cube_like_attack/result/key_recovery_bounds1177_ivstart9
forgery_dir=forgery_attack/result/forgery_attack_single_ivstart28
key_result=$(find "$key_dir" -maxdepth 1 -type f -name 'result_*_no*.log' | sort -V | tail -1)
forgery_result=$(find "$forgery_dir" -maxdepth 1 -type f -name 'result_*_no1.log' | sort -V | tail -1)
if [ -z "$key_result" ] || [ -z "$forgery_result" ]; then echo "Missing expected result logs" >&2; exit 1; fi
"$sage_python" - "$key_result" "$key_dir" <<'PY'
import re, sys, pathlib
key_result = pathlib.Path(sys.argv[1])
key_dir = pathlib.Path(sys.argv[2])
text = key_result.read_text(encoding='utf-8', errors='replace')
m = re.findall(r'Total_unique_auxiliary_and_involved_key_bits:\s*(\d+)\s*/\s*(\d+)', text)
if not m: raise SystemExit(f'missing coverage in {key_result}')
value, bound = map(int, m[-1])
if bound != 1177 or value < 1177: raise SystemExit(f'coverage failed: {value}/{bound}')
for path in key_dir.glob('result_*_no*.log'):
    t = path.read_text(encoding='utf-8', errors='replace')
    a = re.findall(r'New_auxiliary_expr_count:\s*(\d+)', t)
    b = re.findall(r'New_involved_key_bit_count:\s*(\d+)', t)
    if a and b and int(a[-1]) + int(b[-1]) < 1:
        raise SystemExit(f'accepted result has zero new coverage: {path}')
PY
grep -q 'cube_variables:' "$forgery_result"
grep -q 'A\[0\]_matrix:' "$forgery_result"
grep -q 'B0_symbolic_check: OK' "$forgery_result"
grep -q 'C0_symbolic_check: OK' "$forgery_result"
grep -q 'D0_symbolic_check: OK' "$forgery_result"
grep -q 'A1_symbolic_check: OK' "$forgery_result"
if grep -qE 'Continuous_search_summary|Independent_auxiliary_check|involved_key_bit' "$forgery_result"; then echo "Forgery result contains key-recovery-only output" >&2; exit 1; fi
test ! -d Twinkle-cube_like_attack/code
test ! -d Twinkle-PA
echo "Package verification passed."
