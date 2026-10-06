#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: bash code/run_key_recovery.sh [--solver <path>]

Run PA key recovery: 1280 1 9 5 1 with bounds=1177.
USAGE
}

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
solver="${TWINKLE_SAT_SOLVER:-/home/author/sat-solvers/lingeling/treengeling}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --solver) solver=$2; shift 2 ;;
    --solver=*) solver=${1#*=}; shift ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
export TWINKLE_PYTHON="${TWINKLE_PYTHON:-/home/author/miniforge3/envs/sage/bin/python}"
export TWINKLE_MAX_SEARCH_ATTEMPTS="${TWINKLE_MAX_SEARCH_ATTEMPTS:-500}"
run_id="pa_key_recovery_twinkle1280_1r_ivstart9_sat5_task1_bounds1177_review_$(date +%Y%m%d_%H%M%S)"
bash code/run_solve_twinkle_cube.sh \
  --variant pa \
  --attack-mode key_recovery \
  --solver "$solver" \
  --output-root "$repo_root/cube_like_attack" \
  --output-subdir key_recovery_bounds1177_ivstart9 \
  --bounds 1177 \
  --min-new-coverage 1 \
  --low-gain-min-swaps 2 \
  --adaptive-diversity \
  --max-low-gain-min-swaps 4 \
  --run-id "$run_id" \
  1280 1 9 5 1
