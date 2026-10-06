#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: bash code/run_forgery_attack.sh [--solver <path>]

Run PA forgery attack cube search: 1280 1 28 5 2.
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
run_id="pa_forgery_attack_twinkle1280_1r_ivstart28_sat5_task2_review_$(date +%Y%m%d_%H%M%S)"
bash code/run_solve_twinkle_cube.sh \
  --variant pa \
  --attack-mode forgery_attack \
  --solver "$solver" \
  --output-root "$repo_root/forgery_attack" \
  --output-subdir forgery_attack_single_ivstart28 \
  --run-id "$run_id" \
  1280 1 28 5 2
