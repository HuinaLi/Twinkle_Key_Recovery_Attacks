#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
python_bin="${TWINKLE_PYTHON:-/home/author/miniforge3/envs/sage/bin/python}"
exec "$python_bin" code/practical_forgery_attack.py "$@"
