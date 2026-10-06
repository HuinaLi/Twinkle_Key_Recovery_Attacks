#!/bin/bash
# Requires a Sage-capable Python: run after conda activate sage, or set TWINKLE_PYTHON.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)
workspace_root=$(cd -- "${repo_root}/.." && pwd)
sat_solver="${TWINKLE_SAT_SOLVER:-/home/author/sat-solvers/lingeling/treengeling}"

usage() {
    cat <<USAGE
Usage: bash code/run_solve_twinkle_cube.sh [-v|--variant <pa|without-io>] [--attack-mode <key_recovery|forgery_attack>] [--solver <path>] [--bounds <n>] [--min-new-coverage <n>] [--low-gain-min-swaps <n>] [--adaptive-diversity] [--max-low-gain-min-swaps <n>] [--run-id <id>] [--start-search-id <n>] [cipher] <rounds> <iv_start_bound> <sat_threads> <task_id>

Run SAT search for Twinkle cube parameters.

Options:
  -v, --variant      Select run target: pa (default) or without-io.
  --attack-mode      PA workflow: key_recovery (default) or forgery_attack.
  --solver           SAT solver executable path; overrides TWINKLE_SAT_SOLVER.
  --output-root      Output root directory; defaults to the variant target.
  --output-subdir    Instance subdirectory under cons/, logs/, and result/.
  --bounds           Optional PA continuous search bound for unique auxiliary/involved bits.
  --min-new-coverage Low-gain threshold for PA continuous search diversity bans.
  --low-gain-min-swaps Minimum active IV swaps required after a low-gain result.
  --adaptive-diversity Increase low-gain min swaps after repeated low-gain results.
  --max-low-gain-min-swaps Maximum min-swaps value used by adaptive diversity.
  --run-id           Reuse this run id instead of creating a timestamped one.
  --start-search-id  Resume continuous search from this no<N> result id.

Arguments:
  cipher          Optional Twinkle cipher size: 1280 (default), 256, or 128.
  rounds          Number of rounds to solve.
  iv_start_bound  IV start bound passed to -d.
  sat_threads     Number of SAT solver threads passed to -satTrd.
  task_id         Task identifier used in run filenames and failure logs.

Examples:
  bash code/run_solve_twinkle_cube.sh 1280 1 27 5 1
  bash code/run_solve_twinkle_cube.sh --variant pa 1280 1 27 5 1
  bash code/run_solve_twinkle_cube.sh --variant pa --attack-mode key_recovery --bounds 1177 1280 1 9 5 2
  bash code/run_solve_twinkle_cube.sh --variant pa --attack-mode forgery_attack 1280 1 28 5 4
  bash code/run_solve_twinkle_cube.sh --variant pa --bounds 1177 --min-new-coverage 1 --low-gain-min-swaps 2 --adaptive-diversity --max-low-gain-min-swaps 4 1280 1 9 5 2
  bash code/run_solve_twinkle_cube.sh --variant pa --bounds 250 --run-id pa_twinkle1280_1r_ivstart9_sat5_task2_20260429_175129 --start-search-id 6 1280 1 9 5 2
  bash code/run_solve_twinkle_cube.sh --variant without-io 1280 2 28 5 3
  bash code/run_solve_twinkle_cube.sh 1 27 5 1
  TWINKLE_PYTHON=/path/to/python bash code/run_solve_twinkle_cube.sh 1280 1 27 5 1
  bash code/run_solve_twinkle_cube.sh --solver /path/to/treengeling 1280 1 27 5 1
  TWINKLE_SAT_SOLVER=/path/to/treengeling bash code/run_solve_twinkle_cube.sh 1280 1 27 5 1

Activate the Sage conda environment first if relying on the default python:
  conda activate sage
USAGE
}

variant="pa"
attack_mode="key_recovery"
bounds=""
min_new_coverage=""
low_gain_min_swaps=""
adaptive_diversity=0
max_low_gain_min_swaps=""
run_id_override=""
start_search_id="1"
output_root=""
output_subdir=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--variant)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            variant=$2
            shift 2
            ;;
        --variant=*)
            variant=${1#*=}
            shift
            ;;
        --attack-mode)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            attack_mode=$2
            shift 2
            ;;
        --attack-mode=*)
            attack_mode=${1#*=}
            shift
            ;;
        --solver)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            sat_solver=$2
            shift 2
            ;;
        --solver=*)
            sat_solver=${1#*=}
            shift
            ;;
        --output-root)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            output_root=$2
            shift 2
            ;;
        --output-root=*)
            output_root=${1#*=}
            shift
            ;;
        --output-subdir)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            output_subdir=$2
            shift 2
            ;;
        --output-subdir=*)
            output_subdir=${1#*=}
            shift
            ;;
        --solver)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            sat_solver=$2
            shift 2
            ;;
        --solver=*)
            sat_solver=${1#*=}
            shift
            ;;
        --bounds)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            bounds=$2
            shift 2
            ;;
        --bounds=*)
            bounds=${1#*=}
            shift
            ;;
        --min-new-coverage)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            min_new_coverage=$2
            shift 2
            ;;
        --min-new-coverage=*)
            min_new_coverage=${1#*=}
            shift
            ;;
        --low-gain-min-swaps)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            low_gain_min_swaps=$2
            shift 2
            ;;
        --low-gain-min-swaps=*)
            low_gain_min_swaps=${1#*=}
            shift
            ;;
        --adaptive-diversity)
            adaptive_diversity=1
            shift
            ;;
        --max-low-gain-min-swaps)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            max_low_gain_min_swaps=$2
            shift 2
            ;;
        --max-low-gain-min-swaps=*)
            max_low_gain_min_swaps=${1#*=}
            shift
            ;;
        --run-id)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            run_id_override=$2
            shift 2
            ;;
        --run-id=*)
            run_id_override=${1#*=}
            shift
            ;;
        --start-search-id)
            if [ "$#" -lt 2 ]; then
                echo "Missing value for $1" >&2
                usage >&2
                exit 2
            fi
            start_search_id=$2
            shift 2
            ;;
        --start-search-id=*)
            start_search_id=${1#*=}
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

if [ -z "$sat_solver" ]; then
    echo "SAT solver path is empty" >&2
    usage >&2
    exit 2
fi

case "$variant" in
    pa) target_name="." ;;
    without-io) target_name="without_io" ;;
    *)
        echo "Unknown variant: $variant" >&2
        usage >&2
        exit 2
        ;;
esac

if [ -n "$output_root" ]; then
    target_dir=$output_root
else
    target_dir="${repo_root}/${target_name}"
fi

if [ -n "$output_subdir" ]; then
    cons_dir="${target_dir}/cons/${output_subdir}"
    logs_dir="${target_dir}/logs/${output_subdir}"
    result_dir="${target_dir}/result/${output_subdir}"
else
    cons_dir="${target_dir}/cons"
    logs_dir="${target_dir}/logs"
    result_dir="${target_dir}/result"
fi
mkdir -p "$cons_dir" "$logs_dir" "$result_dir"

if [ "$#" -eq 4 ]; then
    cipher="1280"
    rounds=$1
    iv_start_bound=$2
    sat_threads=$3
    task_id=$4
elif [ "$#" -eq 5 ]; then
    cipher=$1
    rounds=$2
    iv_start_bound=$3
    sat_threads=$4
    task_id=$5
else
    usage >&2
    exit 2
fi

case "$cipher" in
    1280|256|128) ;;
    *)
        echo "Unknown cipher: $cipher" >&2
        usage >&2
        exit 2
        ;;
esac

if [ -n "$bounds" ]; then
    case "$bounds" in
        ''|*[!0-9]*)
            echo "Invalid bounds: $bounds" >&2
            usage >&2
            exit 2
            ;;
    esac
fi
for opt_pair in \
    "min-new-coverage:$min_new_coverage" \
    "low-gain-min-swaps:$low_gain_min_swaps" \
    "max-low-gain-min-swaps:$max_low_gain_min_swaps"
do
    opt_name=${opt_pair%%:*}
    opt_value=${opt_pair#*:}
    if [ -n "$opt_value" ]; then
        case "$opt_value" in
            ''|*[!0-9]*)
                echo "Invalid ${opt_name}: ${opt_value}" >&2
                usage >&2
                exit 2
                ;;
        esac
    fi
done
case "$start_search_id" in
    ''|*[!0-9]*)
        echo "Invalid start-search-id: $start_search_id" >&2
        usage >&2
        exit 2
        ;;
esac
if [ "$start_search_id" -gt 1 ] && [ -z "$run_id_override" ]; then
    echo "--start-search-id > 1 requires --run-id" >&2
    usage >&2
    exit 2
fi

case "$attack_mode" in
    key_recovery|forgery_attack) ;;
    *)
        echo "Unknown attack mode: $attack_mode" >&2
        usage >&2
        exit 2
        ;;
esac
if [ "$attack_mode" = "forgery_attack" ]; then
    if [ "$variant" != "pa" ]; then
        echo "--attack-mode forgery_attack is only supported with --variant pa" >&2
        usage >&2
        exit 2
    fi
    if [ -n "$bounds" ] || [ -n "$min_new_coverage" ] || [ -n "$low_gain_min_swaps" ] || [ "$adaptive_diversity" -eq 1 ] || [ -n "$max_low_gain_min_swaps" ] || [ "$start_search_id" -gt 1 ]; then
        echo "forgery_attack does not support --bounds, resume, or low-gain diversity options" >&2
        usage >&2
        exit 2
    fi
fi

run_task() {
    local cipher=$1
    local rounds=$2
    local iv_start_bound=$3
    local sat_threads=$4
    local index=$5
    local timestamp
    local run_id
    local log
    local start_epoch
    local end_epoch
    local runtime_seconds
    local status
    local bounds_args=()
    local diversity_args=()
    local start_search_args=()
    local attack_mode_args=(--attack-mode "$attack_mode")

    timestamp=$(date +%Y%m%d_%H%M%S)
    if [ -n "$run_id_override" ]; then
        run_id="$run_id_override"
    else
        run_id="${variant}_twinkle${cipher}_${rounds}r_ivstart${iv_start_bound}_sat${sat_threads}_task${index}_${timestamp}"
    fi
    if [ "$start_search_id" -gt 1 ]; then
        log="${logs_dir}/run_${run_id}_resume_no${start_search_id}.log"
    else
        log="${logs_dir}/run_${run_id}.log"
    fi
    start_epoch=$(date +%s)
    status=0
    if [ -n "$bounds" ]; then
        bounds_args=(--bounds "$bounds")
    fi
    if [ -n "$min_new_coverage" ]; then
        diversity_args+=(--min-new-coverage "$min_new_coverage")
    fi
    if [ -n "$low_gain_min_swaps" ]; then
        diversity_args+=(--low-gain-min-swaps "$low_gain_min_swaps")
    fi
    if [ "$adaptive_diversity" -eq 1 ]; then
        diversity_args+=(--adaptive-diversity)
    fi
    if [ -n "$max_low_gain_min_swaps" ]; then
        diversity_args+=(--max-low-gain-min-swaps "$max_low_gain_min_swaps")
    fi
    start_search_args=(--start-search-id "$start_search_id")

    local py="${TWINKLE_PYTHON:-python}"
    {
        echo "Run ID: ${run_id}"
        echo "Output variant: ${variant}"
        echo "Attack mode: ${attack_mode}"
        echo "Cipher: ${cipher}"
        echo "Rounds: ${rounds}"
        echo "IV start bound: ${iv_start_bound}"
        echo "SAT threads: ${sat_threads}"
        echo "Task ID: ${index}"
        echo "Output root: ${target_dir}"
        echo "Output subdir: ${output_subdir:-none}"
        echo "Bounds: ${bounds:-none}"
        echo "Min new coverage: ${min_new_coverage:-default}"
        echo "Low-gain min swaps: ${low_gain_min_swaps:-default}"
        echo "Adaptive diversity: ${adaptive_diversity}"
        echo "Max low-gain min swaps: ${max_low_gain_min_swaps:-default}"
        echo "Start search ID: ${start_search_id}"
        echo "Python: ${py}"
        echo "SAT solver: ${sat_solver}"
        echo "Started at: $(date "+%Y-%m-%d %H:%M:%S")"
        echo "CNF path: ${cons_dir}/cube_${run_id}.cnf"
        echo "Solver log path: ${cons_dir}/cube_${run_id}_no1.solver.log"
        echo "Result path: ${result_dir}/result_${run_id}_no1.log"
        echo ""

        TWINKLE_CIPHER="$cipher" TWINKLE_RUN_ID="$run_id" "${py}" -u "${script_dir}/run_cube_sat_search.py" \
            --variant "$variant" \
            --cipher "$cipher" \
            --run-id "$run_id" \
            --result-dir "$result_dir" \
            "${attack_mode_args[@]}" \
            "${bounds_args[@]}" \
            "${diversity_args[@]}" \
            "${start_search_args[@]}" \
            -r "$rounds" -d "$iv_start_bound" -satTrd "$sat_threads" \
            -f "${cons_dir}" \
            -sat "${sat_solver}"
        status=$?

        end_epoch=$(date +%s)
        runtime_seconds=$((end_epoch - start_epoch))
        echo ""
        echo "Finished at: $(date "+%Y-%m-%d %H:%M:%S")"
        echo "Total runtime seconds: ${runtime_seconds}"
        echo "Wrapper log path: ${log}"
    } > "$log" 2>&1

    if [ "$status" -ne 0 ]; then
        echo "$(date "+%Y-%m-%d %H:%M:%S") Task ${run_id} failed with exit code ${status}" >> "${logs_dir}/error.log"
    fi
    return "$status"
}

run_task "$cipher" "$rounds" "$iv_start_bound" "$sat_threads" "$task_id" &
pid=$!
wait "$pid"
exit $?
