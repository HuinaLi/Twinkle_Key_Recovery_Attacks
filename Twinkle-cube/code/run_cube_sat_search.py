#-------------------------------------------------------------------------------
# Name:     Run all sol_list to check if there are any better colliding trails.
# Purpose:  Easily Run all the files.
# Author:   author
#-------------------------------------------------------------------------------

import argparse
from itertools import combinations
import json
import logging
import os
import subprocess
import sys
import time
import timeit

script_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.normpath(os.path.join(script_dir, ".."))

CIPHER_CHOICES = ("1280", "256", "128")
ATTACK_MODE_CHOICES = ("key_recovery", "forgery_attack")

PRINTER_INVALID_AUX_EXIT_CODE = int(os.environ.get("TWINKLE_INVALID_AUX_EXIT_CODE", "23"))
DEFAULT_MAX_AUX_ATTEMPTS = int(os.environ.get("TWINKLE_MAX_AUX_ATTEMPTS", "100"))
DEFAULT_MAX_SEARCH_ATTEMPTS = int(os.environ.get("TWINKLE_MAX_SEARCH_ATTEMPTS", "1000"))

VARIANT_CONFIG = {
    "pa": {
        "target_dir": ".",
        "model_module": "pa_cube_search_model",
        "print_script": "pa_sat_result_printer.py",
    },
    "without-io": {
        "target_dir": "without_io",
        "model_module": "without_io_cube_search_model",
        "print_script": "without_io_sat_result_printer.py",
    },
}


def configure_cipher(cipher):
    os.environ["TWINKLE_CIPHER"] = str(cipher)
    import twinkle_round_function as twinkle

    return twinkle


def load_variant_config(variant):
    config = VARIANT_CONFIG[variant]
    model = __import__(config["model_module"])
    target_dir = os.path.join(repo_root, config["target_dir"])
    print_result_script = os.path.join(script_dir, config["print_script"])
    return model, target_dir, print_result_script


def build_run_id(variant, cipher, rounds, iv_start_bound, num_threads):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return f"{variant}_twinkle{cipher}_{rounds}r_ivstart{iv_start_bound}_sat{num_threads}_{timestamp}"


def run_satsolver(solver, num_threads, cnf_file, solver_log, timeout_seconds=100000):
    try:
        with open(solver_log, "w") as f:
            subprocess.run(
                [solver, "-t", str(num_threads), cnf_file],
                stdout=f,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=timeout_seconds,
            )
    except subprocess.TimeoutExpired:
        print(f"The solver was terminated after {timeout_seconds} seconds due to timeout.")
        return False
    except subprocess.CalledProcessError as e:
        if e.returncode in (20, 10):
            return True
        print(f"SAT solver failed with exit code {e.returncode}.")
        return False
    return True


def check_satisfiability(solver_log):
    try:
        with open(solver_log, "r") as f:
            content = f.read()
        return "s SATISFIABLE" in content
    except FileNotFoundError:
        print(f"Log file {solver_log} does not exist or cannot be read.")
        return False


def save_output(command, print_file, rejected_file=None):
    res = subprocess.run(command, capture_output=True, text=True)
    if res.returncode == 0:
        with open(print_file, "w") as f:
            f.write(res.stdout)
        print(f"Output has been saved to {print_file}")
        return "accepted"
    if res.returncode == PRINTER_INVALID_AUX_EXIT_CODE and rejected_file:
        with open(rejected_file, "w") as f:
            f.write(res.stdout)
            if res.stderr:
                f.write("\n[stderr]\n")
                f.write(res.stderr)
        print(f"Rejected solution output has been saved to {rejected_file}")
        return "rejected"
    print("No solution or an error occurred while running the script.")
    if res.stderr:
        print(res.stderr)
    return "error"


def normalize_key_expression(expr):
    return " + ".join(part.strip() for part in str(expr).split("+") if part.strip())


def format_python_list(values):
    return "[" + ", ".join(repr(value) for value in values) + "]"


def parse_auxiliary_summary_table(result_file):
    rows = []
    in_table = False
    with open(result_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("| Auxiliary_original_IV |"):
                in_table = True
                continue
            if not in_table:
                continue
            if not stripped.startswith("|"):
                break
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if len(cells) < 3:
                continue
            if all(cell and set(cell) <= {"-"} for cell in cells[:3]):
                continue
            rows.append(
                {
                    "auxiliary_original_IV": cells[0],
                    "auxiliary_expr": normalize_key_expression(cells[1]),
                    "involved_key_bit": cells[2],
                }
            )
    return rows


def ordered_unique(values):
    seen = set()
    out = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def checkpoint_path(result_dir, run_id):
    return os.path.join(result_dir, f"search_state_{run_id}.json")


def atomic_write_json(path, data):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp_path, path)


def make_checkpoint_data(
    run_id,
    bounds,
    next_search_id,
    seen_auxiliary_exprs,
    seen_involved_bits,
    accepted_results,
    diversity_state=None,
):
    data = {
        "run_id": run_id,
        "bounds": bounds,
        "next_search_id": next_search_id,
        "unique_auxiliary_exprs": sorted(seen_auxiliary_exprs),
        "unique_involved_key_bits": sorted(seen_involved_bits),
        "total_unique": len(seen_auxiliary_exprs) + len(seen_involved_bits),
        "accepted_results": list(accepted_results),
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if diversity_state:
        data.update(diversity_state)
    return data


def write_search_checkpoint(
    target_dir,
    run_id,
    bounds,
    next_search_id,
    seen_auxiliary_exprs,
    seen_involved_bits,
    accepted_results,
    diversity_state=None,
):
    path = checkpoint_path(target_dir, run_id)
    data = make_checkpoint_data(
        run_id,
        bounds,
        next_search_id,
        seen_auxiliary_exprs,
        seen_involved_bits,
        accepted_results,
        diversity_state,
    )
    atomic_write_json(path, data)
    return path


def read_search_checkpoint(target_dir, run_id):
    path = checkpoint_path(target_dir, run_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("run_id") != run_id:
        raise ValueError(f"checkpoint run_id mismatch in {path}: {data.get('run_id')} != {run_id}")
    return data


def rebuild_continuous_search_state(result_dir, run_id, start_search_id, bounds):
    seen_auxiliary_exprs = set()
    seen_involved_bits = set()
    accepted_results = []
    for no in range(1, start_search_id):
        result_file = os.path.join(result_dir, f"result_{run_id}_no{no}.log")
        if not os.path.exists(result_file):
            raise FileNotFoundError(
                f"cannot resume at no{start_search_id}: missing previous result {result_file}"
            )
        rows = parse_auxiliary_summary_table(result_file)
        if not rows:
            raise ValueError(
                f"cannot resume at no{start_search_id}: no auxiliary summary rows in {result_file}"
            )
        seen_auxiliary_exprs.update(row["auxiliary_expr"] for row in rows)
        seen_involved_bits.update(row["involved_key_bit"] for row in rows)
        accepted_results.append(os.path.basename(result_file))
    write_search_checkpoint(
        result_dir, run_id, bounds, start_search_id, seen_auxiliary_exprs, seen_involved_bits, accepted_results
    )
    return seen_auxiliary_exprs, seen_involved_bits, accepted_results, "rebuilt"


def restore_continuous_search_state(result_dir, run_id, start_search_id, bounds):
    checkpoint = read_search_checkpoint(result_dir, run_id)
    if checkpoint is None:
        return rebuild_continuous_search_state(result_dir, run_id, start_search_id, bounds)

    checkpoint_next = int(checkpoint.get("next_search_id", 1))
    if start_search_id < checkpoint_next:
        raise ValueError(
            f"cannot resume at no{start_search_id}: checkpoint next_search_id is {checkpoint_next}; "
            "choose a start id >= checkpoint next_search_id"
        )
    if start_search_id > checkpoint_next:
        return rebuild_continuous_search_state(result_dir, run_id, start_search_id, bounds)

    seen_auxiliary_exprs = set(checkpoint.get("unique_auxiliary_exprs", []))
    seen_involved_bits = set(checkpoint.get("unique_involved_key_bits", []))
    accepted_results = list(checkpoint.get("accepted_results", []))
    diversity_state = {
        "current_low_gain_min_swaps": checkpoint.get("current_low_gain_min_swaps"),
        "consecutive_low_gain_results": int(checkpoint.get("consecutive_low_gain_results", 0)),
        "low_gain_results": int(checkpoint.get("low_gain_results", 0)),
    }
    return seen_auxiliary_exprs, seen_involved_bits, accepted_results, "checkpoint", diversity_state


def parse_solver_iv_bits(solver_log, iv_bits=128):
    assignment = {}
    with open(solver_log, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("v"):
                continue
            for token in line.split()[1:]:
                try:
                    lit = int(token)
                except ValueError:
                    continue
                if lit == 0:
                    continue
                var = abs(lit)
                if 1 <= var <= iv_bits:
                    assignment[var] = 1 if lit > 0 else 0
    if len(assignment) < iv_bits:
        missing = [i for i in range(1, iv_bits + 1) if i not in assignment]
        raise ValueError(f"solver log {solver_log} is missing IV assignment for v{missing[0]}")
    return [assignment[i] for i in range(1, iv_bits + 1)]


def build_low_gain_diversity_ban_clauses(iv_bits, min_swaps):
    active_vars = [i + 1 for i, bit in enumerate(iv_bits) if bit]
    if min_swaps <= 0 or not active_vars:
        return []
    min_swaps = min(min_swaps, len(active_vars))
    subset_size = len(active_vars) - min_swaps + 1
    return [[-var for var in subset] for subset in combinations(active_vars, subset_size)]


def append_clauses_to_cnf(cnf_file, clauses):
    if not clauses:
        return 0
    with open(cnf_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    first_nl = content.find("\n")
    if first_nl < 0:
        raise ValueError(f"empty or malformed CNF: {cnf_file}")
    header = content[:first_nl].strip().split()
    if len(header) != 4 or header[0] != "p" or header[1] != "cnf":
        raise ValueError(f"first line must be 'p cnf <vars> <clauses>' in {cnf_file}")
    var_count = header[2]
    clause_count = int(header[3])
    new_header = f"p cnf {var_count} {clause_count + len(clauses)}\n"
    clause_text = "\n".join(" ".join(str(lit) for lit in clause) + " 0" for clause in clauses)
    new_content = new_header + content[first_nl + 1 :]
    if not new_content.endswith("\n"):
        new_content += "\n"
    new_content += clause_text + "\n"
    with open(cnf_file, "w", encoding="utf-8") as f:
        f.write(new_content)
    return len(clauses)


def replace_summary_field(result_file, field_name, value):
    with open(result_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    prefix = f"{field_name}:"
    for idx, line in enumerate(lines):
        if line.startswith(prefix):
            lines[idx] = f"{prefix} {value}\n"
            with open(result_file, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True
    return False


def make_diversity_checkpoint_state(
    min_new_coverage,
    low_gain_min_swaps,
    adaptive_diversity,
    max_low_gain_min_swaps,
    current_low_gain_min_swaps,
    consecutive_low_gain_results,
    low_gain_results,
):
    return {
        "min_new_coverage": min_new_coverage,
        "low_gain_min_swaps": low_gain_min_swaps,
        "adaptive_diversity": bool(adaptive_diversity),
        "max_low_gain_min_swaps": max_low_gain_min_swaps,
        "current_low_gain_min_swaps": current_low_gain_min_swaps,
        "consecutive_low_gain_results": consecutive_low_gain_results,
        "low_gain_results": low_gain_results,
    }


def append_continuous_search_summary(
    result_file,
    bounds,
    seen_auxiliary_exprs,
    seen_involved_bits,
    min_new_coverage=0,
    low_gain_min_swaps=0,
):
    rows = parse_auxiliary_summary_table(result_file)
    current_auxiliary_exprs = ordered_unique(row["auxiliary_expr"] for row in rows)
    current_involved_bits = ordered_unique(row["involved_key_bit"] for row in rows)

    repeated_auxiliary_exprs = [value for value in current_auxiliary_exprs if value in seen_auxiliary_exprs]
    repeated_involved_bits = [value for value in current_involved_bits if value in seen_involved_bits]
    new_auxiliary_exprs = [value for value in current_auxiliary_exprs if value not in seen_auxiliary_exprs]
    new_involved_bits = [value for value in current_involved_bits if value not in seen_involved_bits]

    seen_auxiliary_exprs.update(current_auxiliary_exprs)
    seen_involved_bits.update(current_involved_bits)
    total_unique = len(seen_auxiliary_exprs) + len(seen_involved_bits)
    new_total = len(new_auxiliary_exprs) + len(new_involved_bits)
    low_gain_result = min_new_coverage > 0 and new_total < min_new_coverage

    summary_lines = [
        "Continuous_search_summary:",
        f"Repeated_auxiliary_expr: {format_python_list(repeated_auxiliary_exprs)}",
        f"Repeated_involved_key_bit: {format_python_list(repeated_involved_bits)}",
        f"New_auxiliary_expr_count: {len(new_auxiliary_exprs)}",
        f"New_involved_key_bit_count: {len(new_involved_bits)}",
        f"Current_result_unique_auxiliary_expr_count: {len(current_auxiliary_exprs)}",
        f"Current_result_unique_involved_key_bit_count: {len(current_involved_bits)}",
        f"Accumulated_unique_auxiliary_expr_count: {len(seen_auxiliary_exprs)}",
        f"Accumulated_unique_involved_key_bit_count: {len(seen_involved_bits)}",
        f"Total_unique_auxiliary_and_involved_key_bits: {total_unique} / {bounds}",
        f"Min_new_coverage: {min_new_coverage}",
        f"Low_gain_result: {'YES' if low_gain_result else 'NO'}",
        f"Low_gain_min_swaps: {low_gain_min_swaps if low_gain_result else 0}",
        "Low_gain_diversity_ban_clauses: 0",
        "",
    ]

    with open(result_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    marker = "A[0]_matrix:\n"
    summary_text = "\n".join(summary_lines)
    if marker in content:
        content = content.replace(marker, summary_text + marker, 1)
    else:
        content = content.rstrip() + "\n\n" + summary_text
    with open(result_file, "w", encoding="utf-8") as f:
        f.write(content)

    return {
        "total_unique": total_unique,
        "new_auxiliary_expr_count": len(new_auxiliary_exprs),
        "new_involved_key_bit_count": len(new_involved_bits),
        "new_total": new_total,
        "low_gain_result": low_gain_result,
        "low_gain_min_swaps": low_gain_min_swaps if low_gain_result else 0,
        "low_gain_diversity_ban_clauses": 0,
        "new_auxiliary_exprs": new_auxiliary_exprs,
        "new_involved_bits": new_involved_bits,
        "repeated_auxiliary_exprs": repeated_auxiliary_exprs,
        "repeated_involved_bits": repeated_involved_bits,
    }


def solve(
    rounds,
    iv_start_bound,
    cnf_dir,
    solver,
    num_threads,
    variant,
    cipher,
    run_id,
    bounds=None,
    start_search_id=1,
    min_new_coverage=0,
    low_gain_min_swaps=2,
    adaptive_diversity=False,
    max_low_gain_min_swaps=4,
    attack_mode="key_recovery",
    result_dir_override=None,
):
    if attack_mode not in ATTACK_MODE_CHOICES:
        print(f"unsupported --attack-mode: {attack_mode}")
        return 2
    if attack_mode == "forgery_attack" and variant != "pa":
        print("--attack-mode forgery_attack is only supported for the pa variant")
        return 2
    if attack_mode == "forgery_attack":
        if bounds is not None or start_search_id != 1 or min_new_coverage != 0 or adaptive_diversity:
            print("forgery_attack does not support --bounds, resume, or low-gain diversity options")
            return 2
    if bounds is not None and variant != "pa":
        print("--bounds is only supported for the pa variant")
        return 2
    if start_search_id < 1:
        print("--start-search-id must be >= 1")
        return 2
    if start_search_id > 1 and not run_id:
        print("--start-search-id > 1 requires --run-id")
        return 2
    if min_new_coverage < 0:
        print("--min-new-coverage must be >= 0")
        return 2
    if low_gain_min_swaps < 1:
        print("--low-gain-min-swaps must be >= 1")
        return 2
    if max_low_gain_min_swaps < low_gain_min_swaps:
        print("--max-low-gain-min-swaps must be >= --low-gain-min-swaps")
        return 2

    os.environ["TWINKLE_RUN_ID"] = run_id
    twinkle = configure_cipher(cipher)
    model, target_dir, print_result_script = load_variant_config(variant)
    result_dir = result_dir_override or os.path.join(target_dir, "result")

    twinkle.logger.info("Twinkle Round Function in ANF form")
    twinkle.logger.info(f"Selected Variant: {twinkle.SELECTED_VARIANT}")
    twinkle.logger.info(
        f"State size: {twinkle.STATE_SIZE} bits (X={twinkle.X_SIZE}, Y={twinkle.Y_SIZE}, L={twinkle.LANE_SIZE})"
    )

    os.makedirs(cnf_dir, exist_ok=True)
    os.makedirs(result_dir, exist_ok=True)

    start = timeit.default_timer()
    print(f"#Run ID: {run_id}")
    print(f"#Output Variant: {variant}")
    print(f"#Attack Mode: {attack_mode}")
    print(f"#Cipher: {cipher} ({twinkle.SELECTED_VARIANT})")
    print(f"#Round: {rounds}, #IV_start =: {iv_start_bound}, #thread: {num_threads}, START:")
    if bounds is not None:
        print(f"#Continuous auxiliary/involved bounds: {bounds}")
        print(f"#Min new coverage before diversity ban: {min_new_coverage}")
        print(f"#Low-gain min swaps: {low_gain_min_swaps}")
        print(f"#Adaptive diversity: {'on' if adaptive_diversity else 'off'}")
        print(f"#Max low-gain min swaps: {max_low_gain_min_swaps}")
    if start_search_id > 1:
        print(f"#Resume search from no.{start_search_id}")

    filename = model.generate_filename(cnf_dir, rounds, iv_start_bound)
    cnf_file = filename + ".cnf"
    if start_search_id == 1:
        model.generate_cube_search_model(cnf_dir, rounds, iv_start_bound)
    elif not os.path.exists(cnf_file):
        print(f"Cannot resume: missing CNF path {cnf_file}")
        return 1
    print(f"CNF path: {cnf_file}")

    count = start_search_id
    accepted = False
    bounds_reached = bounds is None
    if bounds is not None and start_search_id == 1:
        seen_auxiliary_exprs = set()
        seen_involved_bits = set()
        accepted_results = []
        current_low_gain_min_swaps = low_gain_min_swaps
        consecutive_low_gain_results = 0
        low_gain_results = 0
        checkpoint = write_search_checkpoint(
            result_dir,
            run_id,
            bounds,
            1,
            seen_auxiliary_exprs,
            seen_involved_bits,
            accepted_results,
            make_diversity_checkpoint_state(
                min_new_coverage,
                low_gain_min_swaps,
                adaptive_diversity,
                max_low_gain_min_swaps,
                current_low_gain_min_swaps,
                consecutive_low_gain_results,
                low_gain_results,
            ),
        )
        print(f"Initialized continuous search checkpoint: {checkpoint}")
    elif start_search_id > 1:
        restored = restore_continuous_search_state(result_dir, run_id, start_search_id, bounds)
        if len(restored) == 5:
            seen_auxiliary_exprs, seen_involved_bits, accepted_results, restore_source, restored_diversity_state = restored
        else:
            seen_auxiliary_exprs, seen_involved_bits, accepted_results, restore_source = restored
            restored_diversity_state = {}
        current_low_gain_min_swaps = restored_diversity_state.get("current_low_gain_min_swaps") or low_gain_min_swaps
        consecutive_low_gain_results = int(restored_diversity_state.get("consecutive_low_gain_results", 0))
        low_gain_results = int(restored_diversity_state.get("low_gain_results", 0))
        print(
            f"Restored continuous search state from {restore_source}: "
            f"aux={len(seen_auxiliary_exprs)}, involved={len(seen_involved_bits)}, "
            f"total={len(seen_auxiliary_exprs) + len(seen_involved_bits)}"
        )
    else:
        seen_auxiliary_exprs = set()
        seen_involved_bits = set()
        accepted_results = []
        current_low_gain_min_swaps = low_gain_min_swaps
        consecutive_low_gain_results = 0
        low_gain_results = 0
    if attack_mode == "forgery_attack":
        max_attempts = 1
    else:
        max_attempts = DEFAULT_MAX_SEARCH_ATTEMPTS if bounds is not None else (DEFAULT_MAX_AUX_ATTEMPTS if variant == "pa" else 1)
    stop_count = start_search_id + max_attempts - 1
    while count <= stop_count:
        print(f"Solve START: no.{count}")
        solver_log = f"{filename}_no{count}.solver.log"
        print_file = os.path.join(result_dir, f"result_{run_id}_no{count}.log")
        rejected_file = os.path.join(result_dir, f"rejected_{run_id}_no{count}.log")
        low_gain_file = os.path.join(result_dir, f"rejected_low_gain_{run_id}_no{count}.log")
        if os.path.exists(solver_log) or os.path.exists(print_file) or os.path.exists(rejected_file) or os.path.exists(low_gain_file):
            print(
                f"Refusing to overwrite existing no{count} artifact: "
                f"solver_log={os.path.exists(solver_log)}, "
                f"result={os.path.exists(print_file)}, rejected={os.path.exists(rejected_file)}, low_gain={os.path.exists(low_gain_file)}"
            )
            return 1
        start1 = timeit.default_timer()
        if run_satsolver(solver, num_threads, cnf_file, solver_log):
            if not check_satisfiability(solver_log):
                print("UNSAT")
                end1 = timeit.default_timer()
                logging.info("cost: %f s" % (end1 - start1))
                print("cost: %f s" % (end1 - start1))
                if bounds is not None:
                    total_unique = len(seen_auxiliary_exprs) + len(seen_involved_bits)
                    print(f"UNSAT before reaching bounds: {total_unique} / {bounds}")
                    return 1
                break
        else:
            print(f"SAT solver command failed for {cnf_file}")
            return 1

        end1 = timeit.default_timer()
        logging.info("solve cost: %f s" % (end1 - start1))
        print("solve cost: %f s" % (end1 - start1))
        print("Find!")
        print(f"Solver log path: {solver_log}")

        command3 = [
            sys.executable,
            print_result_script,
            "-c",
            cnf_file,
            "-s",
            solver_log,
            "-r",
            str(rounds),
            "--attack-mode",
            attack_mode,
        ]
        output_status = save_output(command3, print_file, rejected_file)
        if output_status == "accepted":
            print(f"Result path: {print_file}")
            accepted = True
            if bounds is not None:
                summary = append_continuous_search_summary(
                    print_file,
                    bounds,
                    seen_auxiliary_exprs,
                    seen_involved_bits,
                    min_new_coverage,
                    current_low_gain_min_swaps,
                )
                if summary["low_gain_result"]:
                    # Low-gain solutions are diagnostic only: keep their bans, but do not
                    # count their coverage or expose them as accepted result logs.
                    seen_auxiliary_exprs.difference_update(summary.get("new_auxiliary_exprs", []))
                    seen_involved_bits.difference_update(summary.get("new_involved_bits", []))
                    iv_bits = parse_solver_iv_bits(solver_log)
                    diversity_clauses = build_low_gain_diversity_ban_clauses(
                        iv_bits, summary["low_gain_min_swaps"]
                    )
                    appended_clause_count = append_clauses_to_cnf(cnf_file, diversity_clauses)
                    summary["low_gain_diversity_ban_clauses"] = appended_clause_count
                    replace_summary_field(
                        print_file,
                        "Low_gain_diversity_ban_clauses",
                        str(appended_clause_count),
                    )
                    os.replace(print_file, low_gain_file)
                    print(f"Low-gain rejected result path: {low_gain_file}")
                    low_gain_results += 1
                    consecutive_low_gain_results += 1
                    if adaptive_diversity and consecutive_low_gain_results >= 3:
                        if current_low_gain_min_swaps < max_low_gain_min_swaps:
                            current_low_gain_min_swaps += 1
                            print(
                                "Adaptive diversity increased low-gain min swaps to "
                                f"{current_low_gain_min_swaps}"
                            )
                        consecutive_low_gain_results = 0
                    checkpoint = write_search_checkpoint(
                        result_dir,
                        run_id,
                        bounds,
                        count + 1,
                        seen_auxiliary_exprs,
                        seen_involved_bits,
                        accepted_results,
                        make_diversity_checkpoint_state(
                            min_new_coverage,
                            low_gain_min_swaps,
                            adaptive_diversity,
                            max_low_gain_min_swaps,
                            current_low_gain_min_swaps,
                            consecutive_low_gain_results,
                            low_gain_results,
                        ),
                    )
                    print(f"Updated continuous search checkpoint after low-gain rejection: {checkpoint}")
                    print(
                        "Low-gain diversity ban: "
                        f"min_swaps={summary['low_gain_min_swaps']}, "
                        f"clauses={summary['low_gain_diversity_ban_clauses']}"
                    )
                    count += 1
                    continue
                else:
                    consecutive_low_gain_results = 0
                    current_low_gain_min_swaps = low_gain_min_swaps
                accepted_results.append(os.path.basename(print_file))
                checkpoint = write_search_checkpoint(
                    result_dir,
                    run_id,
                    bounds,
                    count + 1,
                    seen_auxiliary_exprs,
                    seen_involved_bits,
                    accepted_results,
                    make_diversity_checkpoint_state(
                        min_new_coverage,
                        low_gain_min_swaps,
                        adaptive_diversity,
                        max_low_gain_min_swaps,
                        current_low_gain_min_swaps,
                        consecutive_low_gain_results,
                        low_gain_results,
                    ),
                )
                print(f"Updated continuous search checkpoint: {checkpoint}")
                print(
                    "Continuous search unique total: "
                    f"{summary['total_unique']} / {bounds} "
                    f"(+aux {summary['new_auxiliary_expr_count']}, "
                    f"+involved {summary['new_involved_key_bit_count']})"
                )
                if summary["low_gain_result"]:
                    print(
                        "Low-gain diversity ban: "
                        f"min_swaps={summary['low_gain_min_swaps']}, "
                        f"clauses={summary['low_gain_diversity_ban_clauses']}"
                    )
                if summary["repeated_auxiliary_exprs"]:
                    print(
                        "Repeated auxiliary expressions: "
                        f"{format_python_list(summary['repeated_auxiliary_exprs'])}"
                    )
                if summary["repeated_involved_bits"]:
                    print(
                        "Repeated involved key bits: "
                        f"{format_python_list(summary['repeated_involved_bits'])}"
                    )
                if summary["total_unique"] >= bounds:
                    print(f"Reached bounds: {summary['total_unique']} / {bounds}")
                    bounds_reached = True
                    break
                count += 1
                continue
            break
        if output_status == "rejected":
            print(f"Rejected result path: {rejected_file}")
            print("Rejected SAT solution because independent auxiliary check failed; continuing with ban clause.")
            count += 1
            continue
        print("Error saving output")
        return 1

    if bounds is not None and not bounds_reached:
        total_unique = len(seen_auxiliary_exprs) + len(seen_involved_bits)
        print(
            f"Reached TWINKLE_MAX_SEARCH_ATTEMPTS={max_attempts} "
            f"for this run without reaching bounds: {total_unique} / {bounds}"
        )
        return 1
    if not accepted and count > stop_count:
        print(f"Reached TWINKLE_MAX_AUX_ATTEMPTS={max_attempts} without an accepted result")
        return 1

    end = timeit.default_timer()
    print("total cost: %f s" % (end - start))
    print("__________End____________")
    return 0


if __name__ == "__main__":
    parse = argparse.ArgumentParser(description="run solve")
    parse.add_argument(
        "--variant",
        choices=sorted(VARIANT_CONFIG),
        default="pa",
        help="run target: pa (default) or without-io",
    )
    parse.add_argument(
        "--cipher",
        choices=CIPHER_CHOICES,
        default=os.environ.get("TWINKLE_CIPHER", "1280"),
        help="Twinkle cipher size: 1280 (default), 256, or 128",
    )
    parse.add_argument("--run-id", help="stable identifier used in generated filenames")
    parse.add_argument(
        "--attack-mode",
        choices=ATTACK_MODE_CHOICES,
        default="key_recovery",
        help="PA attack workflow: key_recovery (strict auxiliary checks) or forgery_attack (single SAT state output)",
    )
    parse.add_argument(
        "--bounds",
        type=int,
        help="continue PA search until unique auxiliary expressions plus involved key bits reaches this bound",
    )
    parse.add_argument(
        "--start-search-id",
        type=int,
        default=1,
        help="search result number to start from when resuming an existing run",
    )
    parse.add_argument(
        "--min-new-coverage",
        type=int,
        default=0,
        help="mark a PA continuous-search result as low-gain when it adds fewer new aux/involved items",
    )
    parse.add_argument(
        "--low-gain-min-swaps",
        type=int,
        default=2,
        help="minimum number of active IV bits to swap out after a low-gain result",
    )
    parse.add_argument(
        "--adaptive-diversity",
        action="store_true",
        help="increase low-gain min swaps after repeated low-gain results",
    )
    parse.add_argument(
        "--max-low-gain-min-swaps",
        type=int,
        default=4,
        help="maximum low-gain min swaps when adaptive diversity is enabled",
    )
    parse.add_argument("-d", "--dvalue", type=int, required=True, help="number of as of A1")
    parse.add_argument(
        "-r", "--rounds", "--round", type=int, required=True, dest="rounds", help="number of rounds"
    )
    parse.add_argument("-f", "--path", type=str, required=True, help="cnf file path")
    parse.add_argument("-sat", "--solver", type=str, required=True, help="solver path")
    parse.add_argument("--result-dir", type=str, default=None, help="directory for result/rejected/checkpoint logs")
    parse.add_argument(
        "-satTrd",
        "--thread",
        type=int,
        required=True,
        dest="num_threads",
        help="parallel SAT solver thread count",
    )
    args = parse.parse_args()
    run_id = args.run_id or build_run_id(
        args.variant, args.cipher, args.rounds, args.dvalue, args.num_threads
    )
    raise SystemExit(
        solve(
            args.rounds,
            args.dvalue,
            args.path,
            args.solver,
            args.num_threads,
            args.variant,
            args.cipher,
            run_id,
            args.bounds,
            args.start_search_id,
            args.min_new_coverage,
            args.low_gain_min_swaps,
            args.adaptive_diversity,
            args.max_low_gain_min_swaps,
            args.attack_mode,
            args.result_dir,
        )
    )
