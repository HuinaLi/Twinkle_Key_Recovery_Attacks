
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_RESULT_LOG = REPO_ROOT / "forgery_attack/result/forgery_attack_single_ivstart28/result_pa_forgery_attack_twinkle1280_1r_ivstart28_sat5_task2_review_20260429_222903_no1.log"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "forgery_attack/result/practical_forgery_attack_single_ivstart28"
C_SOURCE = SCRIPT_DIR / "practical_forgery_fast.c"
C_BINARY = Path("/tmp/practical_forgery_fast")
LANE_SIZE = 80
STATE_SIZE = 1280
TAG_MAX = 32
ROUND_CONSTANTS = [
    int("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e638d01377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b54709179216d5d98979fb1bd1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96ba7c9045f12c7f9924a19947b3916cf70801f2e2858efc16636920d871574e69a458fea3f4933d7e0d95748f728eb658718bcd5882154aee7b54a41dc25a59b5", 16),
    int("9c30d5392af26013c5d1b023286085f0ca417918b8db38ef8e79dcb0603a180e6c9e0e8bb01e8a3ed71577c1bd314b2778af2fda55605c60e65525f3aa55ab945748986263e8144055ca396a2aab10b6b4cc5c341141e8cea15486af7c72e993b3ee1411636fbc2a2ba9c55d741831f6ce5c3e169b87931eafd6ba336c24cf5c7a325381289586773b8f48986b4bb9afc4bfe81b6628219361d809ccfb21a991", 16),
    int("487cac605dec8032ef845d5de98575b1dc262302eb651b8823893e81d396acc50f6d6ff383f442392e0b4482a484200469c8f04a9e1f9b5e21c66842f6e96c9a670c9c61abd388f06a51a0d2d8542f68960fa728ab5133a36eef0b6c137a3be4ba3bf0507efb2a98a1f1651d39af017666ca593e82430e888cee8619456f9fb47d84a5c33b8b5ebee06f75d885c12073401a449f56c16aa64ed3aa62363f7706", 16),
    int("1bfedf72429b023d37d0d724d00a1248db0fead349f1c09b075372c980991b7b25d479d8f6e8def7e3fe501ab6794c3b976ce0bd04c006bac1a94fb6409f60c45e5c9ec2196a246368fb6faf3e6c53b51339b2eb3b52ec6f6dfc511f9b30952ccc814544af5ebd09bee3d004de334afd660f2807192e4bb3c0cba85745c8740fd20b5f39b9d3fbdb5579c0bd1a60320ad6a100c6402c7279679f25fefb1fa3cc", 16),
]
O0 = [20,24,38,77,49,66,30,40,76,15,46,50,17,18,61,62]
O1 = [63,45,34,39,32,43,60,66,54,26,55,36,61,12,15,35]
SIGMA_A = [1,3,5,7,11,13,17,19,23,29]
SIGMA_B = [0,1,2,3,4,5,6,7,8,9]


def index_xyz(x: int, y: int, z: int) -> int:
    return x + 4 * y + 16 * z


def require_bits(value: str, length: int, name: str) -> str:
    value = "".join(value.split())
    if len(value) != length or any(c not in "01" for c in value):
        raise ValueError(f"{name} must be a {length}-bit 0/1 string")
    return value


def read_key(args: argparse.Namespace) -> str:
    if bool(args.key_bits) == bool(args.key_file):
        raise ValueError("provide exactly one of --key-bits or --key-file")
    if args.key_bits:
        return require_bits(args.key_bits, STATE_SIZE, "key-bits")
    return require_bits(Path(args.key_file).read_text(), STATE_SIZE, "key-file")


def read_key_for_run(args: argparse.Namespace, resume_state: dict | None) -> str:
    if args.key_bits or args.key_file:
        key = read_key(args)
        if resume_state is not None and resume_state.get("key_bits") and key != resume_state["key_bits"]:
            raise ValueError("resume key does not match checkpoint key")
        return key
    if resume_state is not None and resume_state.get("key_bits"):
        return require_bits(resume_state["key_bits"], STATE_SIZE, "checkpoint key_bits")
    raise ValueError("provide exactly one of --key-bits or --key-file")


def parse_cube_variables(text: str) -> list[int]:
    m = re.search(r"cube_variables:\s*\n\[([^\]]*)\]", text)
    if not m:
        raise ValueError("cannot find cube_variables list in result log")
    out = [int(x) for x in re.findall(r"v(\d+)", m.group(1))]
    if len(out) != len(set(out)):
        raise ValueError("duplicate cube variables in result log")
    if not out:
        raise ValueError("cube_variables list is empty")
    return out


def parse_a0_first_128(text: str) -> list[str]:
    marker = "A[0]_matrix:"
    start = text.find(marker)
    if start < 0:
        raise ValueError("cannot find A[0]_matrix in result log")
    b_start = text.find("B[0]_matrix:", start)
    section = text[start:b_start if b_start >= 0 else len(text)]
    m = re.search(r"Slices 0-7:\s*\n[^\n]*\n((?:[^\n]*\n){4})", section)
    if not m:
        raise ValueError("cannot parse A[0] Slices 0-7 block")
    state = [None] * 128
    for y, row in enumerate(m.group(1).splitlines()):
        toks = row.split()
        if len(toks) != 32:
            raise ValueError(f"A[0] row {y} in Slices 0-7 should have 32 tokens, got {len(toks)}")
        for z in range(8):
            for x in range(4):
                state[index_xyz(x, y, z)] = toks[4 * z + x]
    if any(v is None for v in state):
        raise ValueError("incomplete A[0] raw pointer template")
    return [str(v) for v in state]


def load_template(result_log: Path) -> tuple[list[int], list[str]]:
    text = result_log.read_text(errors="replace")
    cube = parse_cube_variables(text)
    raw = parse_a0_first_128(text)
    for i, tok in enumerate(raw):
        if tok in ("0", "1"):
            continue
        if tok != f"v{i}":
            raise ValueError(f"unexpected raw pointer symbolic bit at index {i}: {tok}")
    if sorted(cube) != sorted(i for i, tok in enumerate(raw) if tok.startswith("v")):
        raise ValueError("cube_variables list does not match free bits in raw pointer template")
    return cube, raw


def validate_pointer(pointer: str, template: list[str]) -> None:
    bad = []
    for i, (bit, tok) in enumerate(zip(pointer, template)):
        if tok in ("0", "1") and bit != tok:
            bad.append((i, tok, bit))
    if bad:
        preview = ", ".join(f"P[{i}] expected {exp} got {got}" for i, exp, got in bad[:12])
        raise ValueError(f"target pointer does not match fixed cube constants: {preview}")


def target_assignment(pointer: str, cube: list[int]) -> int:
    value = 0
    for j, idx in enumerate(cube):
        if pointer[idx] == "1":
            value |= 1 << j
    return value


def pointer_for_assignment(template: list[str], cube: list[int], assignment: int) -> str:
    bits = ["0" if tok.startswith("v") else tok for tok in template]
    for j, idx in enumerate(cube):
        bits[idx] = "1" if ((assignment >> j) & 1) else "0"
    return "".join(bits)


def pointer_matrix_rows(pointer: str) -> list[list[list[str]]]:
    rows: list[list[list[str]]] = []
    for y in range(4):
        row_groups: list[list[str]] = []
        for z in range(8):
            row_groups.append([pointer[index_xyz(x, y, z)] for x in range(4)])
        rows.append(row_groups)
    return rows


def pointer_matrix_lines(pointer: str) -> list[str]:
    lines = [
        "forged_pointer:",
        "Slices 0-7:",
        " ".join(f"z = {z}".ljust(12) for z in range(8)).rstrip(),
    ]
    for row_groups in pointer_matrix_rows(pointer):
        lines.append(" ".join(" ".join(group).ljust(12) for group in row_groups).rstrip())
    return lines


def fi_expand(pointer: str) -> list[int]:
    p = [1 if c == "1" else 0 for c in pointer]
    s: list[int] = []
    for a, b in zip(SIGMA_A, SIGMA_B):
        out = [0] * 128
        for j, bit in enumerate(p):
            out[(a * j + b) % 128] = bit
        s.extend(out)
    return s


def sbox_step(s: list[int]) -> list[int]:
    out = [0] * STATE_SIZE
    for y in range(4):
        for z in range(LANE_SIZE):
            ps = [index_xyz(x, y, z) for x in range(4)]
            i0, i1, i2, i3 = [s[p] for p in ps]
            vals = [
                (i0&i2&i3) ^ (i0&i3) ^ i0 ^ (i1&i2) ^ (i1&i3) ^ (i2&i3),
                (i0&i1) ^ (i0&i3) ^ i1 ^ i2,
                (i0&i1&i2) ^ i0 ^ (i1&i3) ^ i1 ^ (i2&i3) ^ i3,
                i0 ^ (i1&i2) ^ (i2&i3) ^ i2 ^ i3,
            ]
            for p, v in zip(ps, vals):
                out[p] = v
    return out


def lane_rotation(s: list[int], offsets: list[int]) -> list[int]:
    out = s[:]
    for y in range(4):
        for x in range(4):
            shift = offsets[x + 4*y] % LANE_SIZE
            for z in range(LANE_SIZE):
                out[index_xyz(x,y,z)] = s[index_xyz(x,y,(z + shift) % LANE_SIZE)]
    return out


def mix_slice(s: list[int]) -> list[int]:
    out = [0] * STATE_SIZE
    for z in range(LANE_SIZE):
        base = 16 * z
        for i in range(16):
            out[base+i] = s[base+i] ^ s[base+((i-5) % 16)] ^ s[base+((i-12) % 16)]
    return out


def add_constant(s: list[int], r: int) -> list[int]:
    c = ROUND_CONSTANTS[r]
    return [bit ^ ((c >> i) & 1) for i, bit in enumerate(s)]


def oracle_tag_python(pointer: str, key_bits: str, tag_len: int, rounds: int) -> str:
    key = [1 if c == "1" else 0 for c in key_bits]
    s = [a ^ b for a, b in zip(fi_expand(pointer), key)]
    for r in range(rounds):
        s = add_constant(lane_rotation(mix_slice(lane_rotation(sbox_step(s), O0)), O1), r)
    tag = [s[i] ^ s[(i + 128) % STATE_SIZE] for i in range(tag_len)]
    return "".join("1" if b else "0" for b in tag)


def xor_tags(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def ensure_c_backend() -> Path:
    if C_BINARY.exists() and C_BINARY.stat().st_mtime >= C_SOURCE.stat().st_mtime:
        return C_BINARY
    subprocess.run(["gcc", "-O3", "-std=c11", "-Wall", "-Wextra", "-o", str(C_BINARY), str(C_SOURCE)], check=True)
    return C_BINARY


def run_c_chunk(key: str, base: str, cube: list[int], target: int, tag_len: int, rounds: int, start: int, count: int) -> tuple[int, int, str]:
    exe = ensure_c_backend()
    proc = subprocess.run([
        str(exe), "--key-bits", key, "--base-pointer", base, "--cube-indices", ",".join(map(str, cube)),
        "--target-assignment", str(target), "--tag-length", str(tag_len), "--rounds", str(rounds), "--start", str(start), "--count", str(count)
    ], check=True, text=True, capture_output=True)
    data = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v
    return int(data["processed"]), int(data["skipped_target"]), data["xor_tag_bits"]


def enumerate_python(key: str, template: list[str], cube: list[int], target: int, tag_len: int, rounds: int, start: int, count: int) -> tuple[int, int, str]:
    total = 1 << len(cube)
    end = min(total, start + count)
    acc = "0" * tag_len
    processed = skipped = 0
    for a in range(start, end):
        if a == target:
            skipped += 1
            continue
        acc = xor_tags(acc, oracle_tag_python(pointer_for_assignment(template, cube, a), key, tag_len, rounds))
        processed += 1
    return processed, skipped, acc


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content)
    os.replace(tmp, path)


def atomic_write_json(path: Path, data: dict) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def append_log(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write("\n".join(lines) + "\n")


def write_new_run_files(out_dir: Path, stamp: str, lines: list[str], summary: dict, checkpoint: dict) -> tuple[Path, Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / f"practical_forgery_attack_{stamp}.log"
    json_path = out_dir / f"practical_forgery_attack_{stamp}.json"
    checkpoint_path = out_dir / f"practical_forgery_attack_{stamp}.checkpoint.json"
    paths = {"log_path": str(log_path), "json_path": str(json_path), "checkpoint_path": str(checkpoint_path)}
    summary.update(paths)
    checkpoint.update(paths)
    atomic_write_text(log_path, "\n".join(lines) + "\n")
    atomic_write_json(json_path, summary)
    atomic_write_json(checkpoint_path, checkpoint)
    return log_path, json_path, checkpoint_path


def update_state_files(json_path: Path, checkpoint_path: Path, summary: dict, checkpoint: dict) -> None:
    atomic_write_json(json_path, summary)
    atomic_write_json(checkpoint_path, checkpoint)


def make_checkpoint(summary: dict, key_bits: str, xor_accumulator: str, next_assignment: int, processed: int, skipped: int, partial: bool) -> dict:
    return {
        "version": 1,
        "timestamp": summary["timestamp"],
        "log_path": summary.get("log_path"),
        "json_path": summary.get("json_path"),
        "checkpoint_path": summary.get("checkpoint_path"),
        "result_log": summary["result_log"],
        "rounds": summary["rounds"],
        "tag_length": summary["tag_length"],
        "cube_variables": summary["cube_variables"],
        "fixed_count": summary["fixed_count"],
        "cube_count": summary["cube_count"],
        "target_assignment": summary["target_assignment"],
        "target_tag": summary["target_tag"],
        "key_bits": key_bits,
        "backend": summary.get("backend"),
        "forged_pointer_bits": summary["forged_pointer_bits"],
        "base_pointer_bits": summary["base_pointer_bits"],
        "xor_accumulator": xor_accumulator,
        "next_assignment": next_assignment,
        "processed_queries": processed,
        "skipped_target_queries": skipped,
        "total_assignments": summary["total_assignments"],
        "expected_full_query_count": summary["expected_full_query_count"],
        "partial": partial,
    }


def load_resume_checkpoint(path: Path) -> dict:
    data = json.loads(path.read_text())
    required = [
        "result_log", "rounds", "tag_length", "target_assignment", "key_bits",
        "xor_accumulator", "next_assignment", "processed_queries", "skipped_target_queries",
        "log_path", "json_path", "checkpoint_path", "target_tag", "base_pointer_bits",
        "forged_pointer_bits",
    ]
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"checkpoint is missing required fields: {missing}")
    return data


def check_resume_value(name: str, got, expected) -> None:
    if got != expected:
        raise ValueError(f"resume {name} mismatch: got {got!r}, expected {expected!r}")


def assignment_limit_from_max_queries(max_queries: int | None, total_assignments: int, target: int) -> int:
    if max_queries is None:
        return total_assignments
    return min(total_assignments, max_queries + (1 if target < max_queries else 0))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Practical Twinkle forgery attack simulator")
    ap.add_argument("--result-log", type=Path, default=DEFAULT_RESULT_LOG)
    ap.add_argument("--pointer-bits", help="128-bit target pointer; if omitted, it is built from --target-assignment")
    ap.add_argument("--target-assignment", type=int, default=0, help="cube assignment used to construct P when --pointer-bits is omitted")
    ap.add_argument("--tag-length", type=int)
    ap.add_argument("--rounds", type=int, default=4, choices=(3, 4), help="actual oracle rounds; use 3 for the ivstart9 demonstration")
    ap.add_argument("--key-bits")
    ap.add_argument("--key-file")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--max-queries", type=int)
    ap.add_argument("--checkpoint-interval", type=int, default=1 << 20)
    ap.add_argument("--resume", type=Path)
    ap.add_argument("--backend", choices=("auto", "c", "python"), default="auto")
    ap.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = ap.parse_args(argv)

    resume_state = load_resume_checkpoint(args.resume) if args.resume else None
    if resume_state is not None:
        result_log = Path(resume_state["result_log"])
        rounds = int(resume_state["rounds"])
        tag_length = int(resume_state["tag_length"])
        target = int(resume_state["target_assignment"])
        if args.tag_length is not None:
            check_resume_value("tag_length", args.tag_length, tag_length)
        if args.rounds != 4 and args.rounds != rounds:
            check_resume_value("rounds", args.rounds, rounds)
        if args.target_assignment != 0 and args.target_assignment != target:
            check_resume_value("target_assignment", args.target_assignment, target)
        backend = args.backend
        if backend == "auto":
            backend = resume_state.get("backend") or "c"
        elif resume_state.get("backend") and backend != resume_state["backend"]:
            check_resume_value("backend", backend, resume_state["backend"])
    else:
        if args.tag_length is None:
            raise ValueError("--tag-length is required unless --resume is used")
        result_log = args.result_log
        rounds = args.rounds
        tag_length = args.tag_length
        target = args.target_assignment
        backend = "c" if args.backend == "auto" else args.backend

    key = read_key_for_run(args, resume_state)
    cube, template = load_template(result_log)
    if not (len(cube) < tag_length <= TAG_MAX):
        raise ValueError(f"--tag-length must satisfy cube_dimension < t <= {TAG_MAX}; cube_dimension={len(cube)}")
    total_assignments = 1 << len(cube)
    if target < 0 or target >= total_assignments:
        raise ValueError(f"--target-assignment must be in [0, {total_assignments - 1}]")

    if args.pointer_bits:
        pointer = require_bits(args.pointer_bits, 128, "pointer-bits")
        validate_pointer(pointer, template)
        actual_target = target_assignment(pointer, cube)
        if actual_target != target:
            raise ValueError(f"--pointer-bits cube assignment is {actual_target}, but target assignment is {target}")
    elif resume_state is not None:
        pointer = require_bits(resume_state["forged_pointer_bits"], 128, "checkpoint forged_pointer_bits")
        validate_pointer(pointer, template)
        check_resume_value("pointer assignment", target_assignment(pointer, cube), target)
    else:
        pointer = pointer_for_assignment(template, cube, target)

    total_queries = total_assignments - 1
    target_tag = oracle_tag_python(pointer, key, tag_length, rounds)
    base_pointer = pointer_for_assignment(template, cube, 0)
    if resume_state is not None:
        check_resume_value("target_tag", target_tag, resume_state["target_tag"])
        check_resume_value("cube_variables", [f"v{i}" for i in cube], resume_state["cube_variables"])
        check_resume_value("base_pointer_bits", base_pointer, resume_state["base_pointer_bits"])

    assignment_limit = assignment_limit_from_max_queries(args.max_queries, total_assignments, target)
    fixed_count = 128 - len(cube)
    cube_count = len(cube)
    pointer_matrix = pointer_matrix_rows(pointer)
    stamp = resume_state["timestamp"] if resume_state is not None else time.strftime("%Y%m%d_%H%M%S")

    summary = {
        "timestamp": stamp,
        "result_log": str(result_log), "rounds": rounds, "tag_length": tag_length,
        "pointer_length": 128, "cube_variables": [f"v{i}" for i in cube],
        "fixed_count": fixed_count, "cube_count": cube_count, "fixed_pointer_bits": fixed_count,
        "forged_pointer_bits": pointer, "forged_pointer_matrix": pointer_matrix, "forged_pointer": pointer,
        "base_pointer_bits": base_pointer, "target_assignment": target, "target_tag": target_tag,
        "total_assignments": total_assignments, "expected_full_query_count": total_queries,
        "execute": bool(args.execute or resume_state), "backend": backend,
    }

    if resume_state is None:
        header_lines = [
            "Practical Twinkle Forgery Attack",
            f"result_log: {result_log}",
            f"rounds: {rounds}",
            f"tag_length: {tag_length}",
            "pointer_length: 128",
            f"cube_variables: {[f'v{i}' for i in cube]}",
            f"fixed_count: {fixed_count}",
            f"cube_count: {cube_count}",
            f"target_assignment: {target}",
            f"forged_pointer_bits: {pointer}",
            *pointer_matrix_lines(pointer),
            f"expected_full_query_count: {total_queries}",
            f"target_tag: {target_tag}",
        ]
    else:
        header_lines = []

    if not args.execute and resume_state is None:
        samples = []
        for a in range(min(4, total_assignments)):
            if a != target:
                samples.append({"assignment": a, "pointer": pointer_for_assignment(template, cube, a)})
        lines = header_lines + ["mode: dry-run", f"sample_queries: {samples}"]
        summary.update({"partial": True, "sample_queries": samples})
        ckpt = make_checkpoint(summary, key, "0" * tag_length, 0, 0, 0, True)
        write_new_run_files(args.output_dir, stamp, lines, summary, ckpt)
        print("\n".join(lines))
        return 0

    if resume_state is None:
        processed_total = skipped_total = 0
        acc = "0" * tag_length
        assignment = 0
        summary.update({"processed_queries": processed_total, "skipped_target_queries": skipped_total, "forged_tag": acc, "partial": True, "next_assignment": assignment})
        ckpt = make_checkpoint(summary, key, acc, assignment, processed_total, skipped_total, True)
        log_path, json_path, checkpoint_path = write_new_run_files(args.output_dir, stamp, header_lines + ["mode: execute", f"backend: {backend}"], summary, ckpt)
    else:
        log_path = Path(resume_state["log_path"])
        json_path = Path(resume_state["json_path"])
        checkpoint_path = Path(resume_state["checkpoint_path"])
        processed_total = int(resume_state["processed_queries"])
        skipped_total = int(resume_state["skipped_target_queries"])
        acc = require_bits(resume_state["xor_accumulator"], tag_length, "checkpoint xor_accumulator")
        assignment = int(resume_state["next_assignment"])
        summary.update({
            "log_path": str(log_path), "json_path": str(json_path), "checkpoint_path": str(checkpoint_path),
            "processed_queries": processed_total, "skipped_target_queries": skipped_total,
            "forged_tag": acc, "partial": True, "next_assignment": assignment,
        })
        append_log(log_path, [
            "",
            "Resume practical forgery attack",
            f"resume_from_checkpoint: {args.resume}",
            f"resume_next_assignment: {assignment}",
            f"backend: {backend}",
            f"assignment_limit: {assignment_limit}",
        ])

    if assignment > assignment_limit:
        raise ValueError(f"checkpoint next_assignment {assignment} is beyond assignment limit {assignment_limit}")

    remaining = assignment_limit - assignment
    while remaining > 0:
        count = min(args.checkpoint_interval, remaining)
        if backend == "c":
            processed, skipped, chunk_tag = run_c_chunk(key, base_pointer, cube, target, tag_length, rounds, assignment, count)
        else:
            processed, skipped, chunk_tag = enumerate_python(key, template, cube, target, tag_length, rounds, assignment, count)
        acc = xor_tags(acc, chunk_tag)
        processed_total += processed
        skipped_total += skipped
        assignment += count
        remaining -= count
        current_partial = assignment < total_assignments
        summary.update({
            "processed_queries": processed_total, "skipped_target_queries": skipped_total,
            "forged_tag": acc, "partial": current_partial, "next_assignment": assignment,
            "backend": backend,
        })
        ckpt = make_checkpoint(summary, key, acc, assignment, processed_total, skipped_total, current_partial)
        update_state_files(json_path, checkpoint_path, summary, ckpt)
        append_log(log_path, [
            "progress:",
            f"  next_assignment: {assignment}",
            f"  processed_queries: {processed_total}",
            f"  skipped_target_queries: {skipped_total}",
            f"  xor_accumulator: {acc}",
            f"  partial: {str(current_partial).lower()}",
            f"checkpoint_updated: {checkpoint_path}",
        ])

    final_partial = assignment < total_assignments
    final_lines = [
        f"processed_queries: {processed_total}",
        f"skipped_target_queries: {skipped_total}",
        f"partial: {str(final_partial).lower()}",
        f"forged_tag: {acc}",
    ]
    if final_partial:
        final_lines.append("verification: PARTIAL_NOT_CHECKED")
    else:
        verification_xor = xor_tags(target_tag, acc)
        verification = "OK" if set(verification_xor) <= {"0"} else "FAILED"
        final_lines += [f"verification_xor: {verification_xor}", f"verification: {verification}"]
        if verification == "OK":
            final_lines.append("Forgery attack succeeded.")
        final_lines.append(f"forged_pair: ({pointer}, {acc})")
        summary.update({"verification_xor": verification_xor, "verification": verification, "forged_pair": [pointer, acc]})
        if verification == "OK":
            summary["success_message"] = "Forgery attack succeeded."
    summary.update({
        "processed_queries": processed_total, "skipped_target_queries": skipped_total,
        "forged_tag": acc, "partial": final_partial, "next_assignment": assignment,
    })
    ckpt = make_checkpoint(summary, key, acc, assignment, processed_total, skipped_total, final_partial)
    update_state_files(json_path, checkpoint_path, summary, ckpt)
    append_log(log_path, final_lines)
    print("\n".join(header_lines + (["mode: execute", f"backend: {backend}"] if resume_state is None else []) + final_lines))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
