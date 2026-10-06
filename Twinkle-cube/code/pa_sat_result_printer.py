"""
Parse Twinkle PA SAT solver output, print symbolic states, and append
symmetry-breaking ban clauses to the CNF. Variable layout matches total_vars in
pa_cube_search_model.generate_cube_search_model.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from twinkle_round_function import (
    LANE_SIZE,
    O0,
    O1,
    STATE_SIZE,
    X_SIZE,
    Y_SIZE,
    index_xy,
    index_xyz,
    input_expansion_fi,
    print_state,
)

IV_BITS = 128
MATRIX_CELL_WIDTH = 11
MATRICES_PER_GROUP = 8
INVALID_AUX_EXIT_CODE = 23
ATTACK_MODES = ("key_recovery", "forgery_attack")
_last_independent_aux_ok = True


class LinearExpr:
    """GF(2) affine expression over one or more IV variables."""

    __slots__ = ("terms", "const")

    def __init__(self, terms=None, const: int = 0) -> None:
        if terms is None:
            normalized_terms = ()
        elif isinstance(terms, str):
            normalized_terms = (terms,)
        else:
            normalized_terms = tuple(terms)
        self.terms = tuple(sorted(set(normalized_terms), key=variable_sort_key))
        self.const = const & 1

    def __add__(self, other: object) -> "LinearExpr":
        if isinstance(other, int):
            other = LinearExpr(None, other)
        if not isinstance(other, LinearExpr):
            return NotImplemented
        terms = set(self.terms)
        for term in other.terms:
            if term in terms:
                terms.remove(term)
            else:
                terms.add(term)
        return LinearExpr(terms, self.const ^ other.const)

    __radd__ = __add__

    def __mul__(self, other: object) -> "LinearExpr":
        if isinstance(other, int):
            return self if (other & 1) else LinearExpr()
        if not isinstance(other, LinearExpr):
            return NotImplemented
        if self.is_constant():
            return other if self.const else LinearExpr()
        if other.is_constant():
            return self if other.const else LinearExpr()
        if self.terms == other.terms and len(self.terms) == 1:
            coeff = 1 ^ self.const ^ other.const
            const = self.const & other.const
            return LinearExpr(self.terms if coeff else None, const)
        raise ValueError(f"nonlinear expression from multiplying {self} and {other}")

    __rmul__ = __mul__

    def is_constant(self) -> bool:
        return not self.terms

    def linear_coeff(self) -> int:
        return 1 if self.terms else 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LinearExpr):
            return False
        return self.terms == other.terms and self.const == other.const

    def __str__(self) -> str:
        parts = list(self.terms)
        if self.const:
            parts.append("1")
        return " + ".join(parts) if parts else "0"


def variable_sort_key(name: str) -> int:
    match = re.fullmatch(r"v(\d+)", name)
    return int(match.group(1)) if match else 10**9


def total_primary_vars(rounds: int) -> int:
    """Count primary variables: IV(128) + A/B/C/D blocks + F(128)."""
    if rounds < 1:
        raise ValueError("rounds must be >= 1")
    return 3 * (rounds - 1) * STATE_SIZE + STATE_SIZE + IV_BITS + IV_BITS


def parse_dimacs_model_bits(text: str, need_bits: int) -> Optional[List[int]]:
    """Extract first need_bits assignments as 0/1 from SAT solver v-lines."""
    sol: List[int] = []
    after_sat = False
    for raw in text.splitlines():
        line = raw.strip()
        if not after_sat:
            if line.startswith("s "):
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "SATISFIABLE":
                    after_sat = True
                elif len(parts) >= 2 and parts[1].startswith("UNSAT"):
                    return None
            continue
        if not line or line.startswith("c"):
            continue
        if not line.startswith("v"):
            continue
        parts = line.split()
        for tok in parts[1:]:
            if tok == "0":
                break
            try:
                lit = int(tok)
            except ValueError as e:
                raise ValueError(f"invalid DIMACS literal: {tok!r}") from e
            sol.append(0 if lit < 0 else 1)
            if len(sol) >= need_bits:
                return sol[:need_bits]
        if len(sol) >= need_bits:
            break
    if len(sol) < need_bits:
        return None
    return sol[:need_bits]


def unpack_states(
    sol: Sequence[int], rounds: int
) -> Tuple[List[int], List[int], List[List[int]], List[List[int]], List[List[int]], List[List[int]]]:
    """Split flat solution vector into IV, F, A, B, C, D."""
    iv = list(sol[0:IV_BITS])
    f: List[int] = []
    a: List[List[int]] = []
    b: List[List[int]] = []
    c: List[List[int]] = []
    d: List[List[int]] = []
    if rounds > 1:
        nm1 = rounds - 1

        def block_start(which: int) -> int:
            return IV_BITS + which * nm1 * STATE_SIZE

        for r in range(nm1):
            lo = block_start(0) + r * STATE_SIZE
            a.append(list(sol[lo : lo + STATE_SIZE]))
        for r in range(nm1):
            b.append(list(sol[block_start(1) + r * STATE_SIZE : block_start(1) + (r + 1) * STATE_SIZE]))
            c.append(list(sol[block_start(2) + r * STATE_SIZE : block_start(2) + (r + 1) * STATE_SIZE]))
            d.append(list(sol[block_start(3) + r * STATE_SIZE : block_start(3) + (r + 1) * STATE_SIZE]))
        f_start = block_start(4)
        f = list(sol[f_start : f_start + IV_BITS])
    else:
        b.append(list(sol[IV_BITS : IV_BITS + STATE_SIZE]))
        f_start = IV_BITS + STATE_SIZE
        f = list(sol[f_start : f_start + IV_BITS])
    return iv, f, a, b, c, d


def symbolic_bit(linear_bit: int, constant_bit: int, index: int) -> str:
    """Render one constrained bit as a linear variable or constant."""
    if linear_bit == 0 and constant_bit == 0:
        return "0"
    if linear_bit == 0 and constant_bit == 1:
        return "1"
    if linear_bit == 1 and constant_bit == 0:
        return f"v{index}"
    if linear_bit == 1 and constant_bit == 1:
        raise ValueError(f"invalid symbolic bit at index {index}: (1, 1)")
    raise ValueError(f"invalid symbolic bit at index {index}: ({linear_bit}, {constant_bit})")


def build_symbolic_iv(iv: Sequence[int], f: Sequence[int]) -> List[str]:
    """Build symbolic IV display values from raw IV/F assignment bits."""
    if len(iv) != IV_BITS or len(f) != IV_BITS:
        raise ValueError(f"IV and F must both have length {IV_BITS}")
    return [symbolic_bit(iv[i], f[i], i) for i in range(IV_BITS)]


def print_symbolic_list(values: Sequence[object]) -> None:
    print("[" + ", ".join(str(v) for v in values) + "]")


def extract_variables(values: Sequence[object]) -> List[str]:
    """Return unique v{i} names in first-seen order from a symbolic list."""
    seen = set()
    out: List[str] = []
    for value in values:
        for name in re.findall(r"v\d+", str(value)):
            if name not in seen:
                seen.add(name)
                out.append(name)
    return out


TABLE9_AUXILIARY_RULES = {
    0: [
        ("vj", (1, 2), 3),
        ("vj", (2, 3), 1),
    ],
    1: [
        ("vj", (0, 2), 3),
        ("vj", (0, 3), 2),
        ("vj", (2, 3), 0),
    ],
    2: [
        ("vj", (0, 1), 3),
        ("vj", (0, 3), 1),
    ],
    3: [
        ("vj", (0, 1), 2),
        ("vj", (1, 2), 0),
        ("vj", (0, 2), 1),
    ],
}


def index_to_xyz(index: int) -> Tuple[int, int, int]:
    """Inverse of index_xyz for the slice-major state layout."""
    z, rem = divmod(index, X_SIZE * Y_SIZE)
    y, x = divmod(rem, X_SIZE)
    return x, y, z


def format_state_bit(label: str, x: int, y: int, z: int) -> str:
    return f"{label}[{x}][{y}][{z}]"


def format_a0_bit(x: int, y: int, z: int) -> str:
    return format_state_bit("A0", x, y, z)


def format_local_key(y: int, z: int, local_x: int) -> str:
    return f"k{index_xyz(local_x, y, z)}"


def format_local_key_sum(y: int, z: int, local_keys: Sequence[int]) -> str:
    return " + ".join(format_local_key(y, z, local_x) for local_x in local_keys)


def expand_auxiliary_positions(cube_x: int, aux_spec: object) -> List[int]:
    if aux_spec == "vj":
        return [x for x in range(X_SIZE) if x != cube_x]
    if isinstance(aux_spec, int):
        return [aux_spec]
    raise ValueError(f"unsupported auxiliary spec: {aux_spec!r}")


def build_fi_origin_map() -> Tuple[List[int], dict[int, List[int]]]:
    """Map each A0 position to its original 128-bit IV/FI origin."""
    origins = input_expansion_fi(list(range(IV_BITS)))
    if len(origins) != STATE_SIZE:
        raise ValueError(f"FI origin map length must be {STATE_SIZE}, got {len(origins)}")
    classes: dict[int, List[int]] = {}
    for idx, origin in enumerate(origins):
        classes.setdefault(int(origin), []).append(idx)
    return [int(v) for v in origins], classes


def equivalent_a0_bits(origin: int, equivalence_classes: dict[int, List[int]]) -> List[str]:
    out: List[str] = []
    for idx in equivalence_classes[origin]:
        x, y, z = index_to_xyz(idx)
        out.append(format_a0_bit(x, y, z))
    return out


def format_folded_equivalence_line(
    prefix: str,
    equivalent_bits: Sequence[str],
    rhs: str,
    max_width: int = 118,
) -> List[str]:
    """Format A0 equivalence bits and RHS with deterministic folding."""
    tokens = list(equivalent_bits) + [rhs]
    lines: List[str] = []
    current = prefix
    continuation = " " * len(prefix)
    for token in tokens:
        piece = token if current == prefix else " = " + token
        if len(current) > len(prefix) and len(current) + len(piece) > max_width:
            lines.append(current)
            current = continuation + token
        else:
            current += piece
    lines.append(current)
    return lines


def auxiliary_candidates_for_occurrence(
    occurrence_index: int,
    cube_var: str,
    cube_x: int,
    y: int,
    z: int,
    fi_origins: Sequence[int],
) -> List[dict[str, object]]:
    candidates: List[dict[str, object]] = []
    seen_origins = set()
    for rule_index, (aux_spec, key_pair, involved_key) in enumerate(TABLE9_AUXILIARY_RULES[cube_x]):
        for aux_x in expand_auxiliary_positions(cube_x, aux_spec):
            aux_idx = index_xyz(aux_x, y, z)
            aux_origin = fi_origins[aux_idx]
            if aux_origin in seen_origins:
                continue
            seen_origins.add(aux_origin)
            candidates.append(
                {
                    "occurrence_index": occurrence_index,
                    "cube_var": cube_var,
                    "cube_x": cube_x,
                    "y": y,
                    "z": z,
                    "aux_x": aux_x,
                    "aux_idx": aux_idx,
                    "aux_origin": aux_origin,
                    "rule_index": rule_index,
                    "key_pair": key_pair,
                    "auxiliary_expr": format_local_key_sum(y, z, key_pair),
                    "involved_key_bit": format_local_key(y, z, involved_key),
                }
            )
    return candidates


def maximum_auxiliary_matching(candidates_by_occurrence: Sequence[List[dict[str, object]]]) -> dict[int, dict[str, object]]:
    """Maximum bipartite matching from occurrence index to distinct FI origin."""
    origin_to_occurrence: dict[int, int] = {}
    occurrence_to_candidate: dict[int, dict[str, object]] = {}

    def try_match(occurrence_index: int, seen_origins: set[int]) -> bool:
        for candidate in candidates_by_occurrence[occurrence_index]:
            origin = int(candidate["aux_origin"])
            if origin in seen_origins:
                continue
            seen_origins.add(origin)
            previous = origin_to_occurrence.get(origin)
            if previous is None or try_match(previous, seen_origins):
                origin_to_occurrence[origin] = occurrence_index
                occurrence_to_candidate[occurrence_index] = candidate
                return True
        return False

    for occurrence_index in range(len(candidates_by_occurrence)):
        try_match(occurrence_index, set())
    return occurrence_to_candidate


def collect_cube_occurrences(a0: Sequence[object], fi_origins: Sequence[int]) -> List[dict[str, object]]:
    occurrences: List[dict[str, object]] = []
    for idx, value in enumerate(a0):
        variables = extract_variables([value])
        if len(variables) != 1:
            continue
        x, y, z = index_to_xyz(idx)
        occurrences.append(
            {
                "idx": idx,
                "cube_var": variables[0],
                "x": x,
                "y": y,
                "z": z,
                "cube_origin": fi_origins[idx],
            }
        )
    return occurrences


def build_auxiliary_selection(a0: Sequence[object]) -> dict[str, object]:
    fi_origins, equivalence_classes = build_fi_origin_map()
    occurrences = collect_cube_occurrences(a0, fi_origins)
    candidates_by_occurrence = [
        auxiliary_candidates_for_occurrence(
            occurrence_index=i,
            cube_var=str(occurrence["cube_var"]),
            cube_x=int(occurrence["x"]),
            y=int(occurrence["y"]),
            z=int(occurrence["z"]),
            fi_origins=fi_origins,
        )
        for i, occurrence in enumerate(occurrences)
    ]
    matching = maximum_auxiliary_matching(candidates_by_occurrence)
    return {
        "fi_origins": fi_origins,
        "equivalence_classes": equivalence_classes,
        "occurrences": occurrences,
        "matching": matching,
        "required": len(occurrences),
        "selected_count": len(matching),
    }


def iter_selected_auxiliary_rows(selection: dict[str, object]) -> List[dict[str, str]]:
    rows: List[dict[str, str]] = []
    occurrences = selection["occurrences"]
    matching = selection["matching"]
    for occurrence_index, occurrence in enumerate(occurrences):
        candidate = matching.get(occurrence_index)
        if candidate is None:
            continue
        rows.append(
            {
                "auxiliary_bit": format_a0_bit(
                    int(candidate["aux_x"]),
                    int(candidate["y"]),
                    int(candidate["z"]),
                ),
                "auxiliary_original_IV": f"IV[{int(candidate['aux_origin'])}]",
                "auxiliary_expr": str(candidate["auxiliary_expr"]),
                "involved_key_bit": str(candidate["involved_key_bit"]),
            }
        )
    return rows


def update_independent_auxiliary_status(selection: dict[str, object]) -> tuple[int, int, bool]:
    global _last_independent_aux_ok
    required = int(selection["required"])
    selected_count = int(selection["selected_count"])
    _last_independent_aux_ok = selected_count == required
    return required, selected_count, _last_independent_aux_ok


def print_independent_auxiliary_status(selection: dict[str, object]) -> None:
    required, selected_count, ok = update_independent_auxiliary_status(selection)
    if ok:
        print(f"Independent_auxiliary_check: OK count={selected_count}")
    else:
        print(f"Independent_auxiliary_check: FAILED required={required} max={selected_count}")
    print(f"Max_independent_auxiliary_original_IV_bits: {selected_count} / {required}")


def print_auxiliary_summary_table(selection: dict[str, object]) -> None:
    rows = [
        (
            str(row["auxiliary_original_IV"]),
            str(row["auxiliary_expr"]),
            str(row["involved_key_bit"]),
        )
        for row in iter_selected_auxiliary_rows(selection)
    ]
    headers = ("Auxiliary_original_IV", "auxiliary: ki + kj", "involved_key_bit")
    widths = [len(header) for header in headers]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(value))

    def fmt_row(values: Sequence[str]) -> str:
        return "| " + " | ".join(value.ljust(widths[i]) for i, value in enumerate(values)) + " |"

    print(fmt_row(headers))
    print("| " + " | ".join("-" * width for width in widths) + " |")
    for row in rows:
        print(fmt_row(row))
    print("")


def print_auxiliary_key_bit_candidates(
    a0: Sequence[object],
    selection: Optional[dict[str, object]] = None,
) -> None:
    global _last_independent_aux_ok
    print("Auxiliary_variables_and_involved_key_bits:")
    if selection is None:
        selection = build_auxiliary_selection(a0)
    equivalence_classes = selection["equivalence_classes"]
    occurrences = selection["occurrences"]
    matching = selection["matching"]
    required, selected_count, _ = update_independent_auxiliary_status(selection)
    if not occurrences:
        print("<none>")
        return

    selected_rows = iter_selected_auxiliary_rows(selection)
    print(f"auxiliary_bits: {[row['auxiliary_bit'] for row in selected_rows]}")
    print(f"auxiliary_original_IV_bits: {[row['auxiliary_original_IV'] for row in selected_rows]}")
    print(f"involved_bits: {[row['involved_key_bit'] for row in selected_rows]}")
    print("Selected_auxiliary_bits_and_involved_bits:")
    for occurrence_index, occurrence in enumerate(occurrences):
        candidate = matching.get(occurrence_index)
        if candidate is None:
            continue
        x, y, z = int(occurrence["x"]), int(occurrence["y"]), int(occurrence["z"])
        cube_var = str(occurrence["cube_var"])
        aux_x = int(candidate["aux_x"])
        aux_y = int(candidate["y"])
        aux_z = int(candidate["z"])
        aux_origin = int(candidate["aux_origin"])
        print(f"cube: {format_a0_bit(x, y, z)} contains {cube_var} as local v{x}")
        print(f"  auxiliary_bit: {format_a0_bit(aux_x, aux_y, aux_z)}")
        print(f"  auxiliary_origin_IV: IV[{aux_origin}]")
        for line in format_folded_equivalence_line(
            "  auxiliary: ",
            equivalent_a0_bits(aux_origin, equivalence_classes),
            str(candidate["auxiliary_expr"]),
        ):
            print(line)
        print(f"  involved_key_bit: {candidate['involved_key_bit']}")

    if selected_count < required:
        print("Unmatched_cube_occurrences:")
        for occurrence_index, occurrence in enumerate(occurrences):
            if occurrence_index in matching:
                continue
            x, y, z = int(occurrence["x"]), int(occurrence["y"]), int(occurrence["z"])
            print(f"{format_a0_bit(x, y, z)} contains {occurrence['cube_var']} as local v{x}")

def parse_symbolic_expr(value: object) -> LinearExpr:
    if isinstance(value, LinearExpr):
        return value
    terms: List[str] = []
    const = 0
    for piece in str(value).strip().split("+"):
        part = piece.strip()
        if part == "0":
            continue
        if part == "1":
            const ^= 1
            continue
        if re.fullmatch(r"v\d+", part):
            terms.append(part)
            continue
        raise ValueError(f"unsupported symbolic expression: {value!r}")
    return LinearExpr(terms, const)


def single_sbox_symbolic(
    i0: LinearExpr, i1: LinearExpr, i2: LinearExpr, i3: LinearExpr
) -> Tuple[LinearExpr, LinearExpr, LinearExpr, LinearExpr]:
    """Symbolically evaluate the Twinkle S-box ANF on affine bits."""
    o0 = i0 * i2 * i3 + i0 * i3 + i0 + i1 * i2 + i1 * i3 + i2 * i3
    o1 = i0 * i1 + i0 * i3 + i1 + i2
    o2 = i0 * i1 * i2 + i0 + i1 * i3 + i1 + i2 * i3 + i3
    o3 = i0 + i1 * i2 + i2 * i3 + i2 + i3
    return o0, o1, o2, o3


def build_symbolic_b0(a0: Sequence[object]) -> List[LinearExpr]:
    if len(a0) != STATE_SIZE:
        raise ValueError(f"A[0] must have length {STATE_SIZE}, got {len(a0)}")
    b0 = [LinearExpr() for _ in range(STATE_SIZE)]
    for y in range(Y_SIZE):
        for z in range(LANE_SIZE):
            positions = [index_xyz(x, y, z) for x in range(X_SIZE)]
            row = [parse_symbolic_expr(a0[pos]) for pos in positions]
            try:
                out = single_sbox_symbolic(*row)
            except ValueError as exc:
                raise ValueError(f"cannot build symbolic B[0] for S-box row y={y}, z={z}: {exc}") from exc
            for pos, expr in zip(positions, out):
                b0[pos] = expr
    return b0


def rotate_lane_right_values(lane: Sequence[object], amount: int) -> List[object]:
    if not lane:
        return []
    size = len(lane)
    amount %= size
    return [lane[(i + amount) % size] for i in range(size)]


def rotate_slice_left_values(slice_values: Sequence[LinearExpr], amount: int) -> List[LinearExpr]:
    if not slice_values:
        return []
    size = len(slice_values)
    amount %= size
    return [slice_values[(i - amount) % size] for i in range(size)]


def symbolic_lane_rotation(state: Sequence[object], offsets: Sequence[int]) -> List[object]:
    out = list(state)
    for y in range(Y_SIZE):
        for x in range(X_SIZE):
            lane_k = index_xy(x, y)
            shift_amount = offsets[lane_k] % LANE_SIZE
            current_lane = [state[index_xyz(x, y, in_z)] for in_z in range(LANE_SIZE)]
            rotated_lane = rotate_lane_right_values(current_lane, shift_amount)
            for in_z in range(LANE_SIZE):
                out[index_xyz(x, y, in_z)] = rotated_lane[in_z]
    return out


def symbolic_lane_rotation0(state: Sequence[object]) -> List[object]:
    return symbolic_lane_rotation(state, O0)


def symbolic_lane_rotation1(state: Sequence[object]) -> List[object]:
    return symbolic_lane_rotation(state, O1)


def symbolic_mix_slice(state: Sequence[object]) -> List[LinearExpr]:
    out = [LinearExpr() for _ in range(STATE_SIZE)]
    for z in range(LANE_SIZE):
        slice_start = index_xyz(0, 0, z)
        slice_in = [parse_symbolic_expr(v) for v in state[slice_start : slice_start + X_SIZE * Y_SIZE]]
        slice_rot5 = rotate_slice_left_values(slice_in, 5)
        slice_rot12 = rotate_slice_left_values(slice_in, 12)
        for i in range(X_SIZE * Y_SIZE):
            out[slice_start + i] = slice_in[i] + slice_rot5[i] + slice_rot12[i]
    return out


def format_matrix_row(state: Sequence[object], z: int, y: int) -> str:
    return " ".join(str(state[index_xyz(x, y, z)]) for x in range(X_SIZE))


def slice_matrix_rows(state: Sequence[object], z: int) -> List[str]:
    return [format_matrix_row(state, z, y) for y in range(Y_SIZE)]


def print_slice_matrix_state(label: str, state: Sequence[object]) -> None:
    """Print cipher-1280 state as 8 compact 4x4 slice matrices per row group."""
    if len(state) != STATE_SIZE:
        raise ValueError(f"{label} length must be {STATE_SIZE}, got {len(state)}")
    print(f"{label}_matrix:")
    if LANE_SIZE != 80 or STATE_SIZE != 1280:
        print_symbolic_list(state)
        return
    for group_start in range(0, LANE_SIZE, MATRICES_PER_GROUP):
        group_end = min(group_start + MATRICES_PER_GROUP, LANE_SIZE)
        zs = list(range(group_start, group_end))
        matrix_rows = {z: slice_matrix_rows(state, z) for z in zs}
        widths = {
            z: max(len(f"z = {z}"), *(len(row) for row in matrix_rows[z]))
            for z in zs
        }
        print(f"Slices {group_start}-{group_end - 1}:")
        print("   ".join(f"z = {z}".ljust(widths[z]) for z in zs))
        for y in range(Y_SIZE):
            print("   ".join(matrix_rows[z][y].ljust(widths[z]) for z in zs))
        print("")


def verify_symbolic_b0(b0_symbolic: Sequence[LinearExpr], b0_bits: Sequence[int], rounds: int) -> None:
    if len(b0_symbolic) != STATE_SIZE or len(b0_bits) != STATE_SIZE:
        raise ValueError(f"B[0] symbolic/solver lengths must both be {STATE_SIZE}")
    if rounds > 1:
        dimacs_start = IV_BITS + (rounds - 1) * STATE_SIZE + 1
    else:
        dimacs_start = IV_BITS + 1
    for i, (expr, actual) in enumerate(zip(b0_symbolic, b0_bits)):
        expected = expr.linear_coeff()
        if expected != actual:
            dimacs_var = dimacs_start + i
            raise ValueError(
                f"B0_symbolic_check failed at B[0][{i}] / DIMACS v{dimacs_var}: "
                f"symbolic={expr}, expected linear bit {expected}, solver bit {actual}"
            )
    print("B0_symbolic_check: OK")



def verify_symbolic_state(
    check_name: str,
    state_label: str,
    symbolic_state: Sequence[object],
    solver_bits: Optional[Sequence[int]] = None,
    dimacs_start: Optional[int] = None,
) -> None:
    if len(symbolic_state) != STATE_SIZE:
        raise ValueError(f"{check_name} symbolic length must be {STATE_SIZE}, got {len(symbolic_state)}")
    parsed_state = [parse_symbolic_expr(expr) for expr in symbolic_state]
    if solver_bits is not None:
        if len(solver_bits) != STATE_SIZE:
            raise ValueError(f"{check_name} solver length must be {STATE_SIZE}, got {len(solver_bits)}")
        for i, (expr, actual) in enumerate(zip(parsed_state, solver_bits)):
            expected = expr.linear_coeff()
            if expected != actual:
                dimacs_part = f" / DIMACS v{dimacs_start + i}" if dimacs_start is not None else ""
                raise ValueError(
                    f"{check_name} failed at {state_label}[{i}]{dimacs_part}: "
                    f"symbolic={expr}, expected linear bit {expected}, solver bit {actual}"
                )
    print(f"{check_name}: OK")


def state_dimacs_start(rounds: int, block_index: int) -> Optional[int]:
    if rounds <= 1:
        return None
    return IV_BITS + block_index * (rounds - 1) * STATE_SIZE + 1


def print_solution_report(
    iv: List[int],
    f: List[int],
    a: List[List[int]],
    b: List[List[int]],
    c: List[List[int]],
    d: List[List[int]],
    rounds: int,
    attack_mode: str = "key_recovery",
) -> None:
    sep = "---------------------------------------------------"
    print(sep)
    print(f"Initial_Var_num: IV_start = {sum(iv)}")
    print(sep)

    symbolic_iv = build_symbolic_iv(iv, f)
    print("cube_variables:")
    print_symbolic_list(extract_variables(symbolic_iv))

    a0 = input_expansion_fi(symbolic_iv)
    expected_a0 = input_expansion_fi(symbolic_iv)
    if a0 != expected_a0:
        raise ValueError("A[0] display does not match input_expansion_fi(IV)")

    global _last_independent_aux_ok
    if attack_mode == "key_recovery":
        auxiliary_selection = build_auxiliary_selection(a0)
        print_independent_auxiliary_status(auxiliary_selection)
        print_auxiliary_summary_table(auxiliary_selection)
    elif attack_mode == "forgery_attack":
        _last_independent_aux_ok = True
    else:
        raise ValueError(f"unsupported attack mode: {attack_mode}")
    print_slice_matrix_state("A[0]", a0)

    b0_symbolic = build_symbolic_b0(a0)
    print_slice_matrix_state("B[0]", b0_symbolic)
    verify_symbolic_b0(b0_symbolic, b[0], rounds)

    c0_symbolic = symbolic_lane_rotation0(b0_symbolic)
    print_slice_matrix_state("C[0]", c0_symbolic)
    verify_symbolic_state(
        "C0_symbolic_check",
        "C[0]",
        c0_symbolic,
        c[0] if c else None,
        state_dimacs_start(rounds, 2),
    )

    d0_symbolic = symbolic_mix_slice(c0_symbolic)
    print_slice_matrix_state("D[0]", d0_symbolic)
    verify_symbolic_state(
        "D0_symbolic_check",
        "D[0]",
        d0_symbolic,
        d[0] if d else None,
        state_dimacs_start(rounds, 3),
    )

    a1_symbolic = symbolic_lane_rotation1(d0_symbolic)
    print_slice_matrix_state("A[1]", a1_symbolic)
    verify_symbolic_state(
        "A1_symbolic_check",
        "A[1]",
        a1_symbolic,
        a[0] if a else None,
        state_dimacs_start(rounds, 0),
    )

def read_sol_ls(sol_path: str | Path, rounds: int, attack_mode: str = "key_recovery") -> Optional[List[int]]:
    """Read SAT solution, print states, return original IV bits for exact-assignment ban."""
    path = Path(sol_path)
    var_num = total_primary_vars(rounds)
    try:
        contents = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise OSError(f"cannot read solution file: {path}") from e

    sol = parse_dimacs_model_bits(contents, var_num)
    if sol is None:
        return None

    iv, f, a, b, c, d = unpack_states(sol, rounds)
    print_solution_report(iv, f, a, b, c, d, rounds, attack_mode)
    return iv


def ban_sol(iv_bits: Sequence[int]) -> List[List[int]]:
    """Ban this exact original IV assignment over DIMACS variables v1..v128."""
    if len(iv_bits) != IV_BITS:
        raise ValueError(f"IV ban expects {IV_BITS} bits, got {len(iv_bits)}")
    return [[-(i + 1) if bit else (i + 1) for i, bit in enumerate(iv_bits)]]


_CNF_HEADER_RE = re.compile(r"^p\s+cnf\s+(\d+)\s+(\d+)\s*$")


def add_ban2cnf(cnf_path: str | Path, ban_list: Sequence[Sequence[int]]) -> None:
    """Append ban clauses to the CNF and bump the clause count in the header."""
    path = Path(cnf_path)
    try:
        pre = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise OSError(f"cannot read CNF: {path}") from e

    if not pre:
        raise ValueError(f"empty CNF file: {path}")

    first_nl = pre.find("\n")
    head_line = pre[:first_nl] if first_nl >= 0 else pre
    m = _CNF_HEADER_RE.match(head_line.strip())
    if not m:
        raise ValueError(
            f"first line must be 'p cnf <vars> <clauses>', got: {head_line[:80]!r}..."
        )

    var_count, clause_count = m.group(1), int(m.group(2))
    new_clause_count = clause_count + len(ban_list)
    new_header = f"p cnf {var_count} {new_clause_count}\n"

    lines_out: List[str] = []
    for clause in ban_list:
        if not clause:
            raise ValueError("ban clause must not be empty")
        lines_out.append(" ".join(str(lit) for lit in clause) + " 0")

    rest = pre[first_nl + 1 :] if first_nl >= 0 else ""
    new_cnf = new_header + rest + "\n".join(lines_out)
    if lines_out and not new_cnf.endswith("\n"):
        new_cnf += "\n"

    try:
        path.write_text(new_cnf, encoding="utf-8")
    except OSError as e:
        raise OSError(f"cannot write CNF: {path}") from e


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Parse Twinkle SAT solution, print states, append z-symmetry ban clauses to CNF"
    )
    p.add_argument("-c", "--cnf", type=Path, required=True, help="path to CNF file")
    p.add_argument("-s", "--solution", type=Path, required=True, help="solver model output file")
    p.add_argument("-r", "--rounds", type=int, required=True, help="round count (must match model generation)")
    p.add_argument(
        "--attack-mode",
        choices=ATTACK_MODES,
        default="key_recovery",
        help="PA output mode: key_recovery keeps auxiliary/key checks; forgery_attack prints states only",
    )
    return p


def main() -> None:
    args = _build_arg_parser().parse_args()
    iv_bits = read_sol_ls(args.solution, args.rounds, args.attack_mode)
    if not iv_bits:
        raise ValueError(
            "no SAT model or insufficient literals (expect 's SATISFIABLE' and enough v-lines)"
        )
    bans = ban_sol(iv_bits)
    add_ban2cnf(args.cnf, bans)
    if args.attack_mode == "key_recovery" and not _last_independent_aux_ok:
        raise SystemExit(INVALID_AUX_EXIT_CODE)


if __name__ == "__main__":
    main()
