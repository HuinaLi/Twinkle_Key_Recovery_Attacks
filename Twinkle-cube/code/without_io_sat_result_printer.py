"""
Parse Twinkle without-IO SAT solver output, print symbolic ANF states, and
append symmetry-breaking ban clauses to the CNF. Variable layout matches
without_io_cube_search_model.generate_cube_search_model.
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
    print_state,
)

MATRICES_PER_GROUP = 8


class LinearExpr:
    """GF(2) affine expression over one or more A[0] variables."""

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
    if rounds < 1:
        raise ValueError("rounds must be >= 1")
    return 4 * (rounds - 1) * STATE_SIZE + STATE_SIZE


def parse_dimacs_model_bits(text: str, need_bits: int) -> Optional[List[int]]:
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
        for tok in line.split()[1:]:
            if tok == "0":
                break
            try:
                lit = int(tok)
            except ValueError as e:
                raise ValueError(f"invalid DIMACS literal: {tok!r}") from e
            sol.append(0 if lit < 0 else 1)
            if len(sol) >= need_bits:
                return sol[:need_bits]
    if len(sol) < need_bits:
        return None
    return sol[:need_bits]


def unpack_states(sol: Sequence[int], rounds: int) -> Tuple[List[List[int]], List[List[int]], List[List[int]], List[List[int]]]:
    a: List[List[int]] = []
    b: List[List[int]] = []
    c: List[List[int]] = []
    d: List[List[int]] = []
    for r in range(rounds):
        a.append(list(sol[r * STATE_SIZE : (r + 1) * STATE_SIZE]))
    for r in range(rounds - 1):
        b_start = rounds * STATE_SIZE + r * STATE_SIZE
        c_start = (rounds + rounds - 1) * STATE_SIZE + r * STATE_SIZE
        d_start = (rounds + 2 * (rounds - 1)) * STATE_SIZE + r * STATE_SIZE
        b.append(list(sol[b_start : b_start + STATE_SIZE]))
        c.append(list(sol[c_start : c_start + STATE_SIZE]))
        d.append(list(sol[d_start : d_start + STATE_SIZE]))
    return a, b, c, d


def build_symbolic_a0(a0_bits: Sequence[int]) -> List[str]:
    if len(a0_bits) != STATE_SIZE:
        raise ValueError(f"A[0] must have length {STATE_SIZE}, got {len(a0_bits)}")
    return [f"v{i}" if bit else "0" for i, bit in enumerate(a0_bits)]


def build_symbolic_state_from_mask(bits: Sequence[int], label: str) -> List[str]:
    if len(bits) != STATE_SIZE:
        raise ValueError(f"{label} must have length {STATE_SIZE}, got {len(bits)}")
    return [f"v{i}" if bit else "0" for i, bit in enumerate(bits)]


def print_symbolic_list(values: Sequence[object]) -> None:
    print("[" + ", ".join(str(v) for v in values) + "]")


def extract_variables(values: Sequence[object]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        for name in re.findall(r"v\d+", str(value)):
            if name not in seen:
                seen.add(name)
                out.append(name)
    return out


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


def verify_symbolic_state(label: str, symbolic: Sequence[LinearExpr], solver_bits: Sequence[int]) -> None:
    if len(symbolic) != STATE_SIZE or len(solver_bits) != STATE_SIZE:
        raise ValueError(f"{label} symbolic/solver lengths must both be {STATE_SIZE}")
    for i, (expr, actual) in enumerate(zip(symbolic, solver_bits)):
        expected = parse_symbolic_expr(expr).linear_coeff()
        if expected != actual:
            raise ValueError(
                f"{label}_symbolic_check failed at {label}[{i}]: "
                f"symbolic={expr}, expected mask bit {expected}, solver bit {actual}"
            )
    print(f"{label}_symbolic_check: OK")


def print_solution_report(
    a: List[List[int]],
    b: List[List[int]],
    c: List[List[int]],
    d: List[List[int]],
    rounds: int,
) -> None:
    if rounds < 2 or len(a) != rounds or len(b) != rounds - 1 or len(c) != rounds - 1 or len(d) != rounds - 1:
        raise ValueError("without-IO symbolic printer expects A[0..r-1] and B/C/D[0..r-2]")

    sep = "---------------------------------------------------"
    print(sep)
    print(f"Initial_Var_num: IV_start = {sum(a[0])}")
    print(sep)

    a0_symbolic = build_symbolic_a0(a[0])
    print("cube_variables:")
    print_symbolic_list(extract_variables(a0_symbolic))
    print_slice_matrix_state("A[0]", a0_symbolic)

    for r in range(rounds - 1):
        b_symbolic = build_symbolic_state_from_mask(b[r], f"B[{r}]")
        c_symbolic = symbolic_lane_rotation0(b_symbolic)
        d_symbolic = symbolic_mix_slice(c_symbolic)
        a_next_symbolic = symbolic_lane_rotation1(d_symbolic)

        print_slice_matrix_state(f"B[{r}]", b_symbolic)
        verify_symbolic_state(f"B{r}", b_symbolic, b[r])

        print_slice_matrix_state(f"C[{r}]", c_symbolic)
        verify_symbolic_state(f"C{r}", c_symbolic, c[r])

        print_slice_matrix_state(f"D[{r}]", d_symbolic)
        verify_symbolic_state(f"D{r}", d_symbolic, d[r])

        print_slice_matrix_state(f"A[{r + 1}]", a_next_symbolic)
        verify_symbolic_state(f"A{r + 1}", a_next_symbolic, a[r + 1])


def read_sol_ls(sol_path: str | Path, rounds: int) -> Optional[List[List[int]]]:
    path = Path(sol_path)
    var_num = total_primary_vars(rounds)
    try:
        contents = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise OSError(f"cannot read solution file: {path}") from e

    sol = parse_dimacs_model_bits(contents, var_num)
    if sol is None:
        return None

    a, b, c, d = unpack_states(sol, rounds)
    print_solution_report(a, b, c, d, rounds)
    return a


def shiftZ(X: list, r0: int) -> list:
    Y = []
    for y in range(Y_SIZE):
        for x in range(X_SIZE):
            for z in range(LANE_SIZE):
                Y.append(X[index_xyz(x, y, (z - r0) % LANE_SIZE)])
    return Y


def ban_sol(a: list) -> list:
    ban_list = []
    for z in range(LANE_SIZE):
        ban = []
        for ai in a:
            ban.append(shiftZ(ai, z))
        ban_list.append(ban)
    return ban_list


def add_ban2cnf(cnf_path: str, ban_list: list) -> None:
    line_cnt = len(ban_list)
    ban_cnf = ""
    for ban in ban_list:
        for r in range(len(ban)):
            ai = ban[r]
            offset = r * STATE_SIZE + 1
            for i in range(len(ai)):
                v = ai[i]
                if v:
                    ban_cnf += "-" + str(i + offset) + " "
                else:
                    ban_cnf += str(i + offset) + " "
        ban_cnf += "0\n"

    with open(cnf_path, "r") as f:
        pre_cnf = f.read()
    index_1st = pre_cnf.find("\n")
    line_1st = pre_cnf[: index_1st + 1].split()
    line_1st[3] = str(int(line_1st[3]) + line_cnt)
    line_1st = " ".join(line_1st) + "\n"
    new_cnf = line_1st + pre_cnf[index_1st + 1 :] + ban_cnf
    with open(cnf_path, "w") as f:
        f.write(new_cnf)


if __name__ == "__main__":
    parse = argparse.ArgumentParser(description="add banned solutions to cnf")
    parse.add_argument("-c", "--cnf", type=str, help="cnf file")
    parse.add_argument("-s", "--solution", type=str, help="solution file")
    parse.add_argument("-r", "--rounds", type=int, help="rounds of the solution")
    parse.add_argument("--attack-mode", default="forgery_attack", help=argparse.SUPPRESS)
    args = parse.parse_args()

    a = read_sol_ls(args.solution, args.rounds)
    if not a:
        raise ValueError("solution not found")
    ban_list = ban_sol(a)
    add_ban2cnf(args.cnf, ban_list)
