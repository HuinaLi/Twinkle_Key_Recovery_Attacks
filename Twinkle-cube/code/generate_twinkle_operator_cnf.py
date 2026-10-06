#!/usr/bin/env python3
"""
Module: cnf_tools.py
Functionality: CNF constraint generation utilities and CLI.
Features: JSON constraint loading, SymPy POSform CNF generation, Espresso minimization, and DIMACS-like formatting.
Author: author
Last Modified: 2026-04-24
Notes: Constraint data is stored as JSON files under cnf_tool/constraints.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Sequence, Tuple

from sympy import symbols
from sympy.logic import POSform

CNFMethod = Literal['sympy', 'espresso']
OutputFormat = Literal['text', 'json', 'python-list', 'raw']

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONSTRAINTS_DIR = SCRIPT_DIR / 'constraints'
DEFAULT_CNF_OUT = SCRIPT_DIR.parent / 'operator_sympy.cnf'
DEFAULT_PLA_OUT = SCRIPT_DIR.parent / 'operator_espresso.pla'

LEGACY_CONSTRAINT_ALIASES = {
    'twinkle_sbox_withConstantInf': 'twinkle_sbox_with_constant_inf',
}


@dataclass(frozen=True)
class ConstraintSpec:
    """Validated truth-table rows for one operator constraint."""

    name: str
    description: str
    num_vars: int
    var_names: List[str]
    rows: List[List[int]]


class CNFGenerator:
    """Generate CNF artifacts from a validated constraint specification."""

    def __init__(self, spec: ConstraintSpec):
        self.spec = spec

    @classmethod
    def from_spec(cls, spec: Dict[str, Any] | ConstraintSpec) -> 'CNFGenerator':
        """Create a generator from a raw or already validated constraint spec."""
        if isinstance(spec, ConstraintSpec):
            return cls(spec)
        return cls(validate_constraint_spec(spec))

    def generate_sympy_cnf(self) -> str:
        """Generate a SymPy POSform CNF expression string."""
        return generate_cnf_by_sympy(self.spec.rows, self.spec.num_vars, self.spec.var_names)

    def generate_espresso_input(self) -> str:
        """Generate PLA input for Espresso."""
        return generate_espresso_input(self.spec.rows, self.spec.num_vars, self.spec.var_names)

    def generate_cnf_by_espresso(
        self,
        e_option: str = 'pos',
        o_option: str = 'eqntott',
        input_path: str | Path | None = None,
    ) -> str:
        """Run Espresso for this constraint and return raw stdout."""
        return run_espresso(
            self.generate_espresso_input(),
            e_option=e_option,
            o_option=o_option,
            input_path=input_path,
        )


def ensure_parent_dir(file_path: str | Path) -> None:
    """Create the parent directory for a path if needed."""
    Path(file_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def write_text_file(content: str, file_path: str | Path) -> None:
    """Write a UTF-8 text file, creating the parent directory if needed."""
    ensure_parent_dir(file_path)
    Path(file_path).write_text(content, encoding='utf-8')


def validate_constraint_spec(spec: Dict[str, Any]) -> ConstraintSpec:
    """Validate a JSON constraint specification."""
    if not isinstance(spec, dict):
        raise ValueError('Constraint spec must be a JSON object')
    name = spec.get('name')
    if not isinstance(name, str) or not name:
        raise ValueError("Constraint spec must contain a non-empty 'name'")
    rows = spec.get('rows')
    if not isinstance(rows, list) or not rows:
        raise ValueError("Constraint spec must contain a non-empty 'rows' list")
    normalized_rows: List[List[int]] = []
    for row_index, row in enumerate(rows):
        if not isinstance(row, list) or not row:
            raise ValueError(f'Row {row_index} must be a non-empty list')
        normalized_row: List[int] = []
        for col_index, value in enumerate(row):
            if value not in (0, 1):
                raise ValueError(f'Row {row_index}, column {col_index} must be 0 or 1')
            normalized_row.append(int(value))
        normalized_rows.append(normalized_row)
    inferred_num_vars = len(normalized_rows[0])
    for row_index, row in enumerate(normalized_rows):
        if len(row) != inferred_num_vars:
            raise ValueError(f'Row {row_index} has width {len(row)}, expected {inferred_num_vars}')
    num_vars = spec.get('num_vars', inferred_num_vars)
    if not isinstance(num_vars, int) or num_vars <= 0:
        raise ValueError("'num_vars' must be a positive integer")
    if num_vars != inferred_num_vars:
        raise ValueError(f"'num_vars' is {num_vars}, but rows have width {inferred_num_vars}")
    var_names = spec.get('var_names')
    if var_names is None:
        var_names = [f'x{i + 1}' for i in range(num_vars)]
    if not isinstance(var_names, list) or len(var_names) != num_vars:
        raise ValueError("'var_names' must be a list with length num_vars")
    normalized_var_names = []
    for index, var_name in enumerate(var_names):
        if not isinstance(var_name, str) or not var_name:
            raise ValueError(f'Variable name {index} must be a non-empty string')
        normalized_var_names.append(var_name)
    description = spec.get('description', '')
    if description is None:
        description = ''
    if not isinstance(description, str):
        raise ValueError("'description' must be a string when provided")
    return ConstraintSpec(
        name=name,
        description=description,
        num_vars=num_vars,
        var_names=normalized_var_names,
        rows=normalized_rows,
    )


def load_constraint_file(path: str | Path) -> ConstraintSpec:
    """Load and validate one JSON constraint file."""
    file_path = Path(path)
    with file_path.open('r', encoding='utf-8') as handle:
        data = json.load(handle)
    return validate_constraint_spec(data)


def load_builtin_constraints(directory: str | Path = DEFAULT_CONSTRAINTS_DIR) -> Dict[str, ConstraintSpec]:
    """Load all JSON constraints from a directory, keyed by constraint name."""
    constraints: Dict[str, ConstraintSpec] = {}
    dir_path = Path(directory)
    if not dir_path.exists():
        return constraints
    for path in sorted(dir_path.glob('*.json')):
        spec = load_constraint_file(path)
        if spec.name in constraints:
            raise ValueError(f"Duplicate constraint name '{spec.name}' in {dir_path}")
        constraints[spec.name] = spec
    return constraints


def resolve_constraint(args: argparse.Namespace) -> ConstraintSpec:
    """Resolve a constraint from a name or a JSON file path."""
    if args.constraint and args.constraint_file:
        raise ValueError("Use either '--constraint' or '--constraint-file', not both")
    if args.constraint_file:
        return load_constraint_file(args.constraint_file)
    if args.constraint:
        constraints = load_builtin_constraints(args.constraints_dir)
        constraint_name = LEGACY_CONSTRAINT_ALIASES.get(args.constraint, args.constraint)
        if constraint_name not in constraints:
            available = ', '.join(sorted(constraints)) or '<none>'
            raise ValueError(f"Unknown constraint '{args.constraint}'. Available constraints: {available}")
        return constraints[constraint_name]
    raise ValueError("Provide '--constraint', '--constraint-file', or '--list-constraints'")


def generate_cnf_by_sympy(rows: Sequence[Sequence[int]], num_vars: int, var_names: Sequence[str] | None = None) -> str:
    """Generate a SymPy POSform CNF expression string from valid rows."""
    names = list(var_names) if var_names is not None else [f'x{i + 1}' for i in range(num_vars)]
    if len(names) != num_vars:
        raise ValueError('var_names length must match num_vars')
    vars_sym = list(symbols(' '.join(names), seq=True))
    return str(POSform(vars_sym, [list(row) for row in rows])) + ';'


def convert_sympy_cnf_text_to_dimacs(content: str) -> Tuple[str, int]:
    """Convert SymPy POS/CNF text into the historical DIMACS-like list format."""
    clauses_count = content.count('&') + 1 if content.strip() else 0
    new_content = content.replace('\n', '').replace('&', '\n').replace('~', '-')
    new_content = re.sub(r'x(\d+)', r'\1', new_content)
    new_content = new_content.replace(' | ', ', ')
    new_content = new_content.replace('(', '\t[').replace(')', '],')
    new_content = new_content.replace(';', '').rstrip()
    return new_content, clauses_count


def convert_dnf_string_to_cnf_dimacs(dnf_string: str) -> Tuple[str, int]:
    """Convert Espresso eqntott DNF output to DIMACS-like CNF clauses."""
    if '=' in dnf_string:
        dnf_string = dnf_string.split('=', 1)[1]
    clean_string = dnf_string.replace('\n', '').replace(' ', '').replace(';', '')
    if not clean_string:
        return '', 0
    formatted_clauses = []
    for term in clean_string.split('|'):
        term_clean = term.replace('(', '').replace(')', '')
        if not term_clean:
            continue
        clause_nums = []
        for literal in term_clean.split('&'):
            if literal.startswith('!x'):
                clause_nums.append(literal[2:])
            elif literal.startswith('x'):
                clause_nums.append(f'-{literal[1:]}')
        formatted_clauses.append(f"\t[{', '.join(clause_nums)}],")
    return '\n'.join(formatted_clauses), len(formatted_clauses)


def generate_espresso_truth_table(rows: Sequence[Sequence[int]]) -> str:
    """Generate the body of an Espresso PLA truth table."""
    return ''.join(''.join(map(str, row)) + ' 1\n' for row in rows)


def generate_espresso_input(
    rows: Sequence[Sequence[int]],
    num_vars: int,
    var_names: Sequence[str] | None = None,
) -> str:
    """Generate PLA input text for Espresso."""
    names = list(var_names) if var_names is not None else [f'x{i + 1}' for i in range(num_vars)]
    if len(names) != num_vars:
        raise ValueError('var_names length must match num_vars')
    header = f".i {num_vars}\n.o 1\n.ilb " + ' '.join(names) + '\n.ob F\n'
    return header + generate_espresso_truth_table(rows) + '.e\n'


def find_espresso_binary() -> str:
    """Find the Espresso binary from the environment, PATH, or known local paths."""
    espresso_bin = os.environ.get('ESPRESSO_BIN') or shutil.which('espresso')
    if espresso_bin:
        return espresso_bin
    for path in ['/home/author/espresso-logic/bin/espresso', '/usr/local/bin/espresso', '/usr/bin/espresso']:
        if Path(path).exists():
            return path
    raise RuntimeError("Espresso binary not found. Set ESPRESSO_BIN or ensure 'espresso' is in PATH.")


def run_espresso(
    pla_content: str,
    e_option: str = 'pos',
    o_option: str = 'eqntott',
    input_path: str | Path | None = None,
    timeout: int = 30,
) -> str:
    """Run Espresso on PLA content and return raw stdout."""
    should_cleanup = False
    if input_path is None:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.pla', delete=False, encoding='utf-8')
        input_path = tmp.name
        should_cleanup = True
        tmp.write(pla_content)
        tmp.close()
    else:
        write_text_file(pla_content, input_path)
    try:
        cmd = [find_espresso_binary(), f'-e{e_option}', f'-o{o_option}', str(input_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            err = (result.stderr or result.stdout or '').strip()
            raise RuntimeError(f'Espresso failed with code {result.returncode}: {err}')
        return result.stdout
    finally:
        if should_cleanup and Path(input_path).exists():
            Path(input_path).unlink()


def generate_constraint_cnf(
    spec: ConstraintSpec | Dict[str, Any],
    method: CNFMethod = 'sympy',
    cnf_out: str | Path | None = None,
    pla_out: str | Path | None = None,
    espresso_e_option: str = 'pos',
    espresso_o_option: str = 'eqntott',
) -> Dict[str, Any]:
    """Generate CNF artifacts for one constraint and return structured results."""
    generator = CNFGenerator.from_spec(spec)
    constraint = generator.spec
    if method == 'sympy':
        raw = generator.generate_sympy_cnf()
        if cnf_out:
            write_text_file(raw, cnf_out)
        formatted, clause_count = convert_sympy_cnf_text_to_dimacs(raw)
    elif method == 'espresso':
        raw = generator.generate_cnf_by_espresso(
            e_option=espresso_e_option,
            o_option=espresso_o_option,
            input_path=pla_out,
        )
        formatted, clause_count = convert_dnf_string_to_cnf_dimacs(raw)
    else:
        raise ValueError("method must be 'sympy' or 'espresso'")
    return {
        'name': constraint.name,
        'description': constraint.description,
        'method': method,
        'num_vars': constraint.num_vars,
        'var_names': constraint.var_names,
        'row_count': len(constraint.rows),
        'clause_count': clause_count,
        'raw': raw,
        'python_list': formatted,
    }


def format_python_list_block(name: str, clause_count: int, body: str) -> str:
    """Format clauses in the historical Python-list block style."""
    return f'#{name} = {clause_count}\n{name} = [\n{body}\n]'


def print_result(result: Dict[str, Any], output_format: OutputFormat) -> None:
    """Print a generated CNF result in the selected output format."""
    block_name = f"{result['name']}_{result['method']}"
    if output_format == 'json':
        print(json.dumps(result, indent=2, sort_keys=True))
    elif output_format == 'raw':
        print(result['raw'])
    elif output_format == 'python-list':
        print(format_python_list_block(block_name, result['clause_count'], result['python_list']))
    else:
        print(f"Constraint: {result['name']}")
        print(f"Method: {result['method']}")
        print(f"Variables: {result['num_vars']}")
        print(f"Rows: {result['row_count']}")
        print(f"Clauses: {result['clause_count']}")
        print(format_python_list_block(block_name, result['clause_count'], result['python_list']))


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(description='Generate CNF constraints from JSON truth-table rows.')
    parser.add_argument('--list-constraints', action='store_true', help='List built-in JSON constraints and exit.')
    parser.add_argument('--constraint', help='Name of a built-in constraint loaded from --constraints-dir.')
    parser.add_argument('--constraint-file', help='Path to a JSON constraint file.')
    parser.add_argument('--constraints-dir', default=str(DEFAULT_CONSTRAINTS_DIR), help='Directory containing built-in JSON constraints.')
    parser.add_argument('--method', choices=['sympy', 'espresso'], default='sympy', help='CNF generation backend.')
    parser.add_argument('--format', choices=['text', 'json', 'python-list', 'raw'], default='text', help='Output format.')
    parser.add_argument('--cnf-out', help='Optional path for raw SymPy CNF output.')
    parser.add_argument('--pla-out', help='Optional path for Espresso PLA input.')
    parser.add_argument('--espresso-e-option', default='pos', help='Espresso -e option value.')
    parser.add_argument('--espresso-o-option', default='eqntott', help='Espresso -o option value.')
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        if args.list_constraints:
            constraints = load_builtin_constraints(args.constraints_dir)
            for name in sorted(constraints):
                spec = constraints[name]
                print(f'{name}: rows={len(spec.rows)}, vars={spec.num_vars}')
            return 0
        spec = resolve_constraint(args)
        result = generate_constraint_cnf(
            spec,
            method=args.method,
            cnf_out=args.cnf_out,
            pla_out=args.pla_out,
            espresso_e_option=args.espresso_e_option,
            espresso_o_option=args.espresso_o_option,
        )
        print_result(result, args.format)
        return 0
    except Exception as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
