from twinkle_round_function import *
from sage.all import *
from sage.rings.polynomial.pbori import *
from sage.sat.converters.polybori import CNFEncoder
from sage.sat.solvers.dimacs import DIMACS
from pysat.card import *
from pysat.formula import IDPool
import argparse
import os
import re


##(A[0][index_xyz(0,y,z)],A[0][index_xyz(1,y,z)],A[0][index_xyz(2,y,z)],A[0][index_xyz(3,y,z)]  ---Sbox-->  
# (B[0][index_xyz(0,y,z)],B[0][index_xyz(1,y,z)],B[0][index_xyz(2,y,z)],B[0][index_xyz(3,y,z)] )

#cnf_twinkle_sbox =  19
cnf_twinkle_sbox =  [
        [6, -3], 
        [8, -1], 
        [-1, -2], 
        [-1, -3], 
        [-1, -4], 
        [-2, -3], 
        [-2, -4], 
        [-3, -4], 
        [5, 6, 7, -2], 
        [5, 6, 7, -4], 
        [5, 7, 8, -6], 
        [1, 6, -5, -7], 
        [3, 8, -5, -7], 
        [1, 2, 3, 4, -5], 
        [1, 2, 3, 4, -7], 
        [2, 3, 4, 5, 7, -8], 
        [1, 2, 4, -5, -7, -8], 
        [1, 3, 5, -6, -7, -8], 
        [1, 3, 7, -5, -6, -8]
 ]

## A[1][index_xyz(0,y,z),index_xyz(1,y,z),index_xyz(2,y,z),index_xyz(3,y,z)] 
#cnf_A1 =  6
cnf_A1 =  [
        [-1, -2], 
        [-1, -3], 
        [-1, -4], 
        [-2, -3], 
        [-2, -4], 
        [-3, -4]
 ]

#cnf_twinkle_mixslice =  4
cnf_twinkle_mixslice =  [
        [4, -1], 
        [4, -2], 
        [4, -3], 
        [1, 2, 3, -4],
 ]

# twinkle_sbox_withConstantInf allowed rows = 48
# cnf_twinkle_sbox_withConstantInf = 53
cnf_twinkle_sbox_withConstantInf =  [
        [-2, -5, 11, 12],
        [2, -4, -10, -11, 12],
        [-3, -9, 10, -11],
        [-4, -6, -11, -12],
        [-5, 8, -11, -12],
        [-1, 6, -8, -9],
        [-7, 9, 11, 12],
        [-2, -8, -9, -11],
        [-3, -6, 8, 9],
        [-3, 9, 11, 12],
        [2, -4, 6, -10, 11, -12],
        [-2, -4, -5, 9],
        [-4, 6, 7, -9, 10],
        [2, -8, 9, -10, 12],
        [-3, -6, -8, -9],
        [-7, -8],
        [1, 5, 9, -10, -11, -12],
        [4, -7, -11, 12],
        [2, -3, 10],
        [-1, 8, 9],
        [1, 2, 6, -9, -11, -12],
        [-5, 10],
        [3, 7, 10, -11, 12],
        [1, 8, -9, -10, 11, -12],
        [1, -4, 5, -11, -12],
        [1, 4, 6, 7, -11, -12],
        [-3, -8, -11, 12],
        [-5, 8, 9, 12],
        [4, -5, -8, 11],
        [-1, 4, -8, 10],
        [-4, -6, -9, 12],
        [-1, 6, 11],
        [-1, -5],
        [9, 10, 11, -12],
        [-2, 3, 10, -11],
        [3, -8, -9, 11, 12],
        [4, 7, 8, -9, 12],
        [-5, -7],
        [-1, -7],
        [-4, 5, -8, -10],
        [2, 3, 5, -10, 12],
        [3, 4, 5, 11, -12],
        [-1, 8, 10, 11],
        [1, 3, -6, -12],
        [-1, 4, 8, -10],
        [-3, -7],
        [-1, -6, 9],
        [-2, 3, -9, 10],
        [-2, 5, 7, -10],
        [6, -7, 12],
        [-3, 6, -12],
        [-3, -4],
        [-5, -6],
 ]
def generate_filename(path, rounds, d_value):
    run_id = os.environ.get("TWINKLE_RUN_ID")
    if run_id:
        return os.path.join(path, f"cube_{run_id}")
    return os.path.join(path, f"cube{rounds}r_d{d_value}")

def _var_index_of(elem):
    """Extract v(#) index from a Sage ring element or string (returns int)."""
    try:
        return int(elem.index())
    except Exception:
        s = str(elem)
        m = re.search(r"v\(?(\d+)\)?", s)
        if m:
            return int(m.group(1))
    raise ValueError(f"cannot parse variable index from: {elem}")

def _clauses_from_template(row, template):
    """Map a CNF template to DIMACS literals (row holds zero-based variable indices)."""
    def lit_to_dimacs(l):
        if l > 0:
            return str(row[l - 1] + 1)
        else:
            idx = abs(l) - 1
            return "-" + str(row[idx] + 1)
    return [" ".join(lit_to_dimacs(l) for l in tpl) + " 0" for tpl in template]

def generate_cube_search_model(path, rounds, d_value):
    ###############INV#########################
    # We aim to search r<=2 round-linear structure with at least 28 cube variables for Twinkle
    # 2r: IV--IV_expansion --> A[0]--Sbox--> B[0] --LR0--> C[0] --MS--> D[0] --LR1--> A[1] 
    # IV        v 1 -  128
    # A[1]      v 129 -   1408 
    # B[0]      v 1409 -  2688
    # C[0]      v 2689 -  3968
    # D[0]      v 3969 -  5248
    # F         v 5249 -  5376     constraint input s-box function 
    ############################################
    global R
    total_vars = 3 * (rounds - 1) * STATE_SIZE + STATE_SIZE + 128 + 128
    R = declare_ring([Block('v', total_vars)], globals())

    # Layout: see block comments above
    IV = [R(v(i)) for i in range(128)]
    if rounds == 2:
        A = [[R(v(i + 128 + r * STATE_SIZE)) for i in range(STATE_SIZE)] for r in range(rounds - 1)]
        B = [[R(v(i + 128 + (rounds - 1 + r) * STATE_SIZE)) for i in range(STATE_SIZE)] for r in range(rounds - 1)]
        C = [[R(v(i + 128 + (2 * (rounds - 1) + r) * STATE_SIZE)) for i in range(STATE_SIZE)] for r in range(rounds - 1)]
        D = [[R(v(i + 128 + (3 * (rounds - 1) + r) * STATE_SIZE)) for i in range(STATE_SIZE)] for r in range(rounds - 1)]
        F = [R(v(i + 128 + 4 * (rounds - 1)  * STATE_SIZE)) for i in range(128)] 
    if rounds == 1:
        B = [R(v(i + 128 )) for i in range(STATE_SIZE)] 
        F = [R(v(i + 128 + STATE_SIZE)) for i in range(128)] 
    Q = set()
    objective_cnf = ""

    # 1) Baseline: FI expansion -> Q
    IV_exp = input_expansion_fi(IV)
    IV_f = input_expansion_fi(F)
   
    if rounds > 1:
        # Lane rotations and wiring constraints
        B[0] = lane_rotation0(B[0])
        D[0] = lane_rotation1(D[0])
        for i in range(STATE_SIZE):
            Q.add(B[0][i] + C[0][i])
            Q.add(D[0][i] + A[0][i])

    # Write baseline CNF via CNFEncoder
    filename = generate_filename(path, rounds,d_value)
    filename += ".cnf"
    solver = DIMACS(filename = filename)
    e = CNFEncoder(solver, R)
    e(list(Q))
    solver.write()

    # Read baseline header (var/clause counts) and keep body text
    with open(filename, "r") as f:
        header = f.readline().split()
        var_num, clause_num = int(header[2]), int(header[3])
        ls_cnf = f.read()
    print(var_num,clause_num)

    # Segment start offsets (zero-based indices into the flat v-block)
    A_start = 128
    B_start = 128 + (rounds - 1) * STATE_SIZE
    C_start = 128 + 2 * (rounds - 1) * STATE_SIZE
    D_start = 128 + 3 * (rounds - 1) * STATE_SIZE
    

    # Map each IV_exp / IV_f entry to its v(#) index (first round input wiring)
    iv_exp_var_idx = [_var_index_of(e) for e in IV_exp]
    iv_f_var_idx = [_var_index_of(e) for e in IV_f]

    # Force the original 128-bit F mask to be nonzero without fixing a specific bit.
    f_var_idx = [_var_index_of(fi) for fi in F]
    f_nonzero_clause = " ".join(str(i + 1) for i in f_var_idx) + " 0\n"
    objective_cnf += f_nonzero_clause
    clause_num += 1
    var_num = max(var_num, max(i + 1 for i in f_var_idx))
    print("F nonzero clause Added")

    # 2) First round S-box SAT model （A,F -> B）
    
    for y in range(Y_SIZE):
        for z in range(LANE_SIZE):
            p0 = index_xyz(0, y, z)
            p1 = index_xyz(1, y, z)
            p2 = index_xyz(2, y, z)
            p3 = index_xyz(3, y, z)

            
            ina0 = iv_exp_var_idx[p0]
            ina1 = iv_exp_var_idx[p1]
            ina2 = iv_exp_var_idx[p2]
            ina3 = iv_exp_var_idx[p3]
            

            inf0 = iv_f_var_idx[p0]
            inf1 = iv_f_var_idx[p1]
            inf2 = iv_f_var_idx[p2]
            inf3 = iv_f_var_idx[p3]

            outb0 = B_start +  p0
            outb1 = B_start +  p1
            outb2 = B_start +  p2
            outb3 = B_start +  p3

            row = [ina0, inf0, ina1, inf1, ina2, inf2, ina3, inf3, outb0, outb1, outb2, outb3]
            clauses = _clauses_from_template(row, cnf_twinkle_sbox_withConstantInf)
            objective_cnf += "\n".join(clauses) + "\n"
            clause_num += len(clauses)
    print(f"cnf_twinkle_sbox_withConstantInf Added")

    if rounds > 1:
        # 3) MixSlice clauses (C[0] -> D[0])
        for z in range(LANE_SIZE):
            for i in range(X_SIZE * Y_SIZE):
                row4 = [
                    C_start + i + index_xyz(0, 0, z),
                    C_start + rotate_left_xy16(i, 5) + index_xyz(0, 0, z),
                    C_start + rotate_left_xy16(i, 12) + index_xyz(0, 0, z),
                    D_start + i + index_xyz(0, 0, z)
                ]
                objective_cnf += "\n".join(_clauses_from_template(row4, cnf_twinkle_mixslice)) + "\n"
                clause_num += len(cnf_twinkle_mixslice)
        print(f"cnf_twinkle_mixslice Added")
        # 4) Constraints on A[rounds-1] when rounds > 1
        for y in range(Y_SIZE):
            for z in range(LANE_SIZE):
                row4 = [
                    A_start + index_xyz(0, y, z),
                    A_start + index_xyz(1, y, z),
                    A_start + index_xyz(2, y, z),
                    A_start + index_xyz(3, y, z)
                ]
                objective_cnf += "\n".join(_clauses_from_template(row4, cnf_A1)) + "\n"
                clause_num += len(cnf_A1)
        print(f"cnf_A1 Added")

    # 5) Cardinality on IV bits (at least d_value active bits)
    lits = list(range(1, 128 + 1))
    pool = IDPool(start_from=var_num + 1)
    cnf_card = CardEnc.equals(lits, bound=d_value, vpool=pool, encoding=EncType.kmtotalizer)
    clause_num += len(cnf_card.clauses)
    for c in cnf_card.clauses:
        objective_cnf += " ".join(str(x) for x in c) + " 0\n"
    var_num = pool.top
    print(f"CardEnc Added")

    # Final CNF: baseline body + objective clauses
    with open(filename, "w") as f:
        f.write(f"p cnf {var_num} {clause_num}\n")
        f.write(ls_cnf)
        f.write(objective_cnf)

    print(f"{rounds}-round twinkle cube Model Done:) var_num:{var_num}, clause_num:{clause_num}")

if __name__ == '__main__':
    parse = argparse.ArgumentParser(description="Adding initialization+Obj")
    parse.add_argument("-d", "--dvalue", type=int, help="number of as of A0")
    parse.add_argument(
        "-r", "--rounds", "--round", type=int, dest="rounds", help="number of rounds"
    )
    parse.add_argument("-f", "--path", type=str, help="cnf file path")
    args = parse.parse_args()

    generate_cube_search_model(args.path, args.rounds, args.dvalue)
    