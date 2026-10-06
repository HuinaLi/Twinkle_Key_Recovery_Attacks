from twinkle_round_function import *
from sage.all import *
from sage.rings.polynomial.pbori import *
from sage.sat.converters.polybori import CNFEncoder
from sage.sat.solvers.dimacs import DIMACS
from pysat.card import *
from pysat.formula import IDPool
import argparse
import os


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

def generate_filename(path, rounds, d_value):
    run_id = os.environ.get("TWINKLE_RUN_ID")
    if run_id:
        return os.path.join(path, f"cube_{run_id}")
    return os.path.join(path, f"cube{rounds}r_d{d_value}")

def generate_cube_search_model(path, rounds, d_value):
    if rounds < 2:
        raise ValueError("without-IO cube search expects rounds >= 2")

    global R
    primary_var_count = 4 * (rounds - 1) * STATE_SIZE + STATE_SIZE
    R = declare_ring([Block('v', primary_var_count)], globals())
    ################INV#########################
    # r-round without-IO propagation:
    # A[0] --Sbox--> B[0] --LR0--> C[0] --MS--> D[0] --LR1--> A[1]
    # ...
    # A[r-2] --Sbox--> B[r-2] --LR0--> C[r-2] --MS--> D[r-2] --LR1--> A[r-1]
    # Variable layout keeps compatibility with the printer and ban clauses:
    # A[0..rounds-1], then B[0..rounds-2], C[0..rounds-2], D[0..rounds-2]
    ############################################

    def a_offset(r):
        return r * STATE_SIZE

    def b_offset(r):
        return (rounds + r) * STATE_SIZE

    def c_offset(r):
        return (rounds + (rounds - 1) + r) * STATE_SIZE

    def d_offset(r):
        return (rounds + 2 * (rounds - 1) + r) * STATE_SIZE

    def emit_template_clause(template, row):
        clause = []
        for lit in template:
            var_id = row[abs(int(lit)) - 1] + 1
            clause.append(str(var_id if lit > 0 else -var_id))
        clause.append('0')
        return " ".join(clause)

    A = [[R(v(i + a_offset(r))) for i in range(STATE_SIZE)] for r in range(rounds)]
    B = [[R(v(i + b_offset(r))) for i in range(STATE_SIZE)] for r in range(rounds - 1)]
    C = [[R(v(i + c_offset(r))) for i in range(STATE_SIZE)] for r in range(rounds - 1)]
    D = [[R(v(i + d_offset(r))) for i in range(STATE_SIZE)] for r in range(rounds - 1)]
    Q = set()
    objective_cnf = " "
    ########### Adding LaneRotation0/1 SAT Model##################

    for r in range(rounds - 1):
        lr0_b = lane_rotation0(B[r])
        lr1_d = lane_rotation1(D[r])
        for i in range(STATE_SIZE):
            Q.add(lr0_b[i] + C[r][i])
            Q.add(lr1_d[i] + A[r + 1][i])

    filename = generate_filename(path, rounds, d_value)
    filename += ".cnf"
    solver = DIMACS(filename=filename)
    e = CNFEncoder(solver, R)
    e(list(Q))
    solver.write()

    with open(filename, "r") as f:
        cnf_info = f.readline().split(" ")
        var_num, clause_num = int(cnf_info[2]), int(cnf_info[3])
        ls_cnf = f.read()
    print(var_num, clause_num)

#################### S-box SAT Model ######################
    # A[r] ---> B[r]
    row = [0] * 8
    for r in range(rounds - 1):
        for y in range(Y_SIZE):
            for z in range(LANE_SIZE):
                row = [
                    a_offset(r) + index_xyz(0, y, z),
                    a_offset(r) + index_xyz(1, y, z),
                    a_offset(r) + index_xyz(2, y, z),
                    a_offset(r) + index_xyz(3, y, z),
                    b_offset(r) + index_xyz(0, y, z),
                    b_offset(r) + index_xyz(1, y, z),
                    b_offset(r) + index_xyz(2, y, z),
                    b_offset(r) + index_xyz(3, y, z),
                ]
                for clause_template in cnf_twinkle_sbox:
                    objective_cnf += emit_template_clause(clause_template, row) + "\n"
                    clause_num += 1
    print(f"cnf_twinkle_sbox Added")

    ## A[rounds-1] ---> final linearity constraint
    row = [0] * 4
    for y in range(Y_SIZE):
        for z in range(LANE_SIZE):
            row = [
                a_offset(rounds - 1) + index_xyz(0, y, z),
                a_offset(rounds - 1) + index_xyz(1, y, z),
                a_offset(rounds - 1) + index_xyz(2, y, z),
                a_offset(rounds - 1) + index_xyz(3, y, z),
            ]
            for clause_template in cnf_A1:
                objective_cnf += emit_template_clause(clause_template, row) + "\n"
                clause_num += 1
    print(f"cnf_A1 Added")
#################### MixSlice SAT Model ######################
    # C[r] ---> D[r]
    row = [0] * 4
    for r in range(rounds - 1):
        for z in range(LANE_SIZE):
            for xy in range(X_SIZE * Y_SIZE):
                row = [
                    c_offset(r) + xy + index_xyz(0, 0, z),
                    c_offset(r) + rotate_left_xy16(xy, 5) + index_xyz(0, 0, z),
                    c_offset(r) + rotate_left_xy16(xy, 12) + index_xyz(0, 0, z),
                    d_offset(r) + xy + index_xyz(0, 0, z),
                ]
                for clause_template in cnf_twinkle_mixslice:
                    objective_cnf += emit_template_clause(clause_template, row) + "\n"
                    clause_num += 1
    print(f"cnf_twinkle_mixslice Added")
#################### Cardinality Constraint SAT Model ######################
######### objective: as (A[0])  ###
    lits = list(range(1, STATE_SIZE + 1))
    pool = IDPool(start_from=var_num + 1)
    cnf = CardEnc.equals(lits, bound=d_value, vpool=pool, encoding=EncType.kmtotalizer)
    clause_num += len(cnf.clauses)
    for i in cnf.clauses:
        temp = []
        for ii in i:
            ii = str(ii)
            temp.append(ii)
        temp.append("0")
        objective_cnf += " ".join(temp) + "\n"
    var_num = pool.top
    print(f"CardEnc Added")
#################### Final SAT model ####################
    with open(filename, "w") as f:
        f.write(f"p cnf {var_num} {clause_num}\n")
        f.write(ls_cnf)
        f.write(objective_cnf)

    print(f"{rounds}-round twinkle-withoutIO cube Model Done:) var_num:{var_num}, clause_num:{clause_num}")


if __name__ == '__main__':
    parse = argparse.ArgumentParser(description="Adding initialization+Obj")
    parse.add_argument("-d", "--dvalue", type=int, help="number of as of A0")
    parse.add_argument(
        "-r", "--rounds", "--round", type=int, dest="rounds", help="number of rounds"
    )
    parse.add_argument("-f", "--path", type=str, help="cnf file path")
    args = parse.parse_args()

    generate_cube_search_model(args.path, args.rounds, args.dvalue)
    