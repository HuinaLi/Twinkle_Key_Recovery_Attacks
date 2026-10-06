#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generic S-box / inverse S-box ANF generator for arbitrary table sizes.

Supports SageMath and manual ANF construction, with MSB/LSB convention for x0/y0.

Author: author, Gemini 2.5 Flash
Date: 2025-10-22
Version: 2.0 (bit convention + ANF symbol remapping)
"""

from sage.crypto.boolean_function import BooleanFunction
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing
import sage.all as sage
import math
from typing import List, Tuple, Dict

# ----------------------------------------------------------------------
# Core Logic and Helpers (unchanged)
# ----------------------------------------------------------------------

def get_sbox_dimensions(sbox: List[int]) -> Tuple[int, int]:
    """
    Automatically determines the input and output bit width of the S-box.
    """
    input_bits = int(math.log2(len(sbox)))
    output_bits = max(sbox).bit_length()
    return input_bits, output_bits

# ----------------------------------------------------------------------
# ANF Generation (Fixed Sage Substitute)
# ----------------------------------------------------------------------

def sbox_to_anf_sage(sbox: List[int], bit_convention: str) -> Dict[str, str]:
    """
    Uses SageMath to convert an arbitrary S-box to ANF expressions,
    handling the x0/y0 bit convention by variable renaming.
    """
    input_bits, output_bits = get_sbox_dimensions(sbox)
    sbox_size = len(sbox)
    
    if sbox_size & (sbox_size - 1) != 0:
        raise ValueError(f"S-box length must be a power of 2, current length: {sbox_size}")
    
    # 1. Base ANF calculation (Sage default: x0=LSB, y0=LSB)
    R_sage = BooleanPolynomialRing(input_bits, names=[f'x{i}' for i in range(input_bits)])
    variables_sage = R_sage.gens() # [x0, x1, ..., x_max]
    
    anf_expressions_poly = {} # Store polynomials here
    
    for output_bit_index in range(output_bits):
        truth_table = []
        for i in range(sbox_size):
            bit_value = (sbox[i] >> output_bit_index) & 1
            truth_table.append(bit_value)
        
        bf = BooleanFunction(truth_table)
        anf_expressions_poly[output_bit_index] = R_sage(bf.algebraic_normal_form())
        
    # 2. Variable and Output Index Transformation
    
    final_anf_output = {}
    
    # Define the Target Ring for the output strings:
    # R_target uses the variable names in the user's desired convention (x0, x1, ...)
    target_var_names = [f'x{i}' for i in range(input_bits)]
    
    # This is where the magic happens:
    # The output string will use names from R_target, even if we substitute in R_sage.
    R_target = BooleanPolynomialRing(input_bits, names=target_var_names)
    target_vars = R_target.gens() # [x0, x1, ..., x_max] in the target ring
    
    for y_index in range(output_bits):
        
        if bit_convention == 'LSB':
            y_std_index = y_index 
            
            # Map: Sage x_i -> Target x_i
            rename_map = {variables_sage[i]: target_vars[i] for i in range(input_bits)}
            
        else: # 'MSB' (Ascon: x0=MSB)
            y_std_index = output_bits - 1 - y_index 
            
            # Map: Sage x_i (bit i) -> Target x_{max - 1 - i} (MSB index)
            # E.g., 5 bits: Sage x0 -> Target x4, Sage x1 -> Target x3, ..., Sage x4 -> Target x0
            rename_map = {
                variables_sage[i]: target_vars[input_bits - 1 - i] 
                for i in range(input_bits)
            }
            
        # b) Get the base polynomial
        poly_raw = anf_expressions_poly[y_std_index]
        
        # c) Apply robust variable substitution using PolyBoRi symbols
        # This is the line that should now be safe:
        poly_transformed = poly_raw.subs(rename_map) 
        
        # d) Store the string representation from the target ring
        final_anf_output[f'y{y_index}'] = str(poly_transformed)
        
    return final_anf_output


def manual_anf_calculation(sbox: List[int], bit_convention: str) -> Dict[str, str]:
    # ... (manual_anf_calculation remains unchanged, as its logic was already correct for string generation)
    """
    Manually calculates the ANF expressions using the Mobius Transform,
    handling the x0/y0 bit convention for final naming.
    """
    input_bits, output_bits = get_sbox_dimensions(sbox)
    sbox_size = len(sbox)
    
    if sbox_size & (sbox_size - 1) != 0:
        raise ValueError(f"S-box length must be a power of 2, current length: {sbox_size}")
    
    def mobius_transform(truth_table):
        n = len(truth_table)
        anf_coeffs = truth_table[:]
        
        num_vars = int(math.log2(n))
        for i in range(num_vars):
            step = 1 << i
            for mask in range(n):
                if mask & step:
                    anf_coeffs[mask] ^= anf_coeffs[mask ^ step]
        return anf_coeffs
    
    def coeffs_to_polynomial(coeffs, num_vars, convention: str):
        # Generates polynomial string based on coeffs (x0=LSB logic)
        terms = []
        
        for i, coeff in enumerate(coeffs):
            if coeff == 1:
                if i == 0:
                    terms.append('1')
                else:
                    term_vars = []
                    for j in range(num_vars):
                        if i & (1 << j):
                            # j is the standard LSB index
                            if convention == 'LSB':
                                var_name = f'x{j}'
                            else: # 'MSB'
                                var_name = f'x{num_vars - 1 - j}'
                                
                            term_vars.append(var_name)
                    # Sort variables for consistent output
                    terms.append('*'.join(sorted(term_vars))) 
        
        if not terms:
            return '0'
        # Sort terms based on a canonical ordering for consistency
        return ' + '.join(sorted(terms)) 
    
    anf_expressions_raw = {}
    
    for output_bit_index in range(output_bits):
        truth_table = []
        for i in range(sbox_size):
            # Standard LSB extraction (bit 0 is LSB)
            bit_value = (sbox[i] >> output_bit_index) & 1
            truth_table.append(bit_value)
        
        anf_coeffs = mobius_transform(truth_table)
        
        # Use LSB index (bit j) for variable naming during transformation
        polynomial = coeffs_to_polynomial(anf_coeffs, input_bits, bit_convention)
        
        # Store: y_LSB_index -> raw expression
        anf_expressions_raw[output_bit_index] = polynomial
        
    # 2. Re-index Y outputs
    final_anf_output = {}
    
    for y_index in range(output_bits):
        
        if bit_convention == 'LSB':
            y_std_index = y_index 
        else: # 'MSB'
            y_std_index = output_bits - 1 - y_index
            
        final_anf_output[f'y{y_index}'] = anf_expressions_raw[y_std_index]
        
    return final_anf_output


def analyze_sbox_properties(sbox: List[int]) -> Dict:
    # ... (Analysis functions remain unchanged for brevity)
    input_bits, output_bits = get_sbox_dimensions(sbox)
    sbox_size = len(sbox)

    print("=== S-box cryptographic properties ===")
    print(f"S-box: {input_bits}-bit input -> {output_bits}-bit output ({sbox_size} entries)")

    is_bijection = len(set(sbox)) == sbox_size and input_bits == output_bits
    print(f"Bijection: {is_bijection}")

    max_diff = 0
    max_output_value = (1 << output_bits)

    for delta_in in range(1, sbox_size):
        for delta_out in range(max_output_value):
            count = 0
            for x in range(sbox_size):
                if sbox[x] ^ sbox[x ^ delta_in] == delta_out:
                    count += 1
            max_diff = max(max_diff, count)

    print(f"Differential uniformity (max count): {max_diff}")
    
    min_linearity = None
    min_nonlinearity = None
    linearities_list = []
    nonlinearities_list = []

    if sbox_size <= 256:
        try:
            input_bits = int(math.log2(sbox_size)) 
            power_of_two_minus_one = 2**(input_bits - 1) # 2^(n-1)

            for output_bit in range(output_bits):
                truth_table = [(sbox[i] >> output_bit) & 1 for i in range(sbox_size)]
                bf = BooleanFunction(truth_table)
                
                nl = bf.nonlinearity()
                # Linearity (Lin) = 2 * (2^(n-1) - NL) from Walsh spectrum
                lin = 2 * (power_of_two_minus_one - nl) 
                
                linearities_list.append(lin)
                nonlinearities_list.append(nl)

            min_linearity = min(linearities_list)
            min_nonlinearity = min(nonlinearities_list)
            
            print(f"Linearity per output bit: {linearities_list}")
            print(f"Min linearity: {min_linearity}")
            print(f"Min nonlinearity: {min_nonlinearity}")
        
        except Exception as e:
            print(f"Linearity computation failed: {e}")
            
    else:
        print("S-box too large; skipping linearity")
    
    return {
        'input_bits': input_bits,
        'output_bits': output_bits,
        'is_bijection': is_bijection,
        'differential_uniformity': max_diff,
        'linearity': min_linearity,
        'nonlinearity': min_nonlinearity,
    }

def generate_inverse_sbox(sbox: List[int]) -> List[int]:
    sbox_size = len(sbox)
    inv_sbox = [None] * sbox_size
    
    for input_value in range(sbox_size):
        output_value = sbox[input_value]
        
        inv_sbox[output_value] = input_value
        
    return [int(x) for x in inv_sbox]


def get_DDT_table(S_box):
    n = len(S_box)
    res = [[0]*n for _ in range(n)]
    res[0][0] = n
    for a in range(n):
        for b in range(n):
            if a == 0 and b == 0:
                continue
            for x in range(n):
                if S_box[x ^ a] ^ S_box[x] == b:
                    res[a][b] += 1
    return res

def main():
    twinkle_sbox = [0x0, 0x3, 0x5, 0xd, 0x6, 0xf, 0xa, 0x8, 
                    0xb, 0x4, 0xe, 0x2, 0x9, 0xc, 0x7, 0x1]  # 4-bit LSB example
    
    ascon_sbox = [0x4, 0xb, 0x1f, 0x14, 0x1a, 0x15, 0x9, 0x2, 
                  0x1b, 0x5, 0x8, 0x12, 0x1d, 0x3, 0x6, 0x1c, 
                  0x1e, 0x13, 0x7, 0xe, 0x0, 0xd, 0x11, 0x18, 
                  0x10, 0xc, 0x1, 0x19, 0x16, 0xa, 0xf, 0x17]  # 5-bit MSB example

    example_sbox = twinkle_sbox
    example_sbox_1 = example_sbox
    example_sbox_2 = generate_inverse_sbox(example_sbox)
    convention = 'MSB'
    
    print("="*60)
    print("--- Example: S-box DDT ---")
    print("="*60)
    DDT_table = get_DDT_table(example_sbox)
    for line in DDT_table:
        print(line)

    print("="*60)
    print(f"--- Example 1: S-box (convention x0/y0 = {convention}) ---")
    print("="*60)
    properties_1 = analyze_sbox_properties(example_sbox_1)
    print()
    
    try:
        # Sage ANF
        anf_sage_1 = sbox_to_anf_sage(example_sbox_1, convention)
        print(f"=== SageMath ANF (x0/y0 = {convention} ) ===")
        for output, expr in anf_sage_1.items():
            print(f"{output} = {expr}")
        print()
    except Exception as e:
        print(f"SageMath error: {e}")
        
    # Manual ANF
    anf_manual_1 = manual_anf_calculation(example_sbox_1, convention)
    print(f"=== Manual ANF (x0/y0 = {convention}) ===")
    for output, expr in anf_manual_1.items():
        print(f"{output} = {expr}")
    print()


    print("="*60)
    print(f"--- Example 2: InvS-box (convention x0/y0 = {convention}) ---")
    print("="*60)
    properties_2 = analyze_sbox_properties(example_sbox_2)
    print()
    
    try:
        # Sage ANF
        anf_sage_2 = sbox_to_anf_sage(example_sbox_2, convention)
        print(f"=== SageMath ANF (x0/y0 = {convention}) ===")
        for output, expr in anf_sage_2.items():
            print(f"{output} = {expr}")
        print()
    except Exception as e:
        print(f"SageMath error: {e}")
        
    # Manual ANF
    anf_manual_2 = manual_anf_calculation(example_sbox_2, convention)
    print(f"=== Manual ANF (x0/y0 = {convention}) ===")
    for output, expr in anf_manual_2.items():
        print(f"{output} = {expr}")
if __name__ == "__main__":
    main()