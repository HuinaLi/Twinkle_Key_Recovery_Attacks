"""
Twinkle Round Function Implementation in ANF (Algebraic Normal Form)

This module implements the Twinkle permutation function based on its specification.
The implementation focuses on algebraic normal form representation for cryptanalysis,
using the SageMath library (pbori).

The state is represented as a (16 * l)-bit array organized as 4x4xl bits.
Coordinates (x, y, z) where 0 <= x, y <= 3 and 0 <= z <= l-1.

*** LOGIC REVERTED: Using Slice-Major memory layout (as per user) ***
Index calculation: x + 4*y + 16*z

Based on the structure of keccakround.py by author.
"""

import logging
import os
from typing import List, Tuple, Union, Optional

from sage.all import *
from sage.rings.polynomial.pbori import *

# --- Variant Selection ---
# Select by cipher size: 1280 -> PA, 256 -> PA-lw1, 128 -> PA-lw2.
CIPHER_VARIANT_MAP = {
    "1280": "PA",
    "256": "PA-lw1",
    "128": "PA-lw2",
}
SELECTED_CIPHER = os.environ.get("TWINKLE_CIPHER", "1280")
if SELECTED_CIPHER not in CIPHER_VARIANT_MAP:
    raise ValueError(
        f"Unknown TWINKLE_CIPHER: {SELECTED_CIPHER}. Must be one of {sorted(CIPHER_VARIANT_MAP)}"
    )
SELECTED_VARIANT = CIPHER_VARIANT_MAP[SELECTED_CIPHER]
# ---

# Constants dictionaries for different variants
VARIANT_CONSTANTS = {
    "PA": {
        "LANE_SIZE": 80,
        "O0": [20, 24, 38, 77, 49, 66, 30, 40, 76, 15, 46, 50, 17, 18, 61, 62],
        "O1": [63, 45, 34, 39, 32, 43, 60, 66, 54, 26, 55, 36, 61, 12, 15, 35]
    },
    "PA-lw1": {
        "LANE_SIZE": 16,
        "O0": [1, 4, 3, 13, 14, 12, 7, 15, 0, 11, 8, 2, 5, 6, 9, 10],
        "O1": [3, 4, 1, 13, 2, 14, 8, 15, 9, 7, 12, 10, 0, 11, 5, 6]
    },
    "PA-lw2": {
        "LANE_SIZE": 8,
        "O0": [1, 2, 5, 4, 7, 3, 4, 1, 6, 0, 7, 2, 6, 5, 3, 0],
        "O1": [0, 3, 7, 4, 5, 7, 4, 0, 1, 2, 3, 6, 6, 2, 1, 5]
    }
}

if SELECTED_VARIANT not in VARIANT_CONSTANTS:
    raise ValueError(f"Unknown variant: {SELECTED_VARIANT}. Must be one of {list(VARIANT_CONSTANTS.keys())}")

# Constants for Twinkle (dynamically set based on variant)
X_SIZE = 4  # Number of columns (x-dimension)
Y_SIZE = 4  # Number of rows (y-dimension)
LANE_SIZE = VARIANT_CONSTANTS[SELECTED_VARIANT]["LANE_SIZE"]
STATE_SIZE = X_SIZE * Y_SIZE * LANE_SIZE  # Total state size in bits
# Rotation offsets (dynamically set based on variant)
O0 = VARIANT_CONSTANTS[SELECTED_VARIANT]["O0"]
O1 = VARIANT_CONSTANTS[SELECTED_VARIANT]["O1"]

# Round constants for AddConstant (AC) step
# Populated as per user request. This is a list of 7 1280-bit integers.
TWINKLE_ROUND_CONSTANTS = [
    # RC1 (already fixed by user, kept as is)
    0x243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e638d01377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b54709179216d5d98979fb1bd1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96ba7c9045f12c7f9924a19947b3916cf70801f2e2858efc16636920d871574e69a458fea3f4933d7e0d95748f728eb658718bcd5882154aee7b54a41dc25a59b5,
    # RC2
    0x9c30d5392af26013c5d1b023286085f0ca417918b8db38ef8e79dcb0603a180e6c9e0e8bb01e8a3ed71577c1bd314b2778af2fda55605c60e65525f3aa55ab945748986263e8144055ca396a2aab10b6b4cc5c341141e8cea15486af7c72e993b3ee1411636fbc2a2ba9c55d741831f6ce5c3e169b87931eafd6ba336c24cf5c7a325381289586773b8f48986b4bb9afc4bfe81b6628219361d809ccfb21a991,
    # RC3
    0x487cac605dec8032ef845d5de98575b1dc262302eb651b8823893e81d396acc50f6d6ff383f442392e0b4482a484200469c8f04a9e1f9b5e21c66842f6e96c9a670c9c61abd388f06a51a0d2d8542f68960fa728ab5133a36eef0b6c137a3be4ba3bf0507efb2a98a1f1651d39af017666ca593e82430e888cee8619456f9fb47d84a5c33b8b5ebee06f75d885c12073401a449f56c16aa64ed3aa62363f7706,
    # RC4
    0x1bfedf72429b023d37d0d724d00a1248db0fead349f1c09b075372c980991b7b25d479d8f6e8def7e3fe501ab6794c3b976ce0bd04c006bac1a94fb6409f60c45e5c9ec2196a246368fb6faf3e6c53b51339b2eb3b52ec6f6dfc511f9b30952ccc814544af5ebd09bee3d004de334afd660f2807192e4bb3c0cba85745c8740fd20b5f39b9d3fbdb5579c0bd1a60320ad6a100c6402c7279679f25fefb1fa3cc,
    # RC5
    0x8ea5e9f8db3222f83c7516dffd616b152f501ec8ad0552ab323db5fafd23876053317b483e00df829e5c57bbca6f8ca01a87562edf1769dbd542a8f6287effc3ac6732c68c4f5573695b27b0bbca58c8e1ffa35db8f011a010fa3d98fd2183b84afcb56c2dd1d35b9a53e479b6f84565d28e49bc4bfb9790e1ddf2daa4cb7e3362fb1341cee4c6e8ef20cada36774c01d07e9efe2bf11fb495dbda4dae909198,
    # RC6
    0xeaad8e716b93d5a0d08ed1d0afc725e08e3c5b2f8e7594b78ff6e2fbf2122b648888b812900df01c4fad5ea0688fc31cd1cff191b3a8c1ad2f2f2218be0e1777ea752dfe8b021fa1e5a0cc0fb56f74e818acf3d6ce89e299b4a84fe0fd13e0b77cc43b81d2ada8d9165fa2668095770593cc7314211a1477e6ad206577b5fa86c75442f5fb9d35cfebcdaf0c7b3e89a0d6411bd3ae1e7e4900250e2d2071b35e,
    # RC7
    0x226800bb57b8e0af2464369bf009b91e5563911d59dfa6aa78c14389d95a537f207d5ba202e5b9c5832603766295cfa911c819684e734a41b3472dca7b14a94a1b5100529a532915d60f573fbc9bc6e42b60a47681e6740008ba6fb5571be91ff296ec6b2a0dd915b6636521e7b9f9b6ff34052ec585566453b02d5da99f8fa108ba47996e85076a4b7a70e9b5b32944db75092ec4192623ad6ea6b049a7df7d
]


# --- Setup Logging (copied from keccakround.py) ---
logger = logging.getLogger('TwinkleRoundF_in_ANF_form')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
# --- End Logging Setup ---


def index_xyz(x: int, y: int, z: int) -> int:
    """
    Calculate the index of coordinates (x, y, z) in the state array.
    
    *** LOGIC REVERTED: Using Slice-Major memory layout (as per user) ***
    Index: x + 4*y + 16*z
    
    Args:
        x: X coordinate (0-3)
        y: Y coordinate (0-3) 
        z: Z coordinate (0 to LANE_SIZE-1)
        
    Returns:
        Index in the state array
    """
    x, y, z = x % X_SIZE, y % Y_SIZE, z % LANE_SIZE
    # Slice-Major layout: S[•][•][z] are contiguous
    return x + X_SIZE*y + (X_SIZE*Y_SIZE)*z

def index_xy(x: int, y: int) -> int:
    """
    Calculate the index of coordinates (x, y) in a 16-bit slice.
    
    Args:
        x: X coordinate (0-3)
        y: Y coordinate (0-3)
        
    Returns:
        Index in the 16-bit slice (0-15)
    """
    x, y = x % X_SIZE, y % Y_SIZE
    return x + X_SIZE * y

def rotate_left_xy16(p: int, amount: int) -> int:
    """
    
    Args:
        p:  coordinate (0-15)
          
    Returns:
        Index in the 16-bit slice (0-15)
    """
    
    return (p - amount + 16) % 16

def SingleSbox_ANF(i0, i1, i2, i3) -> Tuple:
    """
    Apply 4-bit S-box transformation using pre-calculated ANF.
    Input bits are (i0, i1, i2, i3).
    Output bits are (o0, o1, o2, o3).

    ANF computed by designer's lookup table(x_0: MSB):
    y0 = x0*x2*x3 + x0*x3 + x0 + x1*x2 + x1*x3 + x2*x3
    y1 = x0*x1 + x0*x3 + x1 + x2
    y2 = x0*x1*x2 + x0 + x1*x3 + x1 + x2*x3 + x3
    y3 = x0 + x1*x2 + x2*x3 + x2 + x3
    
    """

    o0 = i0*i2*i3 + i0*i3 + i0 + i1*i2 + i1*i3 + i2*i3
    o1 = i0*i1 + i0*i3 + i1 + i2
    o2 = i0*i1*i2 + i0 + i1*i3 + i1 + i2*i3 + i3
    o3 = i0 + i1*i2 + i2*i3 + i2 + i3
    
    return o0, o1, o2, o3

def sbox_step(S: List) -> List:
    """
    Apply the S-box layer to the state.
    The S-box is applied vertically:
    S[0][y][z]...S[3][y][z] <- Sb(S[0][y][z]...S[3][y][z])
    
    *** LOGIC CHECKED: Correct for Slice-Major layout ***
    (Bits S[0,y,z] to S[3,y,z] are contiguous in memory)
    """
    S_out = [R(0) for _ in range(STATE_SIZE)]
    for y in range(Y_SIZE):
        for z in range(LANE_SIZE):
            # Get the 4 input bits from the vertical column
            # For Slice-Major, these are contiguous:
            # index(0,y,z) = 4*y + 16*z
            # index(1,y,z) = 1 + 4*y + 16*z
            # ...
            i0 = S[index_xyz(0, y, z)]
            i1 = S[index_xyz(1, y, z)]
            i2 = S[index_xyz(2, y, z)]
            i3 = S[index_xyz(3, y, z)]
            
            # Apply ANF S-box
            o0, o1, o2, o3 = SingleSbox_ANF(i0, i1, i2, i3)
            
            # Set the 4 output bits back
            S_out[index_xyz(0, y, z)] = o0
            S_out[index_xyz(1, y, z)] = o1
            S_out[index_xyz(2, y, z)] = o2
            S_out[index_xyz(3, y, z)] = o3
            
    return S_out

def rotate_lane_right(lane: List, amount: int) -> List:
    """
    Apply cyclic right shift (>>) to a single lane.
    (Loop implementation based on user feedback)
    """
    l_size = len(lane)
    if l_size == 0:
        return []
    amount = amount % l_size
    Y = []
    for i in range(l_size):
        Y.append(lane[(i + amount + l_size) % l_size])
    return Y

def lane_rotation0(S: List) -> List:
    """
    Apply the LaneRotation0 step.
    S[x][y][•] ← S[x][y][•] ≫ (O0[x + 4y] mod l)
    
    *** LOGIC REVERTED: Using Gather-Rotate-Scatter for Slice-Major layout ***
    (Lane S[x,y,•] is non-contiguous)
    """
    S_out = S[:]  # Start with a copy
    for y in range(Y_SIZE):
        for x in range(X_SIZE):
            lane_k = index_xy(x, y) # k = x + 4y
            shift_amount = O0[lane_k] % LANE_SIZE
            
            # 1. Extract current lane (List Comprehension for non-contiguous gather)
            # index(x,y,in_z) = (x+4y) + 16*in_z
            current_lane = [S[index_xyz(x, y, in_z)] for in_z in range(LANE_SIZE)]
            
            # 2. Rotate it
            rotated_lane = rotate_lane_right(current_lane, shift_amount)
            
            # 3. Place it back into the output state (Scatter)
            for in_z in range(LANE_SIZE):
                S_out[index_xyz(x, y, in_z)] = rotated_lane[in_z]
            
    return S_out

def rotate_slice_left(slice_16bit: List, amount: int) -> List:
    """
    Apply cyclic left shift (<<) to a 16-bit slice.
    (Loop implementation based on user feedback)
    """
    l_size = len(slice_16bit) # Should be 16
    if l_size == 0:
        return []
    amount = amount % l_size
    Y = []
    for i in range(l_size):
        Y.append(slice_16bit[(i - amount) % l_size])
    return Y

def mix_slice(S: List) -> List:
    """
    Apply the MixSlice diffusion layer.
    S[•][•][z] ← S[•][•][z] ⊕ (S[•][•][z] ≪ 5) ⊕ (S[•][•][z] ≪ 12)
    
    *** LOGIC CHECKED: Correct for Slice-Major layout ***
    (Slice S[•,•,z] is contiguous)
    """
    S_out = [R(0) for _ in range(STATE_SIZE)]
    for z in range(LANE_SIZE):
        # 1. Extract the 16-bit slice (contiguous)
        slice_start = index_xyz(0, 0, z)
        slice_in = S[slice_start : slice_start + 16]
        
        # 2. Get rotated versions
        slice_rot5 = rotate_slice_left(slice_in, 5)
        slice_rot12 = rotate_slice_left(slice_in, 12)
        
        # 3. Calculate output slice (XOR = + in ANF ring)
        slice_out = [R(0) for _ in range(16)]
        for i in range(16):
            slice_out[i] = slice_in[i] + slice_rot5[i] + slice_rot12[i]
            
        # 4. Write the output slice back (contiguous)
        for i in range(16):
            S_out[slice_start + i] = slice_out[i]
                
    return S_out

def lane_rotation1(S: List) -> List:
    """
    Apply the LaneRotation1 step.
    S[x][y][•] ← S[x][y][•] ≫ (O1[x + 4y] mod l)
    
    *** LOGIC REVERTED: Using Gather-Rotate-Scatter for Slice-Major layout ***
    (Lane S[x,y,•] is non-contiguous)
    """
    S_out = S[:]  # Start with a copy
    for y in range(Y_SIZE):
        for x in range(X_SIZE):
            lane_k = index_xy(x, y) # k = x + 4y
            shift_amount = O1[lane_k] % LANE_SIZE
            
            # 1. Extract current lane (List Comprehension for non-contiguous gather)
            # index(x,y,in_z) = (x+4y) + 16*in_z
            current_lane = [S[index_xyz(x, y, in_z)] for in_z in range(LANE_SIZE)]
            
            # 2. Rotate it
            rotated_lane = rotate_lane_right(current_lane, shift_amount)
            
            # 3. Place it back into the output state (Scatter)
            for in_z in range(LANE_SIZE):
                S_out[index_xyz(x, y, in_z)] = rotated_lane[in_z]
            
    return S_out

def add_constant(S: List, r: int) -> List:
    """
    Add round constant (AC step).
    
    Modified as per user request:
    XOR the entire state S (STATE_SIZE bits) with the r-th round constant.
    
    *** LOGIC CHECKED: Correct for any layout ***
    (Iterates flat memory)
    """
    if not TWINKLE_ROUND_CONSTANTS:
        # Silently return state unmodified if no constants are defined
        return S
        
    if r >= len(TWINKLE_ROUND_CONSTANTS):
        raise ValueError(f"Round number {r} exceeds constant list {len(TWINKLE_ROUND_CONSTANTS)-1}")
    
    constant = TWINKLE_ROUND_CONSTANTS[r]
    
    # XOR the entire state (STATE_SIZE bits) with the constant
    # Assumes STATE_SIZE (e.g., 256) bits are used from the constant
 
    for i in range(STATE_SIZE):
        if (constant >> i) & 0x1:
            S[i] += 1  # XOR with 1
     
    return S

def twinkle_round(S: List, r_num: int) -> List:
    """
    Apply a single round of the Twinkle permutation R.
    R = AC ◦ LaneRotation1 ◦ MixSlice ◦ LaneRotation0 ◦ S-box
    
    This means the steps are applied in the following order:
    1. S-box
    2. LaneRotation0
    3. MixSlice
    4. LaneRotation1
    5. AddConstant
    """
    # 1. S-box
    S = sbox_step(S)
    
    # 2. LaneRotation0
    S = lane_rotation0(S)
    
    # 3. MixSlice
    S = mix_slice(S)
    
    # 4. LaneRotation1
    S = lane_rotation1(S)
    
    # 5. AddConstant (AC)
    S = add_constant(S, r_num)
    
    return S

def apply_rounds(S: List, num_rounds: int) -> List:
    """
    Apply a specified number of Twinkle rounds.
    """
    for i in range(num_rounds):
        S = twinkle_round(S, i)
    return S

def compression_fo(S: List, n: int) -> List:
    """
    Apply the compression operation FO (final output) based on STATE_SIZE.
    
    If STATE_SIZE >= 256:
        O <- Trunc(S ⊕ (S >> 128), n), where n in [1, STATE_SIZE - 128]
    Otherwise (STATE_SIZE < 256):
        O <- Trunc(S, n), where n in [1, STATE_SIZE] (Assumed range)
    
    *** LOGIC CHECKED: Correct for any layout ***
    (Operates on flat memory)
    
    Args:
        S: The final state list (STATE_SIZE bits).
        n: The desired output length (number of least significant bits).
        
    Returns:
        A list of n output bits.
    """
    
    if STATE_SIZE >= 256:
        # Case 1: "PA" (1280) and "PA-lw1" (256)
        max_n = STATE_SIZE - 128
        if not (1 <= n <= max_n):
            raise ValueError(f"For STATE_SIZE >= 256, output length n must be between 1 and {max_n}. Got n = {n}.")
        
        # 1. Create S_shifted = S >> 128 (CYCLIC right shift)
        S_shifted = rotate_lane_right(S, 128)
        
        # 2. Calculate S_xor = S ⊕ S_shifted
        S_xor = [R(0) for _ in range(STATE_SIZE)]
        for i in range(STATE_SIZE):
            S_xor[i] = S[i] + S_shifted[i]  # + is XOR in ANF ring
            
        # 3. Truncate to the least significant n bits
        O = S_xor[0:n]
        
    else:
        # Case 2: "PA-lw2" (128)
        # Assumed valid range for n is [1, STATE_SIZE]
        max_n = STATE_SIZE
        if not (1 <= n <= max_n):
            raise ValueError(f"For STATE_SIZE < 256, output length n must be between 1 and {max_n}. Got n = {n}.")

        # 1. Truncate S directly
        O = S[0:n]
    
    return O

def print_state(X: List) -> None:
    """
    Pretty-print the Twinkle state in hexadecimal form, one 16-bit slice
    at a time, as requested by the user.

    *** LOGIC UPDATED: Prints Slices (16-bit) instead of Lanes ***
    """
    
    SLICE_SIZE = X_SIZE * Y_SIZE # 16 bits
    SLICES_PER_LINE = 8 # Number of 16-bit hex values per line
    
    print(f"--- Twinkle State (Slice View, {LANE_SIZE} slices of {SLICE_SIZE}-bits each) ---")
    
    row_print = ""
    for z in range(LANE_SIZE):
        # 1. Get the contiguous 16-bit slice
        # index(0,0,z) = 16*z
        slice_start = index_xyz(0, 0, z) 
        slice_binary = X[slice_start : slice_start + SLICE_SIZE]
        
        # 2. Convert to hex
        slice_hex = _convert_binary_to_hex_str(slice_binary)
        
        # 3. Append to row
        row_print += slice_hex + " "
        
        # 4. Print line if full or if it's the last slice
        if (z + 1) % SLICES_PER_LINE == 0 or (z + 1) == LANE_SIZE:
            print(f"Slices {z - (z % SLICES_PER_LINE):>3} - {z:>3}: {row_print}")
            row_print = ""
    print("------")


def _convert_binary_to_hex_str(binary_list: List) -> str:
    """
    Internal helper to convert a list of bits (0/1 or symbolic)
    to a hex string, following the Keccak print logic.
    (LSB-first bits to MSB-first hex string)
    """
    num_bits = len(binary_list)
    if num_bits % 8 != 0:
        return "[Error: Bit length not multiple of 8]"

    state_hex = ""
    num_bytes = num_bits // 8
    for k in range(num_bytes):
        tmp = 0
        for bit in range(8):
            bit_val = binary_list[k * 8 + bit]
            try:
                bit_val = int(bit_val)
            except (TypeError, ValueError):
                return "[Symbolic ANF]"
            tmp += (bit_val << bit)
        
        # Prepend the byte to build the MSB-first string
        state_hex = hex(tmp)[2:].zfill(2) + state_hex
    
    return "0x" + state_hex


def print_trunc_state(bit_list: List) -> None:
    """
    Prints an arbitrary truncated bit list in a hex format, one 16-bit
    slice at a time, as requested by the user.
    
    *** LOGIC UPDATED: Prints Slices (16-bit) instead of Lanes ***
    """
    
    n = len(bit_list)
    SLICE_SIZE = X_SIZE * Y_SIZE # 16
    SLICES_PER_LINE = 8 # Same as print_state
    
    # Check if length is a multiple of slice size
    if n % SLICE_SIZE != 0:
        logger.warning(f"Output size {n} is not a multiple of slice size {SLICE_SIZE}.")
        # Fallback to just printing all bytes in one line
        if n % 8 == 0:
            print(_convert_binary_to_hex_str(bit_list))
        else:
            logger.error(f"Output size {n} is not a multiple of 8. Cannot print hex.")
        print("------")
        return

    num_slices = n // SLICE_SIZE
    row_print = ""
    
    for z in range(num_slices):
        # 1. Get the 16-bit slice
        slice_start = z * SLICE_SIZE
        slice_binary = bit_list[slice_start : slice_start + 16]
        
        # 2. Convert to hex
        slice_hex = _convert_binary_to_hex_str(slice_binary)
        
        # 3. Append to row
        row_print += slice_hex + " "
        
        # 4. Print line if full or if it's the last slice
        if (z + 1) % SLICES_PER_LINE == 0 or (z + 1) == num_slices:
            print(f"Slices {z - (z % SLICES_PER_LINE):>3} - {z:>3}: {row_print}")
            row_print = ""
    print("------")


def hex_list_to_bit_list(hex_list: List[int], lanesize:int) -> List[int]:
    """
    Convert a list of integers into a contiguous list of bits (0/1).
    Adapted from keccakround.py.

    Bit order per integer word:
    - LSB → MSB within each word (i.e., bit 0 first).

    Args:
        hex_list: list of integers (e.g., [0x1b, 0x8082, ...])
        lanesize: number of bits to extract per integer
        
    Returns:
        A list of bits (integers 0/1) representing the concatenation of all
        provided integers in LSB-first order per word.
    """
    bit_list: List[int] = []
    # Create a mask for the specified lanesize
    mask = (1 << lanesize) - 1
    
    for val in hex_list:
        word = int(val) & mask
        for k in range(lanesize):
            bit_list.append((word >> k) & 0x1)
    return bit_list


def _apply_sigma_permutation(iv_bits: List[int], a: int, b: int) -> List[int]:
    """
    Apply affine position permutation σ: j -> (a*j + b) mod 128 on 128 input bits.

    Args:
        iv_bits: 128 bits, LSB-first order.
        a, b: parameters of σ.

    Returns:
        Permuted 128-bit list (same LSB-first semantics; bit j maps to position σ(j)).
    """
    if len(iv_bits) != 128:
        raise ValueError(f"iv_bits must have length 128, got {len(iv_bits)}")
    out_bits: List[int] = [0] * 128
    for j in range(128):
        mapped = (a * j + b) % 128
        out_bits[mapped] = iv_bits[j]
    return out_bits


def input_expansion_fi(iv_bits: List[int]) -> List[int]:
    """
    Input expansion FI: expand a 128-bit IV into a 1280-bit state S.

    Definition:
      - Use 10 permutations σ_i (i=0..9), each defined as j -> (a_i * j + b_i) mod 128.
      - S <- Pσ9·IV || ... || Pσ0·IV, where Pσ0·IV occupies the least significant 128 bits of S.

    This implementation uses an internal LSB-first bit order. The returned list stores
    Pσ0·IV at indices 0..127, Pσ1·IV at 128..255, and so on up to Pσ9·IV, totaling 1280 bits.

    Args:
        iv_bits: A 128-bit list of bits (0/1), LSB-first.

    Returns:
        A 1280-bit list of bits (LSB-first concatenation).
    """
    if len(iv_bits) != 128:
        raise ValueError(f"iv_bits must have length 128, got {len(iv_bits)}")

    # Table 3 parameters (σ_i coefficients)
    SIGMA_A: List[int] = [1, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    SIGMA_B: List[int] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    S: List[int] = []
    num_per = LANE_SIZE //8  # 10 permutations for 1280 bits
    # Per spec, σ0 occupies the least significant 128 bits; append i = 0..9 in order
    for i in range(num_per):
        permuted = _apply_sigma_permutation(iv_bits, SIGMA_A[i], SIGMA_B[i])
        S.extend(permuted)

    if len(S) != STATE_SIZE:
        raise RuntimeError(f"FI expansion length must be {STATE_SIZE} bits.")
    return S

def observe_input_expansion():
    global R
    R = declare_ring([Block('v', 128)], globals())
    # Example IV in hex (16 bytes = 128 bits)
    IV_in = [R(v(i)) for i in range(128)]
    
    # Apply FI expansion
    S = input_expansion_fi(IV_in)
    
    # Print the resulting state S in groups of 4 elements per line
    logger.info("Input Expansion FI Resulting State S (4 elements per line):")
    for i in range(0, len(S), 4):
        group = S[i:i+4]
        print(" ".join(str(elem) for elem in group))

    print(S)

def test_twinkle():
    # Initialize polynomial ring for ANF representation
    # This makes variables x_0, x_1, ..., x_{STATE_SIZE-1} globally available
    global R
    R = declare_ring([Block('x', STATE_SIZE)], globals())
    

    # --- Test all-zero state (concrete test) ---
    logger.info("--- Testing all-zero state through 5 rounds ---")
    # Create a concrete state of all zeros
    S_zero = [R(0) for _ in range(STATE_SIZE)]
    S_zero_out = apply_rounds(S_zero, 5)
    print(S_zero_out)
    logger.info("State after 5 rounds (all-zero input):")
    print_state(S_zero_out)
    
    # --- Test Compression Function FO ---
    # This test will now run for all variants, exercising the new logic
    logger.info("--- Testing compression function FO ---")
    try:
        # Test with 32 bits. This is valid for all variants
        # PA: 32 in [1, 1152]
        # PA-lw1: 32 in [1, 128]
        # PA-lw2: 32 in [1, 128]
        if SELECTED_VARIANT == "PA":
            output_bits_n = 1152
        elif SELECTED_VARIANT == "PA-lw1":
            output_bits_n = 128
        else: # PA-lw2
            output_bits_n = 128
            
        O = compression_fo(S_zero_out, output_bits_n)
        print(O)
        # Use the new print function
        logger.info(f"FO output (n={output_bits_n}) from all-zero 5-round state (Variant: {SELECTED_VARIANT}):")
        print_trunc_state(O)
        
        logger.info("Compression function test PASSED.")
    except Exception as e:
        logger.error(f"Compression function test FAILED with error: {e}")

    
    # --- Symbolic ANF Generation (Commented Out) ---
    # logger.info("--- Generating symbolic ANF for 1 round ---")
    # S_in = [R.gen(i) for i in range(STATE_SIZE)]
    # S_out = apply_rounds(S_in, 1)
    # logger.info("1 round applied. ANF of output bit S_out[0]:")
    # print(S_out[0])

def analysis_linearize_sbox():
    global R
    R = declare_ring([Block('v', 4)], globals())
    print(f"v0: {R(v(0))}")
    for i in range(8):
        x1 = (i >> 2) & 1
        x2 = (i >> 1) & 1
        x3 = i & 1
        w0, w1, w2, w3 = SingleSbox_ANF( R(v(0)), R(x1), R(x2), R(x3))
        print(f"{R(v(0))}, {x1}, {x2}, {x3}  ====> {w0}, {w1}, {w2},  {w3}")

    print("="*60)
    print(f"v1: {R(v(1))}")
    for i in range(8):
        x1 = (i >> 2) & 1
        x2 = (i >> 1) & 1
        x3 = i & 1
        w0, w1, w2, w3 = SingleSbox_ANF( R(x1), R(v(1)),R(x2), R(x3))
        print(f"{x1},{R(v(1))}, {x2}, {x3}  ====> {w0}, {w1}, {w2},  {w3}")
   
    print("="*60)
    print(f"v2: {R(v(2))}")
    for i in range(8):
        x1 = (i >> 2) & 1
        x2 = (i >> 1) & 1
        x3 = i & 1 
        w0, w1, w2, w3 = SingleSbox_ANF( R(x1), R(x2), R(v(2)), R(x3))
        print(f"{x1}, {x2},{R(v(2))}, {x3}  ====> {w0}, {w1}, {w2},  {w3}")


    print("="*60)
    print(f"v3: {R(v(3))}")
    for i in range(8):
        x1 = (i >> 2) & 1
        x2 = (i >> 1) & 1
        x3 = i & 1
        w0, w1, w2, w3 = SingleSbox_ANF( R(x1), R(x2), R(x3), R(v(3)))
        print(f"{x1}, {x2}, {x3},{R(v(3))}  ====> {w0}, {w1}, {w2},  {w3}")

def interactionofIV0_Aux_Invkey():
    global R
    # R = declare_ring([Block('k', 4*rounds*STATE_SIZE + STATE_SIZE), Block('v', 4*rounds*STATE_SIZE + STATE_SIZE)], globals())
    R = declare_ring([Block('v', 4), Block('k', 4)], globals())
    """
    a_vars[i] --Sbox--> b_vars[i] --LR0--> c_vars[i] --MS--> d_vars[i] --LR1--AC--> a_vars[i+1] 

    """
    
    for i in range(8):
        print("="*60)
        v1, v2, v3 = R((i >> 2) & 1), R((i >> 1) & 1), R(i & 1)
        v0 = R(v(0))
        v_list = [v0, v1, v2, v3]
        
        # Original input/output
        inputs = [v0, v1 + R(k(1)), v2 + R(k(2)), v3 + R(k(3))]
        w0, w1, w2, w3 = SingleSbox_ANF(*inputs)
        print(f"INput: {inputs}\nOUTput: {w0}, {w1}, {w2}, {w3}")
    
        # Check all auxiliary variables vi = ka_val + kb_val for i=1,2,3
        # Key combination patterns: (k1, k2), (k2, k3), (k1, k3)
        key_patterns = [
            # (1, 2, "k1_val + k2_val"),  # vi = k1 + k2
            (2, 3, "k2_val + k3_val"),  # vi = k2 + k3
            # (1, 3, "k1_val + k3_val"),  # vi = k1 + k3
        ]
        
        for aux_idx in [2]:
            for ka_idx, kb_idx, pattern_name in key_patterns:
                print(f"Adding Auxiable Vars v{aux_idx} = {pattern_name}")
                for j in range(4):
                    ka_val = R((j >> 1) & 1)
                    kb_val = R(j & 1)
                    
                    if ka_val + kb_val == v_list[aux_idx]:
                        # Build input with auxiliary variable constraint
                        # Original: [v0, v1 + k(1), v2 + k(2), v3 + k(3)]
                        inputs_aux = [v0, v1 + R(k(1)), v2 + R(k(2)), v3 + R(k(3))]
                        
                        # Fix the keys according to the pattern
                        inputs_aux[ka_idx] = v_list[ka_idx] + ka_val
                        inputs_aux[kb_idx] = v_list[kb_idx] + kb_val
                        
                        w0, w1, w2, w3 = SingleSbox_ANF(*inputs_aux)
                        
                        # Collect quadratic terms
                        quadratic_terms = [(f"w{idx}", m) for idx, w in enumerate([w0, w1, w2, w3]) 
                                           for m in w.monomials() if m.deg() == 2]
                        
                        # Build key display string
                        key_display = ["freek0"]
                        for k_idx in [1, 2, 3]:
                            if k_idx == ka_idx:
                                key_display.append(str(ka_val))
                            elif k_idx == kb_idx:
                                key_display.append(str(kb_val))
                            else:
                                key_display.append(str(R(k(k_idx))))
                        
                        print(f"Aux var: v{aux_idx} = {pattern_name}")
                        print(f"\tkeys: {', '.join(key_display)}")
                        print(f"\tinput: {inputs_aux}\n\toutput: {w0}, {w1}, {w2}, {w3}")
                        print(f"\tInvolved Keys {quadratic_terms}")

def interactionofIV1_Aux_Invkey():
    global R
    # R = declare_ring([Block('k', 4*rounds*STATE_SIZE + STATE_SIZE), Block('v', 4*rounds*STATE_SIZE + STATE_SIZE)], globals())
    R = declare_ring([Block('v', 4), Block('k', 4)], globals())
    """
    a_vars[i] --Sbox--> b_vars[i] --LR0--> c_vars[i] --MS--> d_vars[i] --LR1--AC--> a_vars[i+1] 

    """
    
    for i in range(8):
        print("="*60)
        v0, v2, v3 = R((i >> 2) & 1), R((i >> 1) & 1), R(i & 1)
        v1 = R(v(1))
        v_list = [v0, v1, v2, v3]
        
        # Original input/output
        inputs = [v0 + R(k(0)), v1, v2 + R(k(2)), v3 + R(k(3))]
        w0, w1, w2, w3 = SingleSbox_ANF(*inputs)
        print(f"INput: {inputs}\nOUTput: {w0}, {w1}, {w2}, {w3}")
    
        # Check all auxiliary variables vi = ka_val + kb_val for i=1,2,3
        # Key combination patterns: (k1, k2), (k2, k3), (k1, k3)
        key_patterns = [
            # (0, 2, "k0_val + k2_val"),  # vi = k1 + k2
            # (2, 3, "k2_val + k3_val"),  # vi = k2 + k3
            (0, 3, "k0_val + k3_val"),  # vi = k1 + k3
        ]
        
        for aux_idx in [0]:
            for ka_idx, kb_idx, pattern_name in key_patterns:
                print(f"Adding Auxiable Vars v{aux_idx} = {pattern_name}")
                for j in range(4):
                    ka_val = R((j >> 1) & 1)
                    kb_val = R(j & 1)
                    
                    if ka_val + kb_val == v_list[aux_idx]:
                        # Build input with auxiliary variable constraint
                        # Original: [v0, v1 + k(1), v2 + k(2), v3 + k(3)]
                        inputs_aux = [v0 + R(k(0)), v1, v2 + R(k(2)), v3 + R(k(3))]
                        
                        # Fix the keys according to the pattern
                        inputs_aux[ka_idx] = v_list[ka_idx] + ka_val
                        inputs_aux[kb_idx] = v_list[kb_idx] + kb_val
                        
                        w0, w1, w2, w3 = SingleSbox_ANF(*inputs_aux)
                        
                        # Collect quadratic terms
                        quadratic_terms = [(f"w{idx}", m) for idx, w in enumerate([w0, w1, w2, w3]) 
                                           for m in w.monomials() if m.deg() == 2]
                        
                        print(f"Aux var: v{aux_idx} = {pattern_name}")
                        print(f"\tinput: {inputs_aux}\n\toutput: {w0}, {w1}, {w2}, {w3}")
                        print(f"\tInvolved Keys {quadratic_terms}")

def interactionofIV2_Aux_Invkey():
    global R
    # R = declare_ring([Block('k', 4*rounds*STATE_SIZE + STATE_SIZE), Block('v', 4*rounds*STATE_SIZE + STATE_SIZE)], globals())
    R = declare_ring([Block('v', 4), Block('k', 4)], globals())
    """
    a_vars[i] --Sbox--> b_vars[i] --LR0--> c_vars[i] --MS--> d_vars[i] --LR1--AC--> a_vars[i+1] 

    """
    
    for i in range(8):
        print("="*60)
        v0, v1, v3 = R((i >> 2) & 1), R((i >> 1) & 1), R(i & 1)
        v2 = R(v(2))
        v_list = [v0, v1, v2, v3]
        
        # Original input/output
        inputs = [v0 + R(k(0)), v1 + R(k(1)), v2, v3 + R(k(3))]
        w0, w1, w2, w3 = SingleSbox_ANF(*inputs)
        print(f"INput: {inputs}\nOUTput: {w0}, {w1}, {w2}, {w3}")
    
        # Check all auxiliary variables vi = ka_val + kb_val for i=1,2,3
        # Key combination patterns: (k1, k2), (k2, k3), (k1, k3)
        key_patterns = [
            # (0, 1, "k0_val + k1_val"),  # vi = k1 + k2
            # (1, 3, "k1_val + k3_val"),  # vi = k2 + k3
            (0, 3, "k0_val + k3_val"),  # vi = k1 + k3
        ]
        
        for aux_idx in [0]:
            for ka_idx, kb_idx, pattern_name in key_patterns:
                print(f"Adding Auxiable Vars v{aux_idx} = {pattern_name}")
                for j in range(4):
                    ka_val = R((j >> 1) & 1)
                    kb_val = R(j & 1)
                    
                    if ka_val + kb_val == v_list[aux_idx]:
                        # Build input with auxiliary variable constraint
                        # Original: [v0, v1 + k(1), v2 + k(2), v3 + k(3)]
                        inputs_aux = [v0 + R(k(0)), v1 + R(k(1)), v2, v3 + R(k(3))]
                        
                        # Fix the keys according to the pattern
                        inputs_aux[ka_idx] = v_list[ka_idx] + ka_val
                        inputs_aux[kb_idx] = v_list[kb_idx] + kb_val
                        
                        w0, w1, w2, w3 = SingleSbox_ANF(*inputs_aux)
                        
                        # Collect quadratic terms
                        quadratic_terms = [(f"w{idx}", m) for idx, w in enumerate([w0, w1, w2, w3]) 
                                           for m in w.monomials() if m.deg() == 2]
                        
                        print(f"Aux var: v{aux_idx} = {pattern_name}")
                        print(f"\tinput: {inputs_aux}\n\toutput: {w0}, {w1}, {w2}, {w3}")
                        print(f"\tInvolved Keys {quadratic_terms}")
 
def interactionofIV3_Aux_Invkey():
    global R
    # R = declare_ring([Block('k', 4*rounds*STATE_SIZE + STATE_SIZE), Block('v', 4*rounds*STATE_SIZE + STATE_SIZE)], globals())
    R = declare_ring([Block('v', 4), Block('k', 4)], globals())
    """
    a_vars[i] --Sbox--> b_vars[i] --LR0--> c_vars[i] --MS--> d_vars[i] --LR1--AC--> a_vars[i+1] 

    """
    
    for i in range(8):
        print("="*60)
        v0, v1, v2 = R((i >> 2) & 1), R((i >> 1) & 1), R(i & 1)
        v3 = R(v(3))
        v_list = [v0, v1, v2, v3]
        
        # Original input/output
        inputs = [v0 + R(k(0)), v1 + R(k(1)), v2 + R(k(2)), v3]
        w0, w1, w2, w3 = SingleSbox_ANF(*inputs)
        print(f"INput: {inputs}\nOUTput: {w0}, {w1}, {w2}, {w3}")
    
        # Check all auxiliary variables vi = ka_val + kb_val for i=1,2,3
        # Key combination patterns: (k1, k2), (k2, k3), (k1, k3)
        key_patterns = [
            # (0, 1, "k0_val + k1_val"),  # vi = k1 + k2
            # (1, 2, "k1_val + k2_val"),  # vi = k2 + k3
            (0, 2, "k0_val + k2_val"),  # vi = k1 + k3
        ]
        
        for aux_idx in [0]:
            for ka_idx, kb_idx, pattern_name in key_patterns:
                print(f"Adding Auxiable Vars v{aux_idx} = {pattern_name}")
                for j in range(4):
                    ka_val = R((j >> 1) & 1)
                    kb_val = R(j & 1)
                    
                    if ka_val + kb_val == v_list[aux_idx]:
                        # Build input with auxiliary variable constraint
                        # Original: [v0, v1 + k(1), v2 + k(2), v3 + k(3)]
                        inputs_aux = [v0 + R(k(0)), v1 + R(k(1)), v2 + R(k(2)), v3]
                        
                        # Fix the keys according to the pattern
                        inputs_aux[ka_idx] = v_list[ka_idx] + ka_val
                        inputs_aux[kb_idx] = v_list[kb_idx] + kb_val
                        
                        w0, w1, w2, w3 = SingleSbox_ANF(*inputs_aux)
                        
                        # Collect quadratic terms
                        quadratic_terms = [(f"w{idx}", m) for idx, w in enumerate([w0, w1, w2, w3]) 
                                           for m in w.monomials() if m.deg() == 2]
                        
                        print(f"Aux var: v{aux_idx} = {pattern_name}")
                        print(f"\tinput: {inputs_aux}\n\toutput: {w0}, {w1}, {w2}, {w3}")
                        print(f"\tInvolved Keys {quadratic_terms}")
 

def ANF_Twinkle():
    global R
    R = declare_ring([Block('x', 128),Block('k', STATE_SIZE)], globals())
    
    IV = [R(x(i)) for i in range(128)]
    for Z in range(8):
        IV[index_xyz(0,0,Z)] = R(0)
        IV[index_xyz(0,1,Z)] = R(0)
        IV[index_xyz(0,2,Z)] = R(0)
    IV[index_xyz(0,3,0)] = R(0)
    IV[index_xyz(0,3,1)] = R(0)
    print(IV)
         

    k1 = [R(k(i)) for i in range(STATE_SIZE)]
    k2 = [R(0) for _ in range(STATE_SIZE)]
    rotate_offset1 = rotate_lane_right(k1, 1)
    # rotate_offset2 = rotate_lane_right(k1, STATE_SIZE -1)
    # for i in range(STATE_SIZE):
    # k2[i] = rotate_offset1[i] + rotate_offset2[i]
    
    S = input_expansion_fi(IV)
    for i in range(STATE_SIZE):
        S[i] = S[i] + k1[i]
    S = apply_rounds(S, 1)
    # for i in range(STATE_SIZE):
    #     S[i] = S[i] + k2[i]
    # S_out = compression_fo(S, 1152)
    logger.info("State after 3 rounds from IV:")
    for i in range(STATE_SIZE):
        print(f"S[{i}] = {S[i]}")


   
if __name__ == '__main__':
    # test_twinkle()
    logger.info("Twinkle Round Function in ANF form")
    logger.info(f"Selected Variant: {SELECTED_VARIANT}")
    logger.info(f"State size: {STATE_SIZE} bits (X={X_SIZE}, Y={Y_SIZE}, L={LANE_SIZE})")
    logger.info(f"Loaded {len(TWINKLE_ROUND_CONSTANTS)} round constants.")

    # interactionofIV0_Aux_Invkey()
    # observe_input_expansion()
    # ANF_Twinkle()
    # test_twinkle()
   
