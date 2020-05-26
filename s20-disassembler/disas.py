#!/usr/bin/env/python3
"""disas.py
   Author: Brian Jopling, May 2020
   Usage: disas.py
"""


#############
#  IMPORTS  #
#############

import sys


#############
#  GLOBALS  #
#############

# Counter for variable names
data_count = 0
skip_count = 0

IS_DEBUG = False

S20_OUTPUT_FILE = "sample.hex"

S20_BITS = 24
# 6 nibbles (4 bits * 6 nibbles = 24 bits) per instruction
S20_NUM_INSTR_NIBBLES = 6

INSTR_SET = {
    "OP_CODE": {
        "1": {
            "SUB_OP_CODE": {
                None: {
                    "INSTRUCTION": "ld"
                }
            }
        },
        "2": {
            "SUB_OP_CODE": {
                None: {
                    "INSTRUCTION": "st"
                }
            }
        },
        "3": {
            "SUB_OP_CODE": {
                None: {
                    "INSTRUCTION": "br"
                }
            }
        },
        "4": {
            "SUB_OP_CODE": {
                None: {
                    "INSTRUCTION": "bsr"
                }
            }
        },
        "5": {
            "SUB_OP_CODE": {
                None: {
                    "INSTRUCTION": "brz"
                }
            }
        },
        "6": {
            "SUB_OP_CODE": {
                None: {
                    "INSTRUCTION": "bnz"
                }
            }
        },
        "7": {
            "SUB_OP_CODE": {
                None: {
                    "INSTRUCTION": "brn"
                }
            }
        },
        "8": {
            "SUB_OP_CODE": {
                None: {
                    "INSTRUCTION": "bnn"
                }
            }
        },
        "0": {
            "SUB_OP_CODE": {
                "00": {
                    "INSTRUCTION": "nop"
                },
                "01": {
                    "INSTRUCTION": "ldi"
                },
                "02": {
                    "INSTRUCTION": "sti"
                },
                "03": {
                    "INSTRUCTION": "add"
                },
                "04": {
                    "INSTRUCTION": "sub"
                },
                "05": {
                    "INSTRUCTION": "and"
                },
                "06": {
                    "INSTRUCTION": "or"
                },
                "07": {
                    "INSTRUCTION": "xor"
                },
                "08": {
                    "INSTRUCTION": "shl"
                },
                "09": {
                    "INSTRUCTION": "sal"
                },
                "0A": {
                    "INSTRUCTION": "shr"
                },
                "0B": {
                    "INSTRUCTION": "sar"
                },
                "10": {
                    "INSTRUCTION": "rts"
                },
                "1F": {
                    "INSTRUCTION": "halt"
                },
            }
        },

    }
}

INSTR_WITH_NO_REGISTERS = ["halt", "rts", "nop"]
INSTR_WITH_SUM_REGISTERS = ["ldi", "sti"]
INSTR_WITH_SHIFT = ["shl", "sal", "shr", "sar"]
INSTR_WITH_BRANCH = ["br", "bsr", "brz", "bnz", "brn", "bnn"]


###############
#   CLASSES   #
###############


class FileService:
    def __init__(self):
        print_debug("Creating FileService...")
        print_debug("Successful init of FileService")

    def get_content_from_file(self):
        """Parses content of S20 output file."""
        try:
            file = open(S20_OUTPUT_FILE, "r")
            content = file.read().replace(" ", "").replace("\n", "")
            file.close()
        except:
            error_quit("Failed to read from file %s" % S20_OUTPUT_FILE, 403)
        return content


###############
#  FUNCTIONS  #
###############


def usage():
    """Prints the usage/help message for this program."""
    program_name = sys.argv[0]
    print("\nUsage:")
    print("\t%s" % program_name)
    print("\tFile \"%s\" must exist and be populated with S20 hex code." % S20_OUTPUT_FILE)


def error_quit(msg, code):
    """Prints out an error message, the program usage, and terminates with an
       error code of `code`."""
    print("\n[!] %s" % msg)
    usage()
    sys.exit(code)


def print_debug(msg):
    """Prints if we are in debug mode."""
    if IS_DEBUG:
        print(msg)


def get_instruction(op_code, sub_op_code=None):
    """Lookup corresponding assembly language instr given an opcode and sub opcode"""
    has_sub_op_code = op_code_has_sub_op_code(op_code)
    if not has_sub_op_code:
        return INSTR_SET["OP_CODE"][op_code]["SUB_OP_CODE"][None]["INSTRUCTION"]
    else:
        return INSTR_SET["OP_CODE"][op_code]["SUB_OP_CODE"][sub_op_code.upper()]["INSTRUCTION"]


def hex_to_binary(str_hex):
    """Convert hexadecimal string to binary string"""
    str_bin = bin(int(str_hex, 16))[2:]
    str_bin = str_bin.zfill(24)  # Pad with zeroes until 24 chars long
    return str_bin


def binary_to_hex(str_bin):
    """Convert binary string to hexadecimal string"""
    return hex(int(str_bin, 2))[2:]


def get_op_code(bits):
    """Opcode defined as first 4 bits of binary"""
    op_code_bits = 4
    bin_op_code = bits[0:op_code_bits]
    hex_op_code = binary_to_hex(bin_op_code)
    return hex_op_code


def op_code_has_sub_op_code(op_code):
    """Returns True or False depending on whether or not a given opcode has a sub opcode"""
    return list(INSTR_SET["OP_CODE"][op_code]["SUB_OP_CODE"].keys())[0] is not None


def get_sub_op_code(op_code, bits):
    """Sub Opcode defined as last 5 bits of binary, if opcode is 0"""
    has_sub_op_code = op_code_has_sub_op_code(op_code)
    sub_op_code = None
    if has_sub_op_code:
        sub_op_code_bits = 5  # Last 5 bits of binary
        bin_sub_op_code = bits[-sub_op_code_bits:]  # Get the last 5 bits of the binary str
        sub_op_code = binary_to_hex(bin_sub_op_code).zfill(2)  # Pad to two chars
    return sub_op_code


def get_register_number(reg_bits):
    """Converts binary bits to decimal number and uses this as the register number"""
    # e.g. 00011 would correspond to r3
    reg_num = int(reg_bits, 2)
    return "r%d" % reg_num


def get_operands_shift_instr(bits):
    """Parse bits based on the encoding of shift instructions"""
    reg_start_bit = 5
    reg_end_bit = 19
    reg_bit_size = 5
    c = 0
    operands = []
    # Start at index 4 (bit 5), go up to bit 19, incrementing by 5 bits at a time.
    for r in range(reg_start_bit - 1, reg_end_bit, reg_bit_size):
        if c != 1:
            reg_num = get_register_number(bits[r:r + reg_bit_size])
        else:
            reg_num = str(int(bits[r:r + reg_bit_size], 2))
        operands.append(reg_num)
        c += 1
    return operands


def get_operands_sum_instr(bits):
    """Parse bits based on the encoding of instructions that sum their registers"""
    # ldi and sti load/store instrs get the memory addr by summing the rA and rB register contents.
    reg_start_bit = 5
    reg_end_bit = 19
    reg_bit_size = 5
    sum = 0
    operands = []
    # Start at index 4 (bit 5), go up to bit 19, incrementing by 5 bits at a time.
    for r in range(reg_start_bit - 1, reg_end_bit, reg_bit_size):
        reg_num = get_register_number(bits[r:r + reg_bit_size])
        operands.append(reg_num)
    # For sti, rC is the source address, so swap it from the final element of the list (index 2) to the first (index 0)
    if get_instruction(get_op_code(bits), get_sub_op_code(get_op_code(bits), bits)) == "sti":
        operands[0], operands[2] = operands[2], operands[0]
    return operands


def get_operands_sub_op_code(bits):
    """Parse bits based on encoding of instructions that have sub opcodes
       but aren't shift, sum-registers, or no-registers types"""
    reg_start_bit = 5
    reg_end_bit = 19
    reg_bit_size = 5
    operands = []
    # Start at index 4 (bit 5), go up to bit 19, incrementing by 5 bits at a time.
    for r in range(reg_start_bit - 1, reg_end_bit, reg_bit_size):
        reg_num = get_register_number(bits[r:r + reg_bit_size])
        operands.append(reg_num)
    return operands


def get_operands_no_sub_op(bits):
    """Parse bits based on encoding of instructions that don't have sub opcodes"""
    reg_start_bit = 5
    reg_end_bit = 9
    addr_start_bit = 10
    addr_end_bit = 24
    operands = []
    # Parse bits from index 4 (bit 5) to (exclusive) index 9 (bit 10)
    reg_num = get_register_number(bits[reg_start_bit - 1:reg_end_bit])
    operands.append(reg_num)
    addr = binary_to_hex(bits[addr_start_bit - 1:addr_end_bit])
    operands.append(addr)
    return operands


def get_operands(bits, op_code, sub_op_code, instr):
    """Return the operands (registers, addresses) used in this instruction"""
    operands = []
    if not sub_op_code:
        operands = get_operands_no_sub_op(bits)
    elif instr in INSTR_WITH_SHIFT:
        operands = get_operands_shift_instr(bits)
    elif instr in INSTR_WITH_SUM_REGISTERS:
        operands = get_operands_sum_instr(bits)
    elif instr in INSTR_WITH_NO_REGISTERS:
        # halt, nop, rts don't use operands, so don't bother parsing their register bits.
        pass
    else:
        operands = get_operands_sub_op_code(bits)
    return operands


def build_btree(btree, list_instrs):
    instrs = list_instrs.copy()
    instr = instrs[0][3]
    addr = instrs[0][0]
    btree[addr] = {}
    # Recursive base case: halt implies we're at the end of a branch.
    if instr == "halt" or instr == "rts":
        btree[addr]["LEFT"] = None
        btree[addr]["RIGHT"] = None
        return btree
    # If we have a branch, then we create two child nodes.
    elif instr in INSTR_WITH_BRANCH:
        # instrs is a list of all instructions
        # e.g. [[addr, machine_code, interp, instr, operands], repeat_for_each_instr]
        # So parse out the first instr in the list, get the last element (operands), and get the last operand.
        # For branches, this is the address to jump to.
        addr_to_jump_to = instrs[0][-1].rsplit(', ')[-1].zfill(4)
        instrs.pop(0)

        if instr != "br" and instr != "bsr":
            # Build left tree
            btree[addr]["LEFT"] = build_btree({}, instrs)
            # Build right tree
            # This is based on where a branch jumps to.
            for i in range(0, len(instrs)):
                if instrs[0][0] == addr_to_jump_to:
                    btree[addr]["RIGHT"] = build_btree({}, instrs)
                    break
                else:
                    instrs.pop(0)
            return btree
        else:
            btree[addr]["RIGHT"] = None
            # Build left tree
            # This is based on where a branch jumps to.
            for i in range(0, len(instrs)):
                if instrs[0][0] == addr_to_jump_to:
                    btree[addr]["LEFT"] = build_btree({}, instrs)
                    break
                else:
                    instrs.pop(0)
            return btree
    # Else not a halt/rts nor a branch, so tack next instrs onto left child and keep going.
    else:
        instrs.pop(0)
        btree[addr]["LEFT"] = build_btree({}, instrs)
        btree[addr]["RIGHT"] = None
        return btree


def translate_bits(s20_output):
    """Main process for translating the bits to assembled code"""
    addr = 0
    instrs = []
    # Iterate over 24 bits (6 chars) at a time.
    for i in range(0, len(s20_output), S20_NUM_INSTR_NIBBLES):
        # Get instructions, 6 nibbles of the S20's output at a time.
        cur_instr = s20_output[i:i + S20_NUM_INSTR_NIBBLES]

        # Convert hex to raw binary bits.
        bits = hex_to_binary(cur_instr)

        # Parse opcode and sub opcode.
        op_code = get_op_code(bits)
        sub_op_code = get_sub_op_code(op_code, bits)

        # Lookup instr based on opcode and sub opcode.
        instr = get_instruction(op_code, sub_op_code)

        # If instr can use operands, parse them.
        operands = get_operands(bits, op_code, sub_op_code, instr)
        operands = ", ".join(operands)

        interp = "        "
        instrs.append([str(hex(addr))[2:].zfill(4), cur_instr, interp, instr, operands])

        # Next line
        addr += 1
    return instrs


def lookup_instr_by_addr(addr, instrs):
    for instr in instrs:
        if instr[0] == addr:
            return instr


def lookup_data_addr(instr):
    data_addr_start_bit = 10
    data_addr_end_bit = 24
    addr = instr[1]
    bin_addr = hex_to_binary(addr)
    data_addr = binary_to_hex(bin_addr[data_addr_start_bit - 1:data_addr_end_bit])
    return data_addr


def label_data(node, instrs):
    """Traverse binary tree of prog flow to label data"""
    global data_count, skip_count
    addr = list(node.keys())[0]
    instr = lookup_instr_by_addr(addr, instrs)
    if instr[3] == "ld" or instr[3] == "st":
        data_addr = lookup_data_addr(instr).zfill(4)
        data_instr = lookup_instr_by_addr(data_addr, instrs)
        # Symbol names are d#, e.g. d0 or d1 or d2 or ...
        label = 'd' + str(data_count)
        # If data already exists at that address, reference that already-existing label.
        try:
            if data_instr[2] != "        ":
                label = data_instr[2]
            # Fix format of operands depending on whether instruction is ld or st.
            if instr[3] == "ld":
                instr[4] = label + ", " + instr[4].split(",")[0]
            elif instr[3] == "st":
                instr[4] = instr[4].split(",")[0] + ", " + label
            # Add symbol to the data address, overwrite existing (unused) instruction with "data".
            data_instr[2] = label.ljust(8)
            data_instr[3] = "data"
            data_instr[4] = str(0)
            data_count += 1
        except TypeError:
            label = 'd' + str(data_count)
            if instr[3] == "ld":
                instr[4] = label + ", " + instr[4].split(",")[0] + " [" + label + " references unknown memory address!]"
            elif instr[3] == "st":
                instr[4] = instr[4].split(",")[0] + ", " + label + " [" + label + " references unknown memory address!]"
            print_debug("Unable to find memory address %s" % data_addr)
            data_count += 1
    if instr[3] in INSTR_WITH_BRANCH:
        label = "skip" + str(skip_count)
        jmp_addr = lookup_data_addr(instr).zfill(4)
        jmp_instr = lookup_instr_by_addr(jmp_addr, instrs)
        if jmp_instr[2] != "        ":
            label = jmp_instr[2]
        if instr[3] == "br" or instr[3] == "bsr":
            instr[4] = label
        else:
            instr[4] = instr[4].split(",")[0] + ", " + label
        jmp_instr[2] = label.ljust(8)
        skip_count += 1

    # Check remaining nodes.
    left_node = node[list(node.keys())[0]]["LEFT"]
    right_node = node[list(node.keys())[0]]["RIGHT"]
    if left_node is not None:
        label_data(left_node, instrs)
    if right_node is not None:
        label_data(right_node, instrs)


def trace_execution(node, instrs):
    """Mutates instrs to contain only unvisited (unreachable) code"""
    addr = list(node.keys())[0]
    instr = lookup_instr_by_addr(addr, instrs)
    if instr in instrs:
        instrs.remove(instr)
        # Check remaining nodes.
        left_node = node[list(node.keys())[0]]["LEFT"]
        right_node = node[list(node.keys())[0]]["RIGHT"]
        if left_node is not None:
            trace_execution(left_node, instrs)
        if right_node is not None:
            trace_execution(right_node, instrs)


def process_data(instrs):
    """Figures out program flow to determine how data is used"""
    unused_instrs = instrs.copy()
    tree_instrs = instrs.copy()
    btree = build_btree({}, tree_instrs)
    trace_execution(btree, unused_instrs)  # Mutates unused_instrs
    for instr in unused_instrs:
        i = instrs.index(instr)
        instrs[i][3] = "data"
        instrs[i][4] = "0"
    label_data(btree, instrs)
    # Final output
    for instr in instrs:
        print("%s" % " ".join(instr))


def main():
    """Program driver"""
    file_service = FileService()
    s20_output = file_service.get_content_from_file()
    instrs = translate_bits(s20_output)
    process_data(instrs)


#############
#  PROCESS  #
#############


if __name__ == '__main__':
    main()
