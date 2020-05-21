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

IS_DEBUG = True

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
            content = file.read().replace(" ", "")
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


def get_operands(bits, op_code, sub_op_code, instr):
    """Return the operands (registers, addresses) used in this instruction"""
    operands = []
    if not sub_op_code:
        reg_start_bit = 5
        reg_end_bit = 9
        # Parse bits from index 4 (bit 5) to (exclusive) index 9 (bit 10)
        reg_num = get_register_number(bits[reg_start_bit-1:reg_end_bit])
        operands.append(reg_num)
        addr_start_bit = 10
        addr_end_bit = 24
        addr = binary_to_hex(bits[addr_start_bit-1:addr_end_bit])
        operands.append(addr)
    elif instr in INSTR_WITH_SHIFT:
        reg_start_bit = 5
        reg_end_bit = 19
        reg_bit_size = 5
        c = 0
        # Start at index 4 (bit 5), go up to bit 19, incrementing by 5 bits at a time.
        for r in range(reg_start_bit-1, reg_end_bit, reg_bit_size):
            if c != 1:
                reg_num = get_register_number(bits[r:r + reg_bit_size])
            else:
                reg_num = str(int(bits[r:r + reg_bit_size], 2))
            operands.append(reg_num)
            c += 1
    elif instr in INSTR_WITH_SUM_REGISTERS:
        # ldi and sti load/store instrs get the memory addr by summing the three values in the register fields.
        reg_start_bit = 5
        reg_end_bit = 19
        reg_bit_size = 5
        sum = 0
        # Start at index 4 (bit 5), go up to bit 19, incrementing by 5 bits at a time.
        for r in range(reg_start_bit-1, reg_end_bit, reg_bit_size):
            sum += int(bits[r:r + reg_bit_size], 2)
        operands.append(hex(sum))
    elif instr in INSTR_WITH_NO_REGISTERS:
        # halt, nop, rts don't use operands, so don't bother parsing their register bits.
        pass
    else:
        reg_start_bit = 5
        reg_end_bit = 19
        reg_bit_size = 5
        # Start at index 4 (bit 5), go up to bit 19, incrementing by 5 bits at a time.
        for r in range(reg_start_bit-1, reg_end_bit, reg_bit_size):
            reg_num = get_register_number(bits[r:r + reg_bit_size])
            operands.append(reg_num)
    return operands


def build_btree(btree, instrs):
    instr = instrs[0][3]
    addr = instrs[0][0]
    btree[addr] = {}
    print_debug("Current instruction %s" % instr)
    if instr == "halt":
        btree[addr]["LEFT"] = None
        btree[addr]["RIGHT"] = None
        return btree
    elif instr in INSTR_WITH_BRANCH:
        print_debug("Current address %s" % addr)
        addr_to_jump_to = instrs[0][-1].rsplit(', ')[-1].zfill(4)
        print_debug("Address to Jump to %s" % addr_to_jump_to)
        instrs.pop(0)

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

        interp = "\t"
        instrs.append([str(hex(addr))[2:].zfill(4), cur_instr, interp, instr, operands])

        # Output
        print("%s" % " ".join(instrs[addr]))

        # Next line
        addr += 1
    return instrs


def process_data(instrs):
    """Figures out program flow to determine how data is used"""
    btree = build_btree({}, instrs)
    print_debug(btree)

    #for instr in instrs:
    #    if instr[0] not in btree

    node = btree
    # Iterate over tree until we find a branch.
    while node[list(node.keys())[0]]["RIGHT"] is None:
        node = node[list(node.keys())[0]]["LEFT"]
    print("Done %s" % node)




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
