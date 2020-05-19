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
    has_sub_op_code = list(INSTR_SET["OP_CODE"][op_code]["SUB_OP_CODE"].keys())[0] is not None
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


def get_sub_op_code(op_code, bits):
    """Sub Opcode defined as last 5 bits of binary, if opcode is 0"""
    # Lookup instr by op_code, see if it can have a sub opcode.
    # Instead of doing the lookup, I could have just checked (if opcode == 0),
    #  but this will work even if non-zero opcodes are given sub opcodes in the future.
    has_sub_op_code = list(INSTR_SET["OP_CODE"][op_code]["SUB_OP_CODE"].keys())[0] is not None
    sub_op_code = None
    if has_sub_op_code:
        sub_op_code_bits = 5  # Last 5 bits of binary
        bin_sub_op_code = bits[-sub_op_code_bits:]  # Get the last 5 bits of the binary str
        sub_op_code = binary_to_hex(bin_sub_op_code).zfill(2)  # Pad to two chars
    return sub_op_code


def translate_bits(s20_output):
    """Main process for translating the bits to assembled code"""
    # Iterate over 24 bits (6 chars) at a time.
    for i in range(0, len(s20_output), S20_NUM_INSTR_NIBBLES):
        # Get instructions, 6 nibbles of the S20's output at a time.
        cur_instr = s20_output[i:i + S20_NUM_INSTR_NIBBLES]
        # Convert hex to raw binary bits.
        bits = hex_to_binary(cur_instr)
        op_code = get_op_code(bits)
        sub_op_code = get_sub_op_code(op_code, bits)
        instr = get_instruction(op_code, sub_op_code)
        print("INSTR %s" % instr)


def main():
    """Program driver"""
    file_service = FileService()
    s20_output = file_service.get_content_from_file()
    translate_bits(s20_output)


#############
#  PROCESS  #
#############


if __name__ == '__main__':
    main()
