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
S20_BYTES = 6

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
                "1f": {
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
    has_sub_op_code = list(INSTR_SET["OP_CODE"][op_code]["SUB_OP_CODE"].keys())[0] is not None
    if not has_sub_op_code:
        return INSTR_SET["OP_CODE"][op_code]["SUB_OP_CODE"][None]["INSTRUCTION"]
    else:
        sub_op_code = "0" + sub_op_code  # Not correct impl, testing.
        return INSTR_SET["OP_CODE"][op_code]["SUB_OP_CODE"][sub_op_code]["INSTRUCTION"]


def translate_bits(s20_output):
    # Iterate over 24 bits (6 bytes) at a time.
    for i in range(0, len(s20_output), S20_BYTES):
        cur_bytes = s20_output[i:i + S20_BYTES]
        op_code = cur_bytes[0]
        sub_op_code = cur_bytes[S20_BYTES-1]
        instr = get_instruction(op_code, sub_op_code)
        print("INSTR %s" % instr)


def main():
    """Driver"""
    file_service = FileService()
    s20_output = file_service.get_content_from_file()
    translate_bits(s20_output)


#############
#  PROCESS  #
#############


if __name__ == '__main__':
    main()
