#! /usr/bin/env python

from idautils import *
from idaapi import *
from idc import *
try:
    import _csv as csv
except ImportError:
    import csv


def get_opcodes():
    opcode_dict = {}
    with open('C:\Tools\opcodes.csv') as csvfile:
        opcode_file = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in opcode_file:
            opcode_dict[row[0]] = row[1]
        return opcode_dict


def make_all_absolute(instruction):
    size_in_bytes = instruction.size
    ea = instruction.ea
    signature = ""
    for byte in range(size_in_bytes):
        signature += "{0:0{1}x}".format(Byte(instruction.ea + byte), 2).upper() + " "

    return signature


def make_only_first(instruction):
    size_in_bytes = instruction.size
    ea = instruction.ea
    signature = ""
    for byte in range(size_in_bytes):
        if byte is 0:
            signature += "{0:0{1}x}".format(Byte(instruction.ea), 2).upper() + " "
            continue
        signature += "?? "
    return signature


def make_only_first_two(instruction, hex_value):
    size_in_bytes = instruction.size
    ea = instruction.ea
    signature = ""
    for byte in range(size_in_bytes):
        if byte is 0:
            signature += hex_value + " "
            continue
        if byte is 1:
            continue
        signature += "?? "
    return signature


def make_all_wildcard(instruction):
    size_in_bytes = instruction.size
    ea = instruction.ea
    signature = ""
    for byte in range(size_in_bytes):
        signature += "?? "

    return signature


def get_basic_info(instruction):
    # TODO CLEAN UP OUTPUT
    func = idaapi.get_func(instruction.ea)
    func_name = GetFunctionName(func.startEA)
    md5 = GetInputFileMD5()

    basic_info = []
    basic_info.append("MD5: %s" % md5)
    basic_info.append("Function: {0:0X} {1:s}".format(func.startEA, func_name))

    return basic_info


def decode_function(instruction, hex_value):
    signature = ""
    if len(hex_value) == 2:
        return hex_value + " "
    elif len(hex_value) == 5:
        return make_only_first_two(instruction, hex_value)
    else:
        print("Nothing Found")


def decode_instructions():
    start = SelStart()
    stop = SelEnd()

    if start == BADADDR:
        print "Please select something"

    instruction = DecodeInstruction(start)

    disasm_text = get_basic_info(instruction)
    signature = ""

    for instruct_address in Heads(start, stop):

        instruction = DecodeInstruction(instruct_address)
        mnem_name = instruction.get_canon_mnem()
        size_in_bytes = instruction.size
        test_opcodes = get_opcodes()
        # print(test_opcodes)
        for row in test_opcodes:
            if mnem_name == row:
                opcode_match = str(test_opcodes[row])
                signature += decode_function(instruction, str(opcode_match))
                # print "Didnt find it for %s" % mnem_name
        for byte in range(size_in_bytes):
            if byte != 0:
                signature += "?? "
        # build the textual rep of yara signature
        bytes = ""
        size_in_bytes = instruction.size
        ea = instruction.ea
        for byte in range(size_in_bytes):
            bytes += "{0:0{1}x}".format(Byte(instruction.ea + byte), 2).upper() + " "

        disasm_text.append("{0:0X} {1:24s} {2:s}".format(instruct_address, bytes, GetDisasm(instruct_address)))

    return signature, disasm_text


def print_signature():
    signature, disasm_text = decode_instructions()
    print "rule opcode{"
    print "\tstrings:"
    for line in disasm_text:
        print "\t\t// %s" % line
    print "\t\t$opcodes = {", signature, "}"
    print "\tcondition:"
    print "\t\tall of them"
    print "}"


print_signature()
