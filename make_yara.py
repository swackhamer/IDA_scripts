#! /usr/bin/env python

from idautils import *
from idaapi import *
from idc import *


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


def make_all_wildcard(instruction):
    size_in_bytes = instruction.size
    ea = instruction.ea
    signature = ""
    for byte in range(size_in_bytes):
        signature += "?? "

    return signature


def decode_call(instruction):
    signature = ""
    ea = instruction.ea
    size_in_bytes = instruction.size
    byte = Byte(ea)

    if byte == 0xFF or byte == 0x9A or byte == 0xE8:
        signature = make_only_first(instruction)
        return signature
    else:
        print("Double Check this might be wrong")
        signature = make_only_first(instruction)

    return signature


def decode_push(instruction):
    signature = ""
    ea = instruction.ea
    size_in_bytes = instruction.size
    byte = Byte(ea)

    if byte == 0xFF or byte == 0x68:
        signature = make_only_first(instruction)
    elif byte == 0x6A:
        signature = make_all_absolute(instruction)
    else:
        signature == "?? "
    return signature


def decode_move(instruction):
    # B9 mov ecx, 0AH, B8 mov eax, 1
    signature = ""
    size_in_bytes = instruction.size
    ea = instruction.ea
    byte = Byte(ea)

    if byte == 0x8B and size_in_bytes == 2:
        signature = make_all_absolute(instruction)
    elif byte == 0x8B:
        signature = make_only_first(instruction)
    elif instruction.size >= 5:
        # TODO FIX THIS
        signature = make_only_first(instruction)
    else:
        signature = make_all_wildcard(instruction)

    return signature


def decode_movdqu(instruction):
    return make_only_first(instruction)


def decode_cmp(instruction):
    if instruction.size > 2:
        return make_only_first(instruction)
    else:
        return make_all_absolute(instruction)


def get_basic_info(instruction):
    # TODO CLEAN UP OUTPUT
    func = idaapi.get_func(instruction.ea)
    func_name = GetFunctionName(func.startEA)
    md5 = GetInputFileMD5()

    basic_info = []
    basic_info.append("MD5: %s" % md5)
    basic_info.append("Function: {0:0X} {1:s}".format(func.startEA, func_name))

    return basic_info


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
        if mnem_name == "call":
            signature += decode_call(instruction)
        elif mnem_name == "push":
            signature += decode_push(instruction)
        elif mnem_name == "mov":
            signature += decode_move(instruction)
        elif mnem_name == "retn":
            signature += "C3 "
        elif mnem_name == "pop":
            signature += "5? "
        elif mnem_name == "movdqu":
            signature += decode_movdqu(instruction)
        elif mnem_name == "cmp":
            signature += decode_cmp(instruction)
        elif mnem_name[0] == "j":  # hopefully only getting the jumps
            signature += make_only_first(instruction)
        else:
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
