import logging

import envi.memory

import strings
from utils import makeEmulator
from function_argument_getter import get_function_contexts
from decoding_manager import DecodedString, FunctionEmulator


floss_logger = logging.getLogger("floss")


def extract_decoding_contexts(vw, function):
    return get_function_contexts(vw, function)


def emulate_decoding_routine(vw, function_index, function, context):
    emu = makeEmulator(vw)
    # Restore function context
    emu.setEmuSnap(context.emu_snap)
    femu = FunctionEmulator(emu, function, function_index)
    floss_logger.debug("Emulating function at 0x%08X called at 0x%08X, return address: 0x%08X",
           function, context.decoded_at_va, context.return_address)
    deltas = femu.emulate_function(context.return_address, 2000)
    return deltas


def extract_delta_bytes(delta, decoded_at_va, source_fva=0x0):
    delta_bytes = []

    memory_snap_before = delta.pre_snap.memory
    memory_snap_after = delta.post_snap.memory
    sp = delta.post_snap.sp

    # maps from region start to section tuple
    mem_before = {m[0]: m for m in memory_snap_before}
    mem_after = {m[0]: m for m in memory_snap_after}

    stack_start = 0x0
    stack_end = 0x0
    for m in memory_snap_after:
        if m[0] <= sp < m[1]:
            stack_start, stack_end = m[0], m[1]

    # iterate memory from after the decoding, since if somethings been allocated,
    # we want to know. don't care if things have been deallocated.
    for section_after_start, section_after in mem_after.items():
        (_, _, _, bytes_after) = section_after
        if section_after_start not in mem_before:
            # TODO delta bytes instead of decoded strings
            delta_bytes.append(DecodedString(section_after_start, bytes_after, 
                                             decoded_at_va, source_fva, False))
            continue

        section_before = mem_before[section_after_start]
        (_, _, _, bytes_before) = section_before

        memory_diff = envi.memory.memdiff(bytes_before, bytes_after)
        for offset, length in memory_diff:
            address = section_after_start + offset

            if stack_start <= address <= sp:
                # every stack address that exceeds the stack pointer can be
                # ignored because it is local to child stack frame
                continue

            diff_bytes = bytes_after[offset:offset + length]
            global_address = False
            if not (stack_start <= address < stack_end):
                # address is in global memory
                global_address = address
            delta_bytes.append(DecodedString(address, diff_bytes, decoded_at_va,
                                             source_fva, global_address))
    return delta_bytes


def extract_strings(delta):
    ret = []
    for s in strings.extract_ascii_strings(delta.s):
        if s.s == "A" * len(s.s):
            # ignore strings of all "A", which is likely taint data
            continue
        ret.append(DecodedString(delta.va + s.offset, s.s, delta.decoded_at_va,
                                 delta.fva, delta.global_address))
    for s in strings.extract_unicode_strings(delta.s):
        if s.s == "A" * len(s.s):
            continue
        ret.append(DecodedString(delta.va + s.offset, s.s, delta.decoded_at_va,
                                 delta.fva, delta.global_address))
    return ret


