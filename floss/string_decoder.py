import logging

import envi.memory

import strings
import decoding_manager
from utils import makeEmulator
from function_argument_getter import get_function_contexts
from decoding_manager import DecodedString


floss_logger = logging.getLogger("floss")


def extract_decoding_contexts(vw, function):
    '''
    Extract the CPU and memory contexts of all calls to the given function.
    Under the hood, we brute-force emulate all code paths to extract the
     state of the stack, registers, and global memory at each call to
     the given address.

    :param vw: The vivisect workspace in which the function is defined.
    :type function: int
    :param function: The address of the function whose contexts we'll find.
    :rtype: Sequence[function_argument_getter.FunctionContext]
    '''
    return get_function_contexts(vw, function)


def emulate_decoding_routine(vw, function_index, function, context):
    '''
    Emulate a function with a given context and extract the CPU and
     memory contexts at interesting points during emulation.
    These "interesting points" include calls to other functions and
     the final state.
    Emulation terminates if the CPU executes an unexpected region of
     memory, or the function returns.
    Implementation note: currently limits emulation to 20,000 instructions.
     This prevents unexpected infinite loops.
     This number is taken from emulating the decoding of "Hello world" using RC4.


    :param vw: The vivisect workspace in which the function is defined.
    :type function_index: viv_utils.FunctionIndex
    :type function: int
    :param function: The address of the function to emulate.
    :type context: funtion_argument_getter.FunctionContext
    :param context: The initial state of the CPU and memory
      prior to the function being called.
    :rtype: Sequence[decoding_manager.Delta]
    '''
    emu = makeEmulator(vw)
    emu.setEmuSnap(context.emu_snap)
    floss_logger.debug("Emulating function at 0x%08X called at 0x%08X, return address: 0x%08X",
           function, context.decoded_at_va, context.return_address)
    deltas = decoding_manager.emulate_function(
                emu,
                function_index,
                function,
                context.return_address,
                20000)
    return deltas


def extract_delta_bytes(delta, decoded_at_va, source_fva=0x0):
    '''
    Extract the sequence of byte sequences that differ from before
     and after snapshots.

    :type delta: decoding_manager.Delta
    :param delta: The before and after snapshots of memory to diff.
    :type decoded_at_va: int
    :param decoded_at_va: TODO
    :type source_fva: int
    :param source_fva: TODO
    :rtype: Sequence[DecodedString]
    '''
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


def extract_strings(b):
    '''
    Extract the ASCII and UTF-16 strings from a bytestring.

    :type b: decoding_manager.DecodedString
    :param b: The data from which to extract the strings. Note its a
      DecodedString instance that tracks extra metadata beyond the
      bytestring contents.
    :rtype: Sequence[decoding_manager.DecodedString]
    '''
    ret = []
    for s in strings.extract_ascii_strings(b.s):
        if s.s == "A" * len(s.s):
            # ignore strings of all "A", which is likely taint data
            continue
        ret.append(DecodedString(b.va + s.offset, s.s, b.decoded_at_va,
                                 b.fva, b.global_address))
    for s in strings.extract_unicode_strings(b.s):
        if s.s == "A" * len(s.s):
            continue
        ret.append(DecodedString(b.va + s.offset, s.s, b.decoded_at_va,
                                 b.fva, b.global_address))
    return ret

