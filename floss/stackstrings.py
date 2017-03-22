# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import re
import logging

from collections import namedtuple
from itertools import groupby
from operator import itemgetter

import viv_utils
import envi.archs.i386
import envi.archs.amd64
import viv_utils.emulator_drivers

import strings
from utils import makeEmulator


logger = logging.getLogger(__name__)
MAX_STACK_SIZE = 0x10000

MIN_NUMBER_OF_MOVS = 8
MIN_CONSECUTIVE_ADDRS_DEFAULT = 4

SIZE_BYTE = 1
SIZE_WORD = 2
SIZE_DWORD = 4
SIZE_QWORD = 8

CallContext = namedtuple("CallContext",
                         [
                             "pc",  # the current program counter, type: int
                             "sp",  # the current stack counter, type: int
                             "init_sp",   # the initial stack counter at start of function, type: int
                             "stack_memory",  # the active stack frame contents, type: str
                         ])


class StackstringContextMonitor(viv_utils.emulator_drivers.Monitor):
    """
    Observes emulation and extracts the active stack frame contents:
    - at each function call in a function
    - based on a heuristic looking for mov instructions to consecutive memory addresses
    """

    def __init__(self, vw, init_sp):
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)

        # this is a public field
        # type: List[CallContext]
        self.ctxs = []

        # this is a private field
        self._init_sp = init_sp

        self.mem_written_to = set([])

        self.extract_contexts_at_vas = set([])

    def apicall(self, emu, op, pc, api, argv):
        self.extract_context(emu, op)

    def extract_context(self, emu, op):
        """ Extract only the bytes on the stack between the base pointer specifically, stack pointer at function entry),
        and stack pointer. """
        stack_top = emu.getStackCounter()
        stack_bottom = self._init_sp
        stack_size = stack_bottom - stack_top
        if stack_size > MAX_STACK_SIZE:
            logger.debug('stack size too big: 0x%x', stack_size)
            return

        stack_buf = emu.readMemory(stack_top, stack_size)
        self.ctxs.append(CallContext(op.va, stack_top, stack_bottom, stack_buf))

    def posthook(self, emu, op, endpc):
        # self.d("0x%x: %s", endpc, op)
        self.find_consecutive_movs(emu, op, endpc)

    def find_consecutive_movs(self, emu, op, va):
        """ Identify contexts based on instructions moving data to consecutive memory addresses. """

        # extract at end of identified basic block
        if va in self.extract_contexts_at_vas:
            self.mem_written_to.clear()
            self.extract_context(emu, op)
            return

        if op.mnem[:3] == "mov":
            va_last_instr = self.get_va_last_instruction_current_bb(emu.vw, va)
            if va_last_instr in self.extract_contexts_at_vas:
                # already identified this bb
                return

            op0 = op.getOperands()[0]
            if isinstance(op0, envi.archs.i386.disasm.i386SibOper):
                addr = emu.getOperAddr(op, 0)
                if addr:
                    self.mem_written_to.add(addr)
                    self.d("Current write count: %d", len(self.mem_written_to))
                    self.d("Addresses written to: %s", ", ".join(map(hex, sorted(self.mem_written_to))))
                    if len(self.mem_written_to) > MIN_NUMBER_OF_MOVS:
                        if self.contains_consecutive_addresses(self.mem_written_to, MIN_CONSECUTIVE_ADDRS_DEFAULT):
                            self.d("Get context at end of this basic block at VA 0x%x", va_last_instr)
                            self.extract_contexts_at_vas.add(va_last_instr)
                        else:
                            self.d("Did not find consecutive addresses")

    def contains_consecutive_addresses(self, data, n):
        """ Return True if n or more consecutive addresses were found. """
        for size in [SIZE_BYTE, SIZE_WORD, SIZE_DWORD, SIZE_QWORD]:
            for l in self.get_len_consecutive_values(data, size):
                if l >= n // size:
                    self.d("Found %d consecutive addresses (size %d)", l, size)
                    return True
        return False

    def get_len_consecutive_values(self, data, size):
        """ Return list of length of consecutive values in data adjusted to size. """
        r = []
        data = sorted(map(lambda (x): x // size, data))
        for k, g in groupby(enumerate(data), lambda (i, x): i - x):
            r.append(len(map(itemgetter(1), g)))
        return r

    def get_va_last_instruction_current_bb(self, vw, va):
        """ Return the VA of the last instruction of the basic block containing the input va. """
        f = viv_utils.Function(vw, vw.getFunction(va))
        for bb in f.basic_blocks:
            if va > bb.va and va <= bb.va + bb.size:
                return bb.instructions[-1].va  # last instruction
        return None


def extract_call_contexts(vw, fva):
    emu = makeEmulator(vw)
    monitor = StackstringContextMonitor(vw, emu.getStackCounter())
    driver = viv_utils.emulator_drivers.FunctionRunnerEmulatorDriver(emu)
    driver.add_monitor(monitor)
    driver.runFunction(fva, maxhit=1, maxrep=0x100, func_only=True)
    return monitor.ctxs


# StackString represents a stackstring extracted from a function.
StackString = namedtuple("StackString",
                         [
                             # type: int
                             # the address from which the stackstring was extracted.
                             "fva",

                             # type: str
                             # the string contents.
                             "s",

                             # type: int
                             # the program counter at which the stackstring existed.
                             "pc",

                             # here's what the following members represent...
                             #
                             #
                             # [smaller addresses]
                             #
                             # +---------------+  <- sp (top of stack)
                             # |               | \
                             # +---------------+  | offset
                             # |               | /
                             # +---------------+
                             # | "abc"         | \
                             # +---------------+  |
                             # |               |  |
                             # +---------------+  | frame_offset
                             # |               |  |
                             # +---------------+  |
                             # |               | /
                             # +---------------+  <- init_sp (bottom of stack, probably bp)
                             #
                             # [bigger addresses]

                             # type: int
                             # the stack counter at which the stackstring existed.
                             # aka, the top of the stack frame
                             "sp",

                             # type: int
                             # the initial stack counter at the start of the function.
                             # aka, the bottom of the stack frame
                             "init_sp",

                             # type: int
                             # the offset into the stack frame at which the stackstring existed.
                             "offset",

                             # type: int
                             # the offset from the function frame at which the stackstring existed.
                             "frame_offset",
                         ])


def getPointerSize(vw):
    if isinstance(vw.arch, envi.archs.amd64.Amd64Module):
        return 8
    elif isinstance(vw.arch, envi.archs.i386.i386Module):
        return 4
    else:
        raise NotImplementedError("unexpected architecture: %s" % (vw.arch.__class__.__name__))


def extract_stackstrings(vw, selected_functions):
    '''
    Extracts the stackstrings from functions in the given workspace.

    :param vw: The vivisect workspace from which to extract stackstrings.
    :rtype: Generator[StackString]
    '''
    logger.debug('extracting stackstrings from %d functions', len(selected_functions))
    for fva in selected_functions:
        logger.debug('extracting stackstrings from function: 0x%x', fva)
        seen = set([])
        filter = re.compile("^p?V?A+$")
        filter_sub = re.compile("^p?VA")  # remove string prefixes: pVA, VA
        for ctx in extract_call_contexts(vw, fva):
            logger.debug('extracting stackstrings at checkpoint: 0x%x stacksize: 0x%x', ctx.pc, ctx.init_sp - ctx.sp)
            for s in strings.extract_ascii_strings(ctx.stack_memory):
                if filter.match(s.s):
                    # ignore strings like: pVA, pVAAA, AAAA
                    # which come from vivisect uninitialized taint tracking
                    continue
                s_stripped = re.sub(filter_sub, "", s.s)
                if s_stripped not in seen:
                    frame_offset = (ctx.init_sp - ctx.sp) - s.offset - getPointerSize(vw)
                    yield(StackString(fva, s_stripped, ctx.pc, ctx.sp, ctx.init_sp, s.offset, frame_offset))
                    seen.add(s_stripped)
            for s in strings.extract_unicode_strings(ctx.stack_memory):
                if filter.match(s.s):
                    # ignore strings like: pVA, pVAAA, AAAA
                    # which come from vivisect uninitialized taint tracking
                    continue
                s_stripped = re.sub(filter_sub, "", s.s)
                if s_stripped not in seen:
                    frame_offset = (ctx.init_sp - ctx.sp) - s.offset - getPointerSize(vw)
                    yield(StackString(fva, s_stripped, ctx.pc, ctx.sp, ctx.init_sp, s.offset, frame_offset))
                    seen.add(s_stripped)
