# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import envi
import viv_utils

import floss.interfaces as interfaces

from . import plugin_object


class XORPlugin(plugin_object.GeneralPlugin):
    """
    Identify unusual XOR instructions.
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def identify(self, vivisect_workspace, function_vas):
        candidate_functions = {}
        # walk over every instruction
        for fva in function_vas:
            f = viv_utils.Function(vivisect_workspace, fva)
            for n_bb in xrange(0, len(f.basic_blocks)):
                bb = f.basic_blocks[n_bb]
                try:
                    instructions = bb.instructions
                    for n_instr in xrange(0, len(bb.instructions)):
                        i = instructions[n_instr]
                        if i.mnem == "xor":
                            if i.opers[0] != i.opers[1]:
                                self.d("suspicious XOR instruction at 0x%08X in function 0x%08X: %s", i.va, fva, i)
                                if (n_instr - 1) > 0 and (n_instr + 1) < len(instructions) - 1:
                                    self.d(
                                        "Instructions: %s;  %s;  %s",
                                        instructions[n_instr - 1],
                                        i,
                                        instructions[n_instr + 1],
                                    )
                                if self.is_security_cookie(f, n_bb, n_instr):
                                    self.d("XOR related to security cookie: %s", i)
                                else:
                                    self.d("unusual XOR: %s", i)
                                    candidate_functions[fva] = 1.0  # TODO scoring
                except envi.InvalidInstruction:
                    self.w("Invalid instruction encountered in basic block, skipping: 0x%x", bb.va)
                    continue
        return candidate_functions

    def is_security_cookie(self, f, n_bb, n_instr):
        # TODO check previous and next instruction for more robust result?
        bb = f.basic_blocks[n_bb]
        instructions = bb.instructions
        i = instructions[n_instr]

        # for security cookie check the xor should use ESP or EBP
        op = i.opers[1]
        if op.isReg():
            reg_name = op._dis_regctx.getRegisterName(op.reg)  # TODO for blog post?
            if reg_name not in ["esp", "ebp"]:
                return False

        # security cookie check should happen in first basic block within first 15 instructions
        if n_bb == 0 and n_instr < 15:
            return True
        # ... or within last 10 instructions before return
        elif instructions[-1].isReturn() and n_instr > (len(instructions) - 10):
            return True

        return False

    def score(self, function_vas, vivisect_workspace=None):
        return function_vas  # scoring simply means identifying functions with non-zero XOR instructions


class ShiftPlugin(plugin_object.GeneralPlugin):
    """
    Identify shift instructions.
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def identify(self, vivisect_workspace, fvas):
        candidate_functions = {}
        for fva in fvas:
            f = viv_utils.Function(vivisect_workspace, fva)
            mnems = set([])
            shift_mnems = set(["shl", "shr", "sar", "sal", "rol", "ror"])
            for bb in f.basic_blocks:
                try:
                    for i in bb.instructions:
                        mnems.add(i.mnem)
                        if i.mnem in shift_mnems:
                            self.d("shift instruction: %s va: 0x%x function: 0x%x", i, i.va, f.va)
                except envi.InvalidInstruction:
                    self.w("Invalid instruction encountered in basic block, skipping: 0x%x", bb.va)
                    continue

            candidate_functions[fva] = 1 - (len(shift_mnems - mnems) / float(len(shift_mnems)))
            self.d("0x%x %f", fva, candidate_functions[fva])
        return candidate_functions

    def score(self, function_vas, vivisect_workspace=None):
        return function_vas  # scoring simply means identifying functions with shift instructions
