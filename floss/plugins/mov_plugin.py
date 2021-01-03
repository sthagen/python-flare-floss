# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import envi
import viv_utils

import floss.interfaces as interfaces

from . import plugin_object


class MovPlugin(plugin_object.GeneralPlugin):
    """
    Identify suspicious MOV instructions.
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def identify(self, vivisect_workspace, function_vas):
        candidate_functions = {}
        # walk over every instruction
        for fva in function_vas:
            f = viv_utils.Function(vivisect_workspace, fva)
            for bb in f.basic_blocks:
                try:
                    for i in bb.instructions:
                        # TODO other identification features: rep movs?, movs from memory to register, e.g. movsx eax, byte ptr [ecx+eax]
                        # identify register dereferenced writes to memory, e.g. mov [eax], cl
                        if i.mnem == "mov":
                            op0, op1 = i.opers
                            # ignore instruction if second operand is an immediate value
                            # TODO use op0.isDeref() instead?
                            if isinstance(op0, envi.archs.i386.disasm.i386RegMemOper) and not op1.isImmed():
                                # TODO what about movs of words, dwords, qwords?
                                # TODO handle dereferences with displacements?
                                if op0.tsize == 1 and op0.disp == 0:
                                    self.d("suspicious MOV instruction at 0x%08X in function 0x%08X: %s", i.va, fva, i)
                                    # TODO add values if multiple such instructions in same function?
                                    candidate_functions[fva] = 1.0
                except envi.InvalidInstruction:
                    self.w("Invalid instruction encountered in basic block, skipping: 0x%x", bb.va)  # TODO log warning?
                    continue
        return candidate_functions

    def score(self, function_vas, vivisect_workspace=None):
        self.d("found suspicious MOV instructions in %d functions", len(function_vas))
        return function_vas  # scoring simply means identifying functions with suspicious instructions
