from collections import namedtuple

import viv_utils
import viv_utils.emulator_drivers

from utils import makeEmulator

# TODO get return address from emu_snap
FunctionContext = namedtuple("FunctionContext", ["emu_snap", "return_address", "decoded_at_va"])


class CallMonitor(viv_utils.emulator_drivers.Monitor):
    """ collect call arguments to a target function during emulation """
    def __init__(self, vivisect_workspace, target_fva):
        """ :param target_fva: address of function whose arguments to monitor """
        viv_utils.emulator_drivers.Monitor.__init__(self, vivisect_workspace)
        self.target_function_va = target_fva
        self.function_contexts = []

    def apicall(self, emu, op, pc, api, argv):
        return_address = self.getStackValue(emu, 0)
        if pc == self.target_function_va:
            self.function_contexts.append(FunctionContext(emu.getEmuSnap(), return_address, op.va))

    def get_contexts(self):
        return self.function_contexts

#    def prehook(self, emu, op, starteip):
#        self.d("%s: %s", hex(starteip), op)


# TODO LoggingObject should have its own file or be in general utils...
class FunctionArgumentGetter(viv_utils.LoggingObject):
    def __init__(self, vivisect_workspace):
        viv_utils.LoggingObject.__init__(self)
        self.vivisect_workspace = vivisect_workspace
        self.emu = makeEmulator(vivisect_workspace)
        self.driver = viv_utils.emulator_drivers.FunctionRunnerEmulatorDriver(self.emu)
        self.index = viv_utils.InstructionFunctionIndex(vivisect_workspace)

    def get_all_function_contexts(self, function_va):
        self.d("Getting function context for function at 0x%08X...", function_va)

        all_contexts = []
        for caller_va in self.get_caller_vas(function_va):
            function_context = self.get_contexts_via_monitor(caller_va, function_va)
            all_contexts.extend(function_context)

        self.d("Got %d function contexts for function at 0x%08X.", len(all_contexts), function_va)
        return all_contexts

    def get_caller_vas(self, function_va):
        # optimization: avoid re-processing the same function repeatedly
        caller_function_vas = set([])
        for caller_va in self.vivisect_workspace.getCallers(function_va):
            self.d("    caller: %s" % hex(caller_va))
            caller_function_va = self.index[caller_va]  # the address of the function that contains this instruction
            self.d("      function: %s" % hex(caller_function_va))
            caller_function_vas.add(caller_function_va)

            # TODO: removeme
            # break
        return caller_function_vas

    def get_contexts_via_monitor(self, fva, target_fva):
        """ run the given function while collecting arguments to a target function """
        monitor = self.setup_monitor(target_fva)
        self.d("    emulating: %s, watching %s" % (hex(self.index[fva]), hex(target_fva)))
        self.driver.runFunction(self.index[fva], maxhit=1, func_only=True)
        contexts = monitor.get_contexts()
        self.driver.remove_monitor(monitor)
        self.d("      results:")
        for c in contexts:
            self.d("        <context>")
        return contexts

    def setup_monitor(self, target_fva):
        monitor = CallMonitor(self.vivisect_workspace, target_fva)
        self.driver.add_monitor(monitor)
        return monitor


def get_function_contexts(vw, fva):
    return FunctionArgumentGetter(vw).get_all_function_contexts(fva)
