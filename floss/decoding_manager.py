from collections import namedtuple

import viv_utils
import envi.memory


DecodedString = namedtuple("DecodedString", ["va", "s", "decoded_at_va", "fva", "global_address"])


class ApiMonitor(viv_utils.emulator_drivers.Monitor):
    '''
    The ApiMonitor observes emulation and provides an interface
     for hooking API calls.
    '''
    def __init__(self, vw, function_index):
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)
        self.function_index = function_index

    def apicall(self, emu, op, pc, api, argv):
        # overridden from Monitor
        self.d("apicall: %s %s %s %s %s", emu, op, pc, api, argv)

    def prehook(self, emu, op, startpc):
        # overridden from Monitor
        self.d("%s: %s", hex(startpc), op)

    def posthook(self, emu, op, endpc):
        # overridden from Monitor
        if op.mnem == "ret":
            try:
                self._check_return(emu, op)
            except Exception as e:
                self.d(str(e))

    def _check_return(self, emu, op):
        '''
        Ensure that the target of the return is within the allowed set of functions.
        TODO(mr): describes what happens on success, failure.
        '''
        function_start = self.function_index[op.va]
        return_addresses = self._get_return_vas(emu, function_start)
        return_address = self.getStackValue(emu, -4)
        if return_address not in return_addresses:
            self._logger.debug("Return address 0x%08X is invalid", return_address)
            self._fix_return(emu, return_address, return_addresses)
        else:
            self._logger.debug("Return address 0x%08X is valid, returning", return_address)

    def _get_return_vas(self, emu, function_start):
        '''
        Get the list of valid addresses to which a function should return.
        '''
        return_vas = []
        callers = self._vw.getCallers(function_start)
        for caller in callers:
            call_op = emu.parseOpcode(caller)
            return_va = call_op.va + call_op.size
            return_vas.append(return_va)
        return return_vas

    def _fix_return(self, emu, return_address, return_addresses):
        '''
        find correct return address and adjust stack.
        TODO(mr): what does "correct" mean? how does the stack get adjusted? for what purpose?
        '''
        self.dumpStack(emu)
        NUM_ADDRESSES = 4
        pointer_size = emu.getPointerSize()
        STACK_SEARCH_WINDOW = pointer_size * NUM_ADDRESSES
        esp = emu.getStackCounter()
        for offset in xrange(0, STACK_SEARCH_WINDOW, pointer_size):
            ret_va_candidate = self.getStackValue(emu, offset)
            if ret_va_candidate in return_addresses:
                emu.setProgramCounter(ret_va_candidate)
                emu.setStackCounter(esp + offset + pointer_size)
                self._logger.debug("Returning to 0x%08X, adjusted stack:", ret_va_candidate)
                self.dumpStack(emu)
                return

        self.dumpStack(emu)
        raise Exception("No valid return address found...")

    def dumpStack(self, emu):
        '''
        Convenience debugging routine for showing
         state current state of the stack.
        '''
        esp = emu.getStackCounter()
        stack_str = ""
        for i in xrange(16, -16, -4):
            if i == 0:
                sp = "<= SP"
            else:
                sp = "%02d" % i
            stack_str = "%s\n0x%08X - 0x%08X %s" % (stack_str, (esp + i), self.getStackValue(emu, i), sp)
        self._logger.debug(stack_str)


def pointerSize(emu):
    '''
    Convenience method whose name might be more readable
     than fetching emu.imem_psize.
    Returns the size of a pointer in bytes for the given emulator.
    :rtype: int
    '''
    return emu.imem_psize


def popStack(emu):
    '''
    Remove the element at the top of the stack.
    :rtype: int
    '''
    v = emu.readMemoryFormat(emu.getStackCounter(), "<P")[0]
    emu.setStackCounter(emu.getStackCounter() + pointerSize(emu))
    return v


class GetProcessHeapHook(viv_utils.emulator_drivers.Hook):
    '''
    Hook and handle calls to GetProcessHeap, returning 0.
    '''
    def hook(self, callname, emu, callconv, api, argv):
        if callname == "kernel32.GetProcessHeap":
            # nop
            callconv.execCallReturn(emu, 0, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


def round(i, size):
    '''
    Round `i` to the nearest greater-or-equal-to multiple of `size`.

    :type i: int
    :type size: int
    :rtype: int
    '''
    if i % size == 0:
        return i
    return i + (i - (i % size))


class RtlAllocateHeapHook(viv_utils.emulator_drivers.Hook):
    '''
    Hook calls to RtlAllocateHeap, allocate memory in a "heap"
     section, and return pointers to this memory.
    The base heap address is 0x69690000.
    The max allocation size is 10 MB.
    '''
    def __init__(self, *args, **kwargs):
        super(RtlAllocateHeapHook, self).__init__(*args, **kwargs)
        self._heap_addr = 0x69690000

    MAX_ALLOCATION_SIZE = 10 * 1024 * 1024
    def _allocate_mem(self, emu, size):
        size = round(size, 0x1000)
        if size > self.MAX_ALLOCATION_SIZE:
            size = self.MAX_ALLOCATION_SIZE
        va = self._heap_addr
        self.d("RtlAllocateHeap: mapping %s bytes at %s", hex(size), hex(va))
        emu.addMemoryMap(va, envi.memory.MM_RWX, "[heap allocation]", "\x00" * (size + 4))
        emu.writeMemory(va, "\x00" * size)
        self._heap_addr += size
        return va

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "ntdll.RtlAllocateHeap":
            emu = driver
            size = driver.getStackValue(0xC)
            va = self._allocate_mem(emu, size)
            callconv.execCallReturn(emu, va, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class AllocateHeap(RtlAllocateHeapHook):
    '''
    Hook calls to AllocateHeap and handle them like calls to RtlAllocateHeapHook.
    '''
    def __init__(self, *args, **kwargs):
        super(AllocateHeap, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "kernel32.LocalAlloc":
            emu = driver
            size = driver.getStackValue(0x8)
            va = self._allocate_mem(emu, size)
            callconv.execCallReturn(emu, va, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class MallocHeap(RtlAllocateHeapHook):
    '''
    Hook calls to malloc and handle them like calls to RtlAllocateHeapHook.
    '''
    def __init__(self, *args, **kwargs):
        super(MallocHeap, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.malloc":
            emu = driver
            size = driver.getStackValue(0x4)
            va = self._allocate_mem(emu, 0x100)  # TODO hard-coded!
            callconv.execCallReturn(emu, va, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class ExitProcessHook(viv_utils.emulator_drivers.Hook):
    '''
    Hook calls to ExitProcess and stop emulation when these are hit.
    '''
    def __init__(self, *args, **kwargs):
        super(ExitProcessHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "kernel32.ExitProcess":
            raise viv_utils.emulator_drivers.StopEmulation()


def is_import(emu, va):
    '''
    Return True if the given VA is that of an imported function.
    '''
    # TODO: also check location type
    t = emu.getVivTaint(va)
    if t is None:
        return False
    return t[1] == "import"


# A snapshot represents the current state of the CPU and memory
Snapshot = namedtuple("Snapshot",
        [   "memory",  # The memory snapshot, type: envi.MemorySnapshot
            "sp",  # The current stack counter, type: int
            "pc",  # The current instruction pointer, type: int
            ])


def make_snapshot(emu):
    '''
    Create a snapshot of the current CPU and memory.

    :rtype: Snapshot
    '''
    return Snapshot(emu.getMemorySnap(), emu.getStackCounter(), emu.getProgramCounter())


# A Delta represents the pair of snapshots from before and
#  after an operation. It facilitates diffing the state of
#  an emalutor.
Delta = namedtuple("Delta",
        [   "pre_snap",  # type: Snapshot
            "post_snap",  # type: Snapshot
            ])


class DeltaCollectorHook(viv_utils.emulator_drivers.Hook):
    """
    hook that collects Deltas at each imported API call.
    """
    def __init__(self, pre_snap):
        super(DeltaCollectorHook, self).__init__()

        self._pre_snap = pre_snap
        # this is a public field
        self.deltas = []

    def hook(self, callname, driver, callconv, api, argv):
        if is_import(driver._emu, driver._emu.getProgramCounter()):
            self.deltas.append(Delta(self._pre_snap, make_snapshot(driver._emu)))


class FunctionEmulator(viv_utils.LoggingObject):
    def __init__(self, emu, fva, function_index):
        viv_utils.LoggingObject.__init__(self)
        self.emu = emu
        self.fva = fva
        self.function_index = function_index

    def emulate_function(self, return_address, max_instruction_count):
        pre_snap = make_snapshot(self.emu)
        delta_collector = DeltaCollectorHook(pre_snap)

        try:
            self.d("Emulating function at 0x%08X", self.fva)
            driver = viv_utils.emulator_drivers.DebuggerEmulatorDriver(self.emu)
            monitor = ApiMonitor(self.emu.vw, self.function_index)
            driver.add_monitor(monitor)
            driver.add_hook(delta_collector)
            driver.add_hook(GetProcessHeapHook())
            driver.add_hook(RtlAllocateHeapHook())
            driver.add_hook(AllocateHeap())
            driver.add_hook(MallocHeap())
            driver.add_hook(ExitProcessHook())
            driver.runToVa(return_address, max_instruction_count)
        except viv_utils.emulator_drivers.InstructionRangeExceededError:
            self.d("Halting as emulation has escaped!")
        except envi.InvalidInstruction:
            self.d("vivisect encountered an invalid instruction. will continue processing.", exc_info=True)
        except envi.UnsupportedInstruction:
            self.d("vivisect encountered an unsupported instruction. will continue processing.", exc_info=True)
        except envi.BreakpointHit:
            self.d("vivisect encountered an unexpected emulation breakpoint. will continue processing.", exc_info=True)
        except viv_utils.emulator_drivers.StopEmulation as e:
            pass
        except Exception:
            self.d("vivisect encountered an unexpected exception. will continue processing.", exc_info=True)
        self.d("Ended emulation at 0x%08X", self.emu.getProgramCounter())

        deltas = delta_collector.deltas
        deltas.append(Delta(pre_snap, make_snapshot(self.emu)))
        return deltas
