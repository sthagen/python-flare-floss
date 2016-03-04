import string
import functools
from collections import namedtuple

import viv_utils
import envi.memory

from utils import makeEmulator
from FunctionArgumentGetter import get_function_contexts


class DecodedString():

    def __init__(self, va, s, decoded_at_va, fva, global_address=False):
        self.va = va
        self.s = s
        self.decoded_at_va = decoded_at_va
        self.fva = fva
        self.global_address = global_address

    def __str__(self):
        s = "%s %s %s %s %s" % (hex(self.va), self.s, hex(self.decoded_at_va), hex(self.fva), str(self.global_address))
        return s

    def __hash__(self):
        return hash((self.va, self.s, self.decoded_at_va, self.fva, self.global_address))

    def __eq__(self, other):
        return ((self.va, self.s, self.decoded_at_va, self.fva, self.global_address) == \
                (other.va, other.s, other.decoded_at_va, other.fva, other.global_address))


def compute_ascii_string_length(s):
    for i, c in enumerate(s):
        if c not in string.printable:
            return i
    return len(s)


def is_ascii_string(s, min_length=4):
    return compute_ascii_string_length(s) >= min_length


def compute_unicode_string_length(s):
    '''
    mostly from vivisect:detectUnicode

    If the address appears to be the start of a unicode string, then
    return the string length in bytes, else return -1.
    This will return true if the memory location is likely
    *simple* UTF16-LE unicode (<ascii><0><ascii><0><0><0>).
    '''
    maxlen = len(s)
    count = 0
    while count < maxlen:
        c0 = s[count]
        if (count + 1) >= len(s):
            break
        c1 = s[count + 1]

        # If it's not null,char,null,char then it's
        # not simple unicode...
        if ord(c1) != 0:
            break

        # If we find our null terminator after more
        # than 4 chars, we're probably a real string
        if ord(c0) == 0:
            break

        # If the first byte char isn't printable, then
        # we're probably not a real "simple" ascii string
        if c0 not in string.printable:
            break

        count += 2
    return count


def is_unicode_string(s, min_length=4):
    '''
    mostly from vivisect:detectUnicode

    If the address appears to be the start of a unicode string, then
    return the string length in bytes, else return -1.
    This will return true if the memory location is likely
    *simple* UTF16-LE unicode (<ascii><0><ascii><0><0><0>).
    '''
    return compute_unicode_string_length(s) >= (min_length * 2)


def is_string(s, min_length=4):
    if is_ascii_string(s, min_length=min_length):
        return True
    if is_unicode_string(s, min_length=min_length):
        return True
    return False


class DecodingManager(viv_utils.LoggingObject):

    def __init__(self, sample_file_path):
        viv_utils.LoggingObject.__init__(self)
        self.vivisect_workspace = viv_utils.getWorkspace(sample_file_path)

        self.function_index = viv_utils.InstructionFunctionIndex(self.vivisect_workspace)
        # TODO do we need a set for the decoded strings?
        self.decoded_strings = set([])

    def run_decoding(self, function_vas):
        for fva in function_vas:
            self.d("decoding function: %s" % (hex(fva)))
            fd = FunctionDecoder(self.vivisect_workspace, fva, self.function_index)
            fd.invoke_decoding()
            self.decoded_strings.update(set(fd.get_decoded_strings()))

    def print_decoded_strings(self, group_fvas=None, min_length=2):
        decoded_strings = self.get_decoded_strings()
        print "%d strings decoded:" % len(decoded_strings)
        if group_fvas:
            for fva in group_fvas:
                ds_filtered = filter(lambda ds: ds.fva == fva, decoded_strings)
                len_ds = len(ds_filtered)
                if len_ds > 0:
                    print "\nDecoding function at 0x%X (decoded %d strings)" % (fva, len_ds)
                    self.format_strings(ds_filtered, min_length)
        else:
            self.format_strings(decoded_strings, min_length)

    def format_strings(self, ds_filtered, min_length):
        print "Offset       Called At    String"
        print "----------   ----------   -------------------------------------"
        for ds in ds_filtered:
            va = ds.va
            if not va:
                va = 0
            print "0x%08X   0x%08X   %s" % (va, ds.decoded_at_va, self.sanitize_string_print(ds.s))

    def sanitize_string_print(self, str_in):
        sanitized_string = str_in.replace('\n', '\\n')
        sanitized_string = sanitized_string.replace('\r', '\\r')
        sanitized_string = sanitized_string.replace('\t', '\\t')
        sanitized_string = "".join(s for s in sanitized_string if s in string.printable)
        return sanitized_string

    def get_decoded_strings(self, min_length=4):
        ret = []
        queue = list(self.decoded_strings)
        while len(queue) > 0:
            d = queue.pop()
            s = d.s.replace("\x00\x00\x00\x00", "")  # quickly remove large empty regions
            if is_unicode_string(s, min_length=min_length):
                slen = compute_unicode_string_length(s)
                ds = s[:slen].decode("utf-16")
                if ds != "A" * slen:
                    ret.append(DecodedString(d.va, ds, d.decoded_at_va, d.fva, d.global_address))
                queue.append(DecodedString(d.va + slen, s[slen:], d.decoded_at_va, d.fva, d.global_address))
            elif is_ascii_string(s, min_length=min_length):
                slen = compute_ascii_string_length(s)
                ds = s[:slen].decode("ascii")
                if ds != "A" * slen:
                    ret.append(DecodedString(d.va, ds, d.decoded_at_va, d.fva, d.global_address))
                queue.append(DecodedString(d.va + slen, s[slen:], d.decoded_at_va, d.fva, d.global_address))
            else:
                if len(s) > 1:
                    # chop off the first byte, then keep searching
                    queue.append(DecodedString(d.va + 1, s[1:], d.decoded_at_va, d.fva, d.global_address))
        return ret


class FunctionDecoder(viv_utils.LoggingObject):

    def __init__(self, vivisect_workspace, fva, function_index):
        viv_utils.LoggingObject.__init__(self)
        self.vw = vivisect_workspace
        self.emu = makeEmulator(vivisect_workspace)
        self.fva = fva
        self.fer = FunctionEmulator(self.emu, fva, function_index)
        self.decoded_strings = []

    def invoke_decoding(self):
        for function_context in get_function_contexts(self.vw, self.fva):
            self.decode_strings(function_context)

    def decode_strings(self, function_context):
        self.d("Restoring function context")
        self.emu.setEmuSnap(function_context.emu_snap)
        self.d("Emulating function at 0x%08X called at 0x%08X, return address: 0x%08X", self.fva,
               function_context.decoded_at_va, function_context.return_address)
        new_strings = self.fer.emulate_function(function_context.return_address,
                                                dump_strings_fn=functools.partial(self.get_strings_from_memory_diff, function_context))
        self.decoded_strings.extend(new_strings)
        strings = self.get_strings_from_memory_diff(function_context)
        self.decoded_strings.extend(strings)

    # TODO this function is pretty big and ugly
    def get_strings_from_memory_diff(self, function_context):
        strings = []
        # memory snap contains data split up by sections
        _, memory_snap_before = function_context.emu_snap
        memory_snap_after = self.emu.getMemorySnap()
        esp = self.emu.getStackCounter()

        # maps from region start to section tuple
        mem_before = {m[0]: m for m in memory_snap_before}
        mem_after = {m[0]: m for m in memory_snap_after}

        # iterate memory from after the decoding, since if somethings been allocated,
        # we want to know. don't care if things have been deallocated.
        for section_after_start, section_after in mem_after.items():
            (_, _, _, bytes_after) = section_after
            if section_after_start not in mem_before:
                strings.append(DecodedString(section_after_start, bytes_after, function_context.decoded_at_va, self.fva))
                continue

            section_before = mem_before[section_after_start]
            (_, _, _, bytes_before) = section_before

            memory_diff = envi.memory.memdiff(bytes_before, bytes_after)
            for offset, length in memory_diff:
                address = section_after_start + offset

                # every stack address that exceeds the stack pointer can be ignored because it is local
                # to child stack frame
                if self.emu.isStackPointer(address):
                    if address <= esp:
                        continue

                self.d("")
                self.d("ESP=0x%X, VA=0x%X", self.emu.getStackCounter(), address)

                diff_bytes = bytes_after[offset:offset + length]
                global_address = False
                if not self.emu.isStackPointer(address):
                    # address is in global memory
                    global_address = address
                strings.append(DecodedString(address, diff_bytes, function_context.decoded_at_va, self.fva, global_address))

                # TODO we pass difference up now, adjust names
                self.d("memory difference found (offset=0x%08X, len=%d): %s", offset, length, str(diff_bytes))
                self.d("before (offset=0x%08X, len=%d):\n%s", offset, length, " ".join(map(lambda x: "0x%02x" % x, map(ord, bytes_before[offset:offset + length]))))
                self.d("after  (offset=0x%08X, len=%d):\n%s", offset, length, " ".join(map(lambda x: "0x%02x" % x, map(ord, bytes_after[offset:offset + length]))))
                self.dumpStack(self.emu)
        return strings

    def dumpStack(self, emu):
        esp = emu.getStackCounter()
        str = ""
        for i in xrange(16, -16, -4):
            if i == 0:
                sp = "<= SP"
            else:
                sp = "%02d" % i
            str = "%s\n0x%08X - 0x%08X %s" % (str, (esp + i), self.getStackValue(emu, i), sp)
        self.d(str)

    def getStackValue(self, emu, offset):
        return emu.readMemoryFormat(emu.getStackCounter() + offset, "<P")[0]

    def get_decoded_strings(self):
        return self.decoded_strings


class ApiMonitor(viv_utils.emulator_drivers.Monitor):

    def __init__(self, vw, function_index):
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)
        self.function_index = function_index

    def apicall(self, emu, op, pc, api, argv):
        self.d("apicall: %s %s %s %s %s", emu, op, pc, api, argv)

    def prehook(self, emu, op, startpc):
        self.d("%s: %s", hex(startpc), op)

    def posthook(self, emu, op, endpc):
        if op.mnem == "ret":
            try:
                self.check_return(emu, op)
            except Exception as e:
                self.d(str(e))

    def check_return(self, emu, op):
        function_start = self.function_index[op.va]
        return_addresses = self.get_return_vas(emu, function_start)
        return_address = self.getStackValue(emu, -4)
        if return_address not in return_addresses:
            self._logger.debug("Return address 0x%08X is invalid", return_address)
            self.fix_return(emu, return_address, return_addresses)
        else:
            self._logger.debug("Return address 0x%08X is valid, returning", return_address)

    def get_return_vas(self, emu, function_start):
        return_vas = []
        callers = self._vw.getCallers(function_start)
        for caller in callers:
            call_op = emu.parseOpcode(caller)
            return_va = call_op.va + call_op.size
            return_vas.append(return_va)
        return return_vas

    def fix_return(self, emu, return_address, return_addresses):
        """ find correct return address and adjust stack """
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
        esp = emu.getStackCounter()
        str = ""
        for i in xrange(16, -16, -4):
            if i == 0:
                sp = "<= SP"
            else:
                sp = "%02d" % i
            str = "%s\n0x%08X - 0x%08X %s" % (str, (esp + i), self.getStackValue(emu, i), sp)
        self._logger.debug(str)


def pointerSize(emu):
    return emu.imem_psize


def popStack(emu):
    v = emu.readMemoryFormat(emu.getStackCounter(), "<P")[0]
    emu.setStackCounter(emu.getStackCounter() + pointerSize(emu))
    return v


class GetProcessHeapHook(viv_utils.emulator_drivers.Hook):
    def hook(self, callname, emu, callconv, api, argv):
        if callname == "kernel32.GetProcessHeap":
            # nop
            callconv.execCallReturn(emu, 0, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


def round(i, size):
    if i % size == 0:
        return i
    return i + (i - (i % size))


class RtlAllocateHeapHook(viv_utils.emulator_drivers.Hook):
    def __init__(self, *args, **kwargs):
        super(RtlAllocateHeapHook, self).__init__(*args, **kwargs)
        self._heap_addr = 0x69690000

    def _allocate_mem(self, emu, size):
        size = round(size, 0x1000)
        if size > 10 * 1024 * 1024:
            size = 10 * 1024 * 1024
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

    def __init__(self, *args, **kwargs):
        super(ExitProcessHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "kernel32.ExitProcess":
            raise viv_utils.emulator_drivers.StopEmulation()


class IncrementalDiffHook(viv_utils.emulator_drivers.Hook):
    def __init__(self, collected_strings=None, dump_strings_fn=None, *args, **kwargs):
        if collected_strings is None:
            raise RuntimeError("required argument: collected_strings")

        if dump_strings_fn is None:
            raise RuntimeError("required argument: dump_strings_fn")

        self._collected_strings = collected_strings
        self._dump_strings_fn = dump_strings_fn

    def hook(self, callname, driver, callconv, api, argv):
        if is_import(driver._emu, driver._emu.getProgramCounter()):
            for s in self._dump_strings_fn():
                self._collected_strings.add(s)


def is_import(emu, va):
    # TODO: also check location type
    t = emu.getVivTaint(va)
    if t is None:
        return False
    return t[1] == "import"


class FunctionEmulator(viv_utils.LoggingObject):

    def __init__(self, emu, fva, function_index):
        viv_utils.LoggingObject.__init__(self)
        self.emu = emu
        self.fva = fva
        self.function_index = function_index

    # TODO make max_instruction_count value changeable globally?
    def emulate_function(self, return_address, max_instruction_count=2000, dump_strings_fn=None):
        collected_strings = set([])
        try:
            self.d("Emulating function at 0x%08X", self.fva)
            driver = viv_utils.emulator_drivers.DebuggerEmulatorDriver(self.emu)
            monitor = ApiMonitor(self.emu.vw, self.function_index)
            driver.add_monitor(monitor)
            driver.add_hook(IncrementalDiffHook(collected_strings=collected_strings, dump_strings_fn=dump_strings_fn))
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
        return collected_strings
