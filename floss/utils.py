import types

import envi.memory as e_mem
import envi.bits as e_bits
import visgraph.pathcore as vg_path

from vivisect.impemu.emulator import WorkspaceEmulator
from vivisect.const import LOC_IMPORT


ONE_MB = 1024 * 1024
STACK_MEM_NAME = "[stack]"


def flossReadMemory(self, va, size):
    """
    This is directly copied from vivisect/impemu/emulator.py.
    The only change is that we return non-ASCII characters (0x90) instead of 'A's if probing the memory fails.
    This gets rid of many AAA... false positive decoded strings.
    :param self: emulator instance
    :param va: virtual address of requested memory
    :param size: size of requested memory
    :return: requested memory or '\x90' if memory hasn't been resolved yet
    """
    if self.logread:
        rlog = vg_path.getNodeProp(self.curpath, 'readlog')
        rlog.append((self.getProgramCounter(),va,size))

    # If they read an import entry, start a taint...
    loc = self.vw.getLocation(va)
    if loc != None:
        lva, lsize, ltype, ltinfo = loc
        if ltype == LOC_IMPORT and lsize == size:  # They just read an import.
            ret = self.setVivTaint('import', loc)
            return e_bits.buildbytes(ret, lsize)

    self._useVirtAddr(va)

    # Read from the emulator's pages if we havent resolved it yet
    probeok = self.probeMemory(va, size, e_mem.MM_READ)
    if self._safe_mem and not probeok:
        return '\0x90' * size  # 0x90 is non-ASCII and NOP instruction in x86

    return e_mem.MemoryObject.readMemory(self, va, size)


def makeEmulator(vw):
    """
    create an emulator using consistent settings.
    """
    emu = vw.getEmulator(logwrite=True)
    emu.readMemory = types.MethodType(flossReadMemory, emu)  # patch readMemory function in emulator object
    removeStackMemory(emu)
    emu.initStackMemory(stacksize=int(0.5 * ONE_MB))
    emu.setStackCounter(emu.getStackCounter() - int(0.25 * ONE_MB))
    emu.setEmuOpt('i386:reponce', False)  # do not short circuit rep prefix
    return emu


def removeStackMemory(emu):
    # TODO this is a hack while vivisect's initStackMemory() has a bug (see issue #27)
    # TODO does this bug still exist?
    memory_snap = emu.getMemorySnap()
    for i in xrange((len(memory_snap) - 1), -1, -1):
        (_, _, info, _) = memory_snap[i]
        if info[3] == STACK_MEM_NAME:
            del memory_snap[i]
            emu.setMemorySnap(memory_snap)
            emu.stack_map_base = None
            return
    raise Exception  # STACK_MEM_NAME not in memory map
