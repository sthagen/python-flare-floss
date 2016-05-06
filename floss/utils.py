ONE_MB = 1024 * 1024
STACK_MEM_NAME = "[stack]"


def makeEmulator(vw):
    """
    create an emulator using consistent settings.
    """
    emu = vw.getEmulator(logwrite=True)
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
