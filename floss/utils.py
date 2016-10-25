import logging

from vivisect import VivWorkspace
import envi.memory as e_mem


floss_logger = logging.getLogger("utils")

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


def get_shellcode_workspace(sample_file_path, base, entry_point, should_save=False):
    """
    Load shellcode into memory object and generate vivisect workspace.
    :param sample_file_path: input file path
    :param base: base address where shellcode will be loaded
    :param entry_point: entry point of shellcode
    :return: vivisect workspace
    """
    vw = VivWorkspace()  # thanks Tom
    # TODO other archs, easily determined?
    arch = 'i386'
    platform = 'windows'
    vw.setMeta('Architecture', arch)
    vw.setMeta('Platform', platform)
    vw.setMeta('Format', 'pe')
    vw.setMeta("StorageName", "%s.viv" % sample_file_path)
    vw._snapInAnalysisModules()

    with open(sample_file_path, "rb") as f:
        bytes = f.read()
        vw.addMemoryMap(base, e_mem.MM_RWX, 'shellcode', bytes)
        vw.addSegment(base, len(bytes), 'shellcode_0x%x' % base, 'blob')

    vw.addEntryPoint(base + entry_point)
    vw.analyze()

    if should_save:
        vw.saveWorkspace()

    return vw
