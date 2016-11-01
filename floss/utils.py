import tabulate
from collections import OrderedDict

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


def get_vivisect_meta_info(vw, selected_functions):
    info = OrderedDict()
    entry_points = vw.getEntryPoints()
    basename = None
    if entry_points:
        basename = vw.getFileByVa(entry_points[0])
    if basename:
        version = vw.getFileMeta(basename, 'Version')
        md5sum = vw.getFileMeta(basename, 'md5sum')
        baseva = hex(vw.getFileMeta(basename, 'imagebase'))
    else:
        version = "N/A"
        md5sum = "N/A"
        baseva = "N/A"

    info["Version"] = version
    info["MD5 Sum"] = md5sum
    info["Format"] = vw.getMeta("Format")
    info["Architecture"] = vw.getMeta("Architecture")
    info["Platform"] = vw.getMeta("Platform")
    disc, undisc = vw.getDiscoveredInfo()
    info["Percentage of discovered executable surface area"] = "%.1f%% (%s / %s)" % (disc * 100.0 / (disc + undisc), disc, disc + undisc)
    info["Base VA"] = baseva
    info["Entry point(s)"] = ", ".join(map(hex, entry_points))
    info["Number of imports"] = len(vw.getImports())
    info["Number of exports"] = len(vw.getExports())
    info["Number of functions"] = len(vw.getFunctions())
    if selected_functions:
        meta = []
        for fva in selected_functions:
            xrefs_to = len(vw.getXrefsTo(fva))
            num_args = len(vw.getFunctionArgs(fva))
            function_meta = vw.getFunctionMetaDict(fva)
            instr_count = function_meta["InstructionCount"]
            block_count = function_meta["BlockCount"]
            size = function_meta["Size"]
            meta.append((hex(fva), xrefs_to, num_args, size, block_count, instr_count))
        info["Selected functions' info"] = "\n%s" % tabulate.tabulate(meta, headers=["fva", "#xrefs", "#args", "size", "#blocks", "#instructions"])
    return info


def hex(i):
    return "0x%X" % (i)
