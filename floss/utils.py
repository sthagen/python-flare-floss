from collections import OrderedDict

ONE_MB = 1024 * 1024
STACK_MEM_NAME = "[stack]"


def makeEmulator(vw):
    """
    create an emulator using consistent settings.
    """
    emu = vw.getEmulator(logwrite=True, taintbyte='\x90')
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


def get_vivisect_meta_info(vw, selected_functions=None):
    info = OrderedDict()
    functions = vw.getFunctions()
    info["Total number of functions"] = len(functions)
    # arch, segments, codeblocks, metadata,
    # filemeta, entry point,
    print vw.getEntryPoints()
    # print vw.getFileMeta()
    print vw.getFiles()
    print vw.getDiscoveredInfo()
    print vw.getStats()

    print vw.getMeta("Architecture")
    print vw.getMeta("Platform")
    print vw.getMeta("ExeName")
    print vw.getMeta("Format")
    print vw.getMeta("StorageName")

    basename = vw.getFileByVa(vw.getEntryPoints()[0])
    if basename is not None:
        baseva = vw.getFileMeta(basename, 'imagebase')
        print hex(baseva)
        print vw.getFileMeta(basename, 'Version')

    ["#functions", "size", "md5sum", ]
    if selected_functions:
        meta = []
        xreflist = []
        # TODO tabulate
        for fva in selected_functions:
            xrefs_to = len(vw.getXrefsTo(fva))
            num_args = len(vw.getFunctionArgs(fva))
            function_meta = vw.getFunctionMetaDict(fva)
            instr_count = function_meta["InstructionCount"]
            block_count = function_meta["BlockCount"]
            size = function_meta["Size"]

            meta.append(("0x%x" % fva, xrefs_to, num_args, size, block_count, instr_count))
        import tabulate

        info["Candidate Function Meta Info"] = "\n%s" % tabulate.tabulate(meta, headers=["fva", "#xrefs", "#args", "size", "#blocks", "#instructions"])
    return info
