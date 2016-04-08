import viv_utils


class ArgumentMonitor(viv_utils.emulator_drivers.Monitor):
    def __init__(self, vw):
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)

    def prehook(self, emu, op, starteip):
        self._logger.debug("prehook: %s: %s", hex(starteip), op)

    def apicall(self, emu, op, pc, api, argv):
        self._logger.debug("apicall: %s %s %s %s", op, pc, api, argv)
