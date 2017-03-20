# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import plugnplay
import viv_utils


# TODO rename to Plugin, rename file
class GeneralPlugin(plugnplay.Plugin, viv_utils.LoggingObject):
    def __str__(self):
        return self.__class__.__name__

    def __repr__(self):
        return str(self)

    def get_name_version(self):
        return "%s (v%s)" % (str(self), self.version)
