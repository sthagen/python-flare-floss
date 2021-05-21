# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import floss.interfaces as interfaces

from . import plugin_object

# TODO skip imports
# print fva in vivisect_workspace.getImports()
# TODO calling convention?
# api = vivisect_workspace.getFunctionApi(fva)
# " Calling convention: %s\n" api[2]


class FunctionCrossReferencesToPlugin(plugin_object.GeneralPlugin):
    """
    Identification based on cross references to functions
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def identify(self, vivisect_workspace, function_vas):
        candidate_functions = {}
        for fva in function_vas:
            xrefs_to = len(vivisect_workspace.getXrefsTo(fva))
            self.d("\nFunction at 0x%08X:\n" " Cross references to: %d\n" % (fva, xrefs_to))
            candidate_functions[fva] = xrefs_to
        return candidate_functions

    def score(self, function_vas, vivisect_workspace=None):
        candidate_functions = {}
        max_cross_references_to = self.get_max_xrefs_to(vivisect_workspace)

        for fva in function_vas:
            xrefs_to = len(vivisect_workspace.getXrefsTo(fva))
            score = 0
            if max_cross_references_to != 0:
                score = float(xrefs_to) / float(max_cross_references_to)
            candidate_functions[fva] = score
        return candidate_functions

    def get_max_xrefs_to(self, vw):
        # find maximum number of cross references to a function
        max_cross_references_to = 0
        for fva in vw.getFunctions():
            xrefs_to = len(vw.getXrefsTo(fva))
            if xrefs_to > max_cross_references_to:
                max_cross_references_to = xrefs_to
        return max_cross_references_to


class FunctionArgumentCountPlugin(plugin_object.GeneralPlugin):
    """
    Identification based on number of function arguments. Score is 1.0 if number of arguments is greater than 0 and
    smaller than 4, It is 0.5 for a number of arguments between 4 and 7, and 0.0 otherwise.
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def identify(self, vivisect_workspace, function_vas):
        candidate_functions = {}
        for fva in function_vas:
            args = vivisect_workspace.getFunctionArgs(fva)
            candidate_functions[fva] = len(args)
            self.d("\nFunction at 0x%08X:\n" " Number of arguments: %d\n" % (fva, len(args)))
        return candidate_functions

    def score(self, function_vas, vivisect_workspace=None):
        candidate_functions = {}
        for fva, arg_len in function_vas.items():
            if arg_len > 0 and arg_len < 4:
                score = 1.0
            elif arg_len >= 4 and arg_len < 7:
                score = 0.5
            else:
                score = 0.0
            candidate_functions[fva] = score
            self.d("\nFunction at 0x%08X:\n" "  Score: %.5f" % (fva, score))
        return candidate_functions

    def __str__(self):
        return self.__class__.__name__

    def __repr__(self):
        return str(self)


class FunctionMetaDataPlugin(plugin_object.GeneralPlugin):
    """
    Abstract class providing functionality for the following meta data plugins
    """

    def get_meta_data(self, vivisect_workspace, function_vas, meta_data_key):
        """
        Return function meta data specified by meta_data_key
        """
        candidate_functions = {}
        for fva in function_vas:
            meta_data = vivisect_workspace.getFunctionMetaDict(fva)
            if meta_data_key in meta_data.keys():
                self.d("Function at 0x%08X has meta data:\n" " %s: %s" % (fva, meta_data_key, meta_data[meta_data_key]))
                candidate_functions[fva] = meta_data[meta_data_key]
        return candidate_functions


class FunctionIsThunkPlugin(FunctionMetaDataPlugin):
    """
    Identify thunk functions. Score is 1.0 if function is thunk, 0.0 otherwise
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def __init__(self):
        FunctionMetaDataPlugin.__init__(self)

    def identify(self, vivisect_workspace, function_vas):
        return self.get_meta_data(vivisect_workspace, function_vas, "Thunk")

    def score(self, function_vas, vivisect_workspace=None):
        candidate_functions = {}
        for fva, is_thunk in function_vas.items():
            if is_thunk:
                candidate_functions[fva] = 1.0
            else:
                candidate_functions[fva] = 0.0
        return candidate_functions


class FunctionBlockCountPlugin(FunctionMetaDataPlugin):
    """
    Count function blocks
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def __init__(self):
        FunctionMetaDataPlugin.__init__(self)

    def identify(self, vivisect_workspace, function_vas):
        return self.get_meta_data(vivisect_workspace, function_vas, "BlockCount")

    def score(self, function_vas, vivisect_workspace=None):
        candidate_functions = {}
        for fva, meta_data_value in function_vas.items():
            score = 0.0 * meta_data_value  # TODO scoring
            candidate_functions[fva] = score
        return candidate_functions


class FunctionInstructionCountPlugin(FunctionMetaDataPlugin):
    """
    Count instructions per function
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def __init__(self):
        FunctionMetaDataPlugin.__init__(self)

    def identify(self, vivisect_workspace, function_vas):
        return self.get_meta_data(vivisect_workspace, function_vas, "InstructionCount")

    def score(self, function_vas, vivisect_workspace=None):
        candidate_functions = {}
        for fva, meta_data_value in function_vas.items():
            score = 0.0 * meta_data_value  # TODO scoring
            candidate_functions[fva] = score
        return candidate_functions


class FunctionSizePlugin(FunctionMetaDataPlugin):
    """
    Count instructions per function
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def __init__(self):
        FunctionMetaDataPlugin.__init__(self)

    def identify(self, vivisect_workspace, function_vas):
        return self.get_meta_data(vivisect_workspace, function_vas, "Size")

    def score(self, function_vas, vivisect_workspace=None):
        candidate_functions = {}
        for fva, meta_data_value in function_vas.items():
            score = 0.0 * meta_data_value  # TODO scoring
            candidate_functions[fva] = score
        return candidate_functions


class FunctionRecursivePlugin(FunctionMetaDataPlugin):
    """
    Count instructions per function
    """

    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def __init__(self):
        FunctionMetaDataPlugin.__init__(self)

    def identify(self, vivisect_workspace, function_vas):
        return self.get_meta_data(vivisect_workspace, function_vas, "Recursive")

    def score(self, function_vas, vivisect_workspace=None):
        candidate_functions = {}
        for fva, meta_data_value in function_vas.items():
            score = 0.0 * meta_data_value  # TODO scoring
            candidate_functions[fva] = score
        return candidate_functions
