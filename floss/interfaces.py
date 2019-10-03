# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

from plugnplay import Interface


class DecodingRoutineIdentifier(Interface):

    """
    Identify a decoding routine.

    Return mapping from function virtual addresses to score of likelihood to be
    a decoding function.
    """

    def identify(self, vivisect_workspace, function_vas):
        """

        :param vivisect_workspace: vivisect workspace for the binary file
        :param function_vas: virtual addresses of functions to analyze
        :return: dictionary {function_va: score}
        """
        pass

    def score(self, function_vas):
        """

        :param function_vas: virtual addresses of functions to be scored
        :return: dictionary {function_va: score}
        """
        pass
