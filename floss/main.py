#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
import os
import sys
import logging
import pkg_resources
import operator
from time import time
from optparse import OptionParser

import plugnplay
import viv_utils

from DecodingManager import DecodingManager
from interfaces import DecodingRoutineIdentifier
import plugins.xor_plugin
import plugins.library_function_plugin
import plugins.function_meta_data_plugin


floss_logger = logging.getLogger("floss")


# TODO add --plugin_dir switch at some point
def get_all_plugins():
    ps = DecodingRoutineIdentifier.implementors()
    if len(ps) == 0:
        ps.append(plugins.function_meta_data_plugin.FunctionCrossReferencesToPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionArgumentCountPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionIsThunkPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionBlockCountPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionInstructionCountPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionSizePlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionRecursivePlugin())
        ps.append(plugins.library_function_plugin.FunctionIsLibraryPlugin())
        ps.append(plugins.xor_plugin.XORSimplePlugin())
    return ps


class StringDecoder(viv_utils.LoggingObject):

    def __init__(self):
        viv_utils.LoggingObject.__init__(self)

        self.decoder_config = StringDecoderConfig()
        self.decoding_manager = DecodingManager(self.decoder_config.get_sample_path())
        self.functions_to_analyze = []

    def identify_decoding_functions(self):
        self.identification_manager = IdentificationManager(self.decoder_config)
        self.identification_manager.run_plugins()
        self.identification_manager.apply_plugin_weights()

    def print_top(self, n=10):
        self.identification_manager.print_top(n)

    def decode_strings(self):
        if self.decoder_config.options.functions:
            self.functions_to_analyze = self.decoder_config.get_functions_to_analyze()
        else:
            # run on top 10 functions for now
            self.functions_to_analyze = self.identification_manager.get_top_candidate_functions(10)
        self.decoding_manager.run_decoding(self.functions_to_analyze)

    def print_decoded_strings(self):
        if self.decoder_config.options.group_functions:
            self.decoding_manager.print_decoded_strings(group_fvas=self.functions_to_analyze)
        else:
            self.decoding_manager.print_decoded_strings()

    def create_idapython_script(self):
        idapython_file = os.path.abspath(self.decoder_config.options.ida_python_file)
        script_content = self.create_script_content()
        try:
            f = open(idapython_file, "w")
            try:
                f.write(script_content)
                print("\nWrote IDAPython script file to %s" % idapython_file)
            finally:
                f.close()
        except Exception as e:
            raise e

    def create_script_content(self):
        main_commands = []
        decoded_strings = self.decoding_manager.get_decoded_strings()  # TODO just to get_decoded_strings?
        for ds in decoded_strings:
            if ds.s != "":
                sanitized_string = self.sanitize_string_script(ds.s)
                if ds.global_address:
                    main_commands.append("AppendComment(%d, \"FLOSS: %s\", True)" % (ds.global_address, sanitized_string))
                    main_commands.append("print \"FLOSS: string \\\"%s\\\" at global VA 0x%X\"" % (sanitized_string, ds.global_address))
                else:
                    main_commands.append("AppendComment(%d, \"FLOSS: %s\")" % (ds.decoded_at_va, sanitized_string))
                    main_commands.append("print \"FLOSS: string \\\"%s\\\" decoded at VA 0x%X\"" % (sanitized_string, ds.decoded_at_va))
        main_commands.append("print \"Imported %d decoded strings from FLOSS\"" % len(decoded_strings))
        script_content = """from idc import MakeComm, MakeRptCmt


def AppendComment(ea, s, repeatable=False):
    # see williutils and http://blogs.norman.com/2011/security-research/improving-ida-analysis-of-x64-exception-handling
    string = Comment(ea)
    if not string:
        string = s
    else:
        if s in string:  # ignore duplicates
            return
        string = string + "\\n" + s
    if repeatable:
        MakeRptCmt(ea, string)
    else:
        MakeComm(ea, string)


def main():
    print "Annotating decoded strings for %s"
    %s

if __name__ == "__main__":
    main()
""" % (self.decoder_config.sample_file_path, "\n    ".join(main_commands))
        return script_content

    def sanitize_string_script(self, str_in):
        sanitized_string = self.decoding_manager.sanitize_string_print(str_in)
        sanitized_string = sanitized_string.replace('\\', '\\\\')
        sanitized_string = sanitized_string.replace('\"', '\\\"')
        return sanitized_string


class StringDecoderConfig(viv_utils.LoggingObject):

    def __init__(self):
        viv_utils.LoggingObject.__init__(self)

        self.args = None
        self.options = None
        self.sample_file_path = None
        self.vivisect_workspace = None
        self.functions_to_analyze = []
        self.selected_plugins = None

        self.load_plugins()
        self.configure()

    def load_plugins(self):
        """
        Get path to plugins and load them into plugnplay
        """
        # note: need to update if the setup.py module names change
        MODULE_NAME = "floss"
        req = pkg_resources.Requirement.parse(MODULE_NAME)
        requested_directory = os.path.join(MODULE_NAME, "plugins")
        try:
            plugins_path = pkg_resources.resource_filename(req, requested_directory)

            plugnplay.plugin_dirs = [plugins_path]
            plugnplay.load_plugins(logging.getLogger("plugin_loader"))
        except pkg_resources.DistributionNotFound as e:
            self.i("failed to load extra plugins: %s", e)

    def configure(self):
        parser = self.get_OptionParser()
        (self.options, self.args) = parser.parse_args()

        self.set_logging_level()

        if self.options.list_plugins:
            self.print_plugin_list()
            sys.exit(0)

        TRY_HELP_MSG = "Try '%s -h' for more information" % parser.get_prog_name()

        # TODO handle multiple files?
        if len(self.args) != 1:
            parser.error("Please provide a valid file path\n%s" % TRY_HELP_MSG)

        self.sample_file_path = self.args[0]
        # TODO handle directories?
        if not os.path.isfile(self.sample_file_path):
            parser.error("'%s' is not a file\n%s" % (self.sample_file_path, TRY_HELP_MSG))
        if not os.path.exists(self.sample_file_path):
            parser.error("File '%s' does not exist\n%s" % (self.sample_file_path, TRY_HELP_MSG))

        self.vivisect_workspace = viv_utils.getWorkspace(self.sample_file_path)

        self.functions_to_analyze = self.select_functions()

        self.selected_plugins = self.select_plugins()

    def get_OptionParser(self):
        usage_message = "%prog [options] FILEPATH"
        parser = OptionParser(usage=usage_message, version="%prog 0.1")
        parser.add_option("-v", "--verbose", dest="verbose",
                          help="show verbose messages and warnings", action="store_true")

        parser.add_option("-d", "--debug", dest="debug",
                          help="show all trace messages", action="store_true")

        parser.add_option("-f", "--functions", dest="functions",
                          help="only analyze the specified functions",
                          type="string")

        parser.add_option("-g", "--group", dest="group_functions",
                          help="group output by virtual address of decoding functions",
                          action="store_true")
        parser.add_option("-i", "--ida", dest="ida_python_file",
                          help="create an IDAPython script to annotate the decoded strings in an IDB file")

        # TODO be able to provide multiple plugins
        parser.add_option("-p", "--plugin", dest="plugin",
                          help="apply the specified identification plugin only")
        parser.add_option("-l", "--list-plugins", dest="list_plugins",
                          help="list all available identification plugins and exit",
                          action="store_true")
        # TODO add switch to skip identification if function is provided?
        # TODO add examples
        return parser

    def set_logging_level(self):
        # reset .basicConfig root handler
        # via: http://stackoverflow.com/a/2588054
        root = logging.getLogger()
        if root.handlers:
            for handler in root.handlers:
                root.removeHandler(handler)

        if self.options.debug:
            logging.basicConfig(level=logging.DEBUG)
        elif self.options.verbose:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

            # ignore messages like:
            # WARNING:EmulatorDriver:error during emulation of function: BreakpointHit at 0x1001fbfb
            # ERROR:EmulatorDriver:error during emulation of function ... DivideByZero: DivideByZero at 0x10004940
            # TODO: probably should should modify emulator driver to de-prioritize this
            logging.getLogger("EmulatorDriver").setLevel(logging.CRITICAL)

            # ignore messages like:
            # WARNING:Monitor:logAnomaly: anomaly: BreakpointHit at 0x1001fbfb
            logging.getLogger("Monitor").setLevel(logging.ERROR)

            # ignore messages like:
            # WARNING:envi/codeflow.addCodeFlow:parseOpcode error at 0x1001044c: InvalidInstruction("'660f3a0fd90c660f7f1f660f6fe0660f' at 0x1001044c",)
            logging.getLogger("envi/codeflow.addCodeFlow").setLevel(logging.ERROR)

            # ignore messages like:
            # WARNING:plugins.xor_plugin.XORSimplePlugin:identify: Invalid instruction encountered in basic block, skipping: 0x4a0637
            logging.getLogger("plugins.xor_plugin.XORSimplePlugin").setLevel(logging.ERROR)

    def print_plugin_list(self):
            print("Available plugins:")
            print("\n".join([" - %s" % plugin.get_name_version() for plugin in get_all_plugins()]))

    def select_functions(self):
        workspace_functions = self.vivisect_workspace.getFunctions()

        if self.options.functions:
            if "," in self.options.functions:
                fva_string_split = self.options.functions.split(",")
                function_vas = [int(fva, 0x10) for fva in fva_string_split]
            else:
                function_vas = [int(self.options.functions, 0x10)]

            selected_functions = []
            for function in function_vas:
                if function in workspace_functions:
                    selected_functions.append(function)
                else:
                    self.i("0x%08X is not a function", self.options.functions)
                    raise Exception("Function NotFound")
            self.d("Selected the following functions: %s", ", ".join(map(hex, selected_functions)))
        else:
            selected_functions = workspace_functions
            self.d("Selected all %d functions", len(selected_functions))

        return selected_functions

    # TODO pass list of strings or list of identifier objects?
    def select_plugins(self):
        selected_plugins = []
        all_plugin_names = map(str, get_all_plugins())

        if self.options.plugin:
            if self.options.plugin in all_plugin_names:
                selected_plugins.append(self.options.plugin)
                self.d("Selected the following plugins: %s", ", ".join(selected_plugins))
            else:
                raise Exception("Plugin not found")
        else:
            selected_plugins = all_plugin_names
            self.d("Selected all %d plugins", len(selected_plugins))
        return selected_plugins

    def get_sample_path(self):
        return self.sample_file_path

    def get_functions_to_analyze(self):
        return self.functions_to_analyze

    def get_selected_plugins(self):
        return self.selected_plugins


class IdentificationManager(viv_utils.LoggingObject):
    PLUGIN_WEIGHTS = {"XORSimplePlugin": 0.5,
                      "FunctionCrossReferencesToPlugin": 0.2,
                      "FunctionArgumentCountPlugin": 0.2,
                      "FunctionIsThunkPlugin": -1.0,
                      "FunctionBlockCountPlugin": 0.025,
                      "FunctionInstructionCountPlugin": 0.025,
                      "FunctionSizePlugin": 0.025,
                      "FunctionRecursivePlugin": 0.025,
                      "FunctionIsLibraryPlugin": -1.0,}

    def __init__(self, decoder_config):
        viv_utils.LoggingObject.__init__(self)

        self.function_vas = decoder_config.get_functions_to_analyze()
        self.plugins = decoder_config.get_selected_plugins()
        self.sample_file_path = decoder_config.sample_file_path
        self.vivisect_workspace = decoder_config.vivisect_workspace
        self.candidate_functions = {}
        self.candidates_weighted = None

    def run_plugins(self, raw_data=False):

        plugins_to_run = []
        for identifier in get_all_plugins():
            if str(identifier) in self.plugins:
                plugins_to_run.append(identifier)

        for identifier in plugins_to_run:
            # identifier =
            plugin_candidates = identifier.identify(self.vivisect_workspace, self.function_vas)
            if raw_data:
                self.merge_candidates(str(identifier), plugin_candidates)
            else:
                scored_candidates = identifier.score(plugin_candidates, self.vivisect_workspace)
                self.merge_candidates(str(identifier), scored_candidates)

    def merge_candidates(self, plugin_name, plugin_candidates):
        """
        Merge data from all plugins into candidate_functions dictionary.
        """

        if not plugin_candidates:
            return self.candidate_functions

        for candidate_function in plugin_candidates:
            if candidate_function in self.candidate_functions.keys():
                self.d("Function at 0x%08X is already in candidate list, merging", candidate_function)
                self.candidate_functions[candidate_function][plugin_name] = plugin_candidates[candidate_function]
            else:
                self.d("Function at 0x%08X is new, adding", candidate_function)
                self.candidate_functions[candidate_function] = {}
                self.candidate_functions[candidate_function][plugin_name] = plugin_candidates[candidate_function]

    def apply_plugin_weights(self):
        """
        Return {effective_function_address: weighted_score}, the weighted score is a sum of the score a
        function received from each plugin multiplied by the plugin's weight. The
        :param candidate_functions: dictionary storing {effective_function_addresses: {plugin_name: score}}
        :param plugin_weights: dictionary storing {plugin_name: weight}
        :return: dictionary storing {effective_function_address: total score}
        """
        logger = logging.getLogger(__name__)

        functions_weighted = {}
        for candidate_function, plugin_score in self.candidate_functions.items():
            logger.debug("0x%08X" % candidate_function)
            total_score = 0.0
            for plugin_name, score in plugin_score.items():
                if plugin_name not in self.PLUGIN_WEIGHTS.keys():
                    raise Exception("Plugin weight not found: %s" % plugin_name)
                logger.debug("[%s] %.05f (weight) * %.05f (score) = %.05f" % (plugin_name, self.PLUGIN_WEIGHTS[plugin_name],
                                                                              score, self.PLUGIN_WEIGHTS[plugin_name] * score))
                total_score = total_score + (self.PLUGIN_WEIGHTS[plugin_name] * score)
            logger.debug("Total score: %.05f\n" % total_score)
            functions_weighted[candidate_function] = total_score

        self.candidates_weighted = functions_weighted

    def sort_candidates_by_score(self):
        # via http://stackoverflow.com/questions/613183/sort-a-python-dictionary-by-value
        return sorted(self.candidates_weighted.items(), key=operator.itemgetter(1), reverse=True)

    def print_top(self, n=10):
        print("\nMost likely decoding functions in %s:" % self.sample_file_path)
        print("address:    score:  ")
        print("----------  -------")
        for fva, score in self.sort_candidates_by_score()[:n]:
            print("0x%08X: %.5f" % (fva, score))

    def get_top_candidate_functions(self, n=10):
        return [fva for fva, _ in self.sort_candidates_by_score()[:n]]

    def get_candidate_functions(self):
        return self.candidate_functions

    def get_forced_functions(self):
        return self.forced_candidates


def main():
    # default to INFO, unless otherwise changed
    logging.basicConfig(level=logging.INFO)

    time0 = time()
    string_decoder = StringDecoder()
    floss_logger.info("identifying decoding functions...")
    string_decoder.identify_decoding_functions()
    string_decoder.print_top()
    floss_logger.info("decoding strings...")
    string_decoder.decode_strings()
    string_decoder.print_decoded_strings()
    if string_decoder.decoder_config.options.ida_python_file:
        floss_logger.info("generating IDA script...")
        string_decoder.create_idapython_script()

    time1 = time()
    print("Finished execution after %f seconds" % (time1-time0))


if __name__ == "__main__":
    main()
