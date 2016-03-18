#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
import os
import sys
import string
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


def print_plugin_list():
    print("Available plugins:")
    print("\n".join([" - %s" % plugin.get_name_version() for plugin in get_all_plugins()]))


class StringDecoder(viv_utils.LoggingObject):

    def __init__(self, vw):
        viv_utils.LoggingObject.__init__(self)
        self.vw = vw

    def identify_decoding_functions(self, plugins, functions):
        identification_manager = IdentificationManager(self.vw, plugins)
        identification_manager.run_plugins(functions)
        identification_manager.apply_plugin_weights()
        return identification_manager

    def decode_strings(self, functions):
        decoding_manager = DecodingManager(self.vw)
        decoding_manager.run_decoding(functions)
        return decoding_manager


def sanitize_string_for_printing(s):
    sanitized_string = s.replace('\n', '\\n')
    sanitized_string = sanitized_string.replace('\r', '\\r')
    sanitized_string = sanitized_string.replace('\t', '\\t')
    sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
    return sanitized_string


def sanitize_string_for_script(s):
    sanitized_string = sanitize_string_for_printing(s)
    sanitized_string = sanitized_string.replace('\\', '\\\\')
    sanitized_string = sanitized_string.replace('\"', '\\\"')
    return sanitized_string


def create_script_content(sample_file_path, decoded_strings):
    main_commands = []
    for ds in decoded_strings:
        if ds.s != "":
            sanitized_string = sanitize_string_for_script(ds.s)
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
""" % (sample_file_path, "\n    ".join(main_commands))
    return script_content


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

    def __init__(self, vw, plugins):
        viv_utils.LoggingObject.__init__(self)
        self.vw = vw
        self.plugins = set(plugins)
        self.candidate_functions = {}
        self.candidates_weighted = None

    def run_plugins(self, functions, raw_data=False):
        plugins_to_run = []
        # TODO: these plugin instances should be passed in from the outside
        # or a client library cannot provide its own plugins
        for identifier in get_all_plugins():
            if str(identifier) in self.plugins:
                plugins_to_run.append(identifier)

        for plugin in plugins_to_run:
            decoder_candidates = plugin.identify(self.vw, functions)
            if raw_data:
                self.merge_candidates(str(plugin), decoder_candidates)
            else:
                scored_candidates = plugin.score(decoder_candidates, self.vw)
                self.merge_candidates(str(plugin), scored_candidates)

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
        functions_weighted = {}
        for candidate_function, plugin_score in self.candidate_functions.items():
            self.d("0x%08X" % candidate_function)
            total_score = 0.0
            for plugin_name, score in plugin_score.items():
                if plugin_name not in self.PLUGIN_WEIGHTS.keys():
                    raise Exception("Plugin weight not found: %s" % plugin_name)
                self.d("[%s] %.05f (weight) * %.05f (score) = %.05f" % (plugin_name, self.PLUGIN_WEIGHTS[plugin_name],
                                                                              score, self.PLUGIN_WEIGHTS[plugin_name] * score))
                total_score = total_score + (self.PLUGIN_WEIGHTS[plugin_name] * score)
            self.d("Total score: %.05f\n" % total_score)
            functions_weighted[candidate_function] = total_score

        self.candidates_weighted = functions_weighted

    def sort_candidates_by_score(self):
        # via http://stackoverflow.com/questions/613183/sort-a-python-dictionary-by-value
        return sorted(self.candidates_weighted.items(), key=operator.itemgetter(1), reverse=True)

    def get_top_candidate_functions(self, n=10):
        return [fva for fva, _ in self.sort_candidates_by_score()[:n]]

    def get_candidate_functions(self):
        return self.candidate_functions


def set_logging_level(should_debug=False, should_verbose=False):
    # reset .basicConfig root handler
    # via: http://stackoverflow.com/a/2588054
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)

    if should_debug:
        logging.basicConfig(level=logging.DEBUG)
    elif should_verbose:
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


def select_functions(vw, function_vas=None):
    """
    given a workspace and sequence of function addresses, return the list of valid functions, or all valid function addresses.
    """
    if function_vas is None:
        return vw.getFunctions()

    function_vas = set(function_vas)
    if len(function_vas - workspace_functions) > 0:
        floss_logger.warn("Functions don't exist:", function_vas - workspace_functions)
        raise Exception("Functions not found")

    return function_vas


def select_plugins(plugin_names=None):
    """
    return the list of valid plugin names from the list of plugin names, or all valid plugin names.
    """
    plugin_names = set(plugin_names)
    all_plugin_names = set(map(str, get_all_plugins()))

    plugin_names.remove("")
    if not plugin_names:
        return list(all_plugin_names)

    if len(plugin_names - all_plugin_names) > 0:
        raise Exception("Plugin not found")

    return plugin_names


def output_strings(ds_filtered, min_length):
    print("Offset       Called At    String")
    print("----------   ----------   -------------------------------------")
    for ds in ds_filtered:
        va = ds.va
        if not va:
            va = 0
        print("0x%08X   0x%08X   %s" % (va, ds.decoded_at_va, sanitize_string_for_printing(ds.s)))


def main():
    # default to INFO, unless otherwise changed
    logging.basicConfig(level=logging.WARNING)

    usage_message = "%prog [options] FILEPATH"
    parser = OptionParser(usage=usage_message, version="%prog 0.1")
    parser.add_option("-v", "--verbose", dest="verbose",
                        help="show verbose messages and warnings", action="store_true")

    parser.add_option("-d", "--debug", dest="debug",
                        help="show all trace messages", action="store_true")

    parser.add_option("-f", "--functions", dest="functions",
                        help="only analyze the specified functions (comma-separated)",
                        type="string")

    parser.add_option("-g", "--group", dest="group_functions",
                        help="group output by virtual address of decoding functions",
                        action="store_true")
    parser.add_option("-i", "--ida", dest="ida_python_file",
                        help="create an IDAPython script to annotate the decoded strings in an IDB file")

    parser.add_option("-p", "--plugins", dest="plugins",
                        help="apply the specified identification plugins only (comma-separated)")
    parser.add_option("-l", "--list-plugins", dest="list_plugins",
                        help="list all available identification plugins and exit",
                        action="store_true")

    options, args = parser.parse_args()

    if options.list_plugins:
        print_plugin_list()
        sys.exit(0)

    TRY_HELP_MSG = "Try '%s -h' for more information" % parser.get_prog_name()

    if len(args) != 1:
        parser.error("Please provide a valid file path\n%s" % TRY_HELP_MSG)

    sample_file_path = args[0]

    if not os.path.exists(sample_file_path):
        parser.error("File '%s' does not exist\n%s" % (sample_file_path, TRY_HELP_MSG))

    if not os.path.isfile(sample_file_path):
        parser.error("'%s' is not a file\n%s" % (sample_file_path, TRY_HELP_MSG))

    set_logging_level(options.debug, options.verbose)

    vw = viv_utils.getWorkspace(sample_file_path)

    fvas = None
    if options.functions:
        fvas = [int(fva, 0x10) for fva in foptions.functions.split(",")]
    selected_functions = select_functions(vw, fvas)
    floss_logger.debug("Selected the following functions: %s", ", ".join(map(hex, selected_functions)))
 
    selected_plugins = select_plugins((options.plugins or "").split(","))
    floss_logger.debug("Selected the following plugins: %s", ", ".join(map(str, selected_plugins)))

    time0 = time()
    string_decoder = StringDecoder(vw)
    floss_logger.info("identifying decoding functions...")

    decoder_results = string_decoder.identify_decoding_functions(selected_plugins, selected_functions)
    print("\nMost likely decoding functions in: " + sample_file_path)
    print("address:    score:  ")
    print("----------  -------")
    for fva, score in decoder_results.sort_candidates_by_score()[:10]:
        print("0x%08X: %.5f" % (fva, score))

    floss_logger.info("decoding strings...")
    strings_results = string_decoder.decode_strings(selected_functions)

    decoded_strings = strings_results.get_decoded_strings()
    print("%d strings decoded:" % len(decoded_strings))
    if options.group_functions:
        fvas = set(map(lambda i: i.fva, decoded_strings))
        for fva in fvas:
            ds_filtered = filter(lambda ds: ds.fva == fva, decoded_strings)
            len_ds = len(ds_filtered)
            if len_ds > 0:
                print("\nDecoding function at 0x%X (decoded %d strings)" % (fva, len_ds))
                output_strings(ds_filtered, 4)
    else:
        output_strings(decoded_strings, 4)

    if options.ida_python_file:
        floss_logger.info("generating IDA script...")
        idapython_file = os.path.abspath(options.ida_python_file)
        script_content = create_script_content(sample_file_path, decoded_strings)
        with open(idapython_file, 'wb') as f:
            try:
                f.write(script_content)
                print("\nWrote IDAPython script file to %s" % idapython_file)
            except Exception as e:
                raise e

    time1 = time()
    print("Finished execution after %f seconds" % (time1-time0))


if __name__ == "__main__":
    main()
