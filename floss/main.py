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
import envi.memory

import strings
import plugins.xor_plugin
import plugins.library_function_plugin
import plugins.function_meta_data_plugin
from utils import makeEmulator
from interfaces import DecodingRoutineIdentifier
from FunctionArgumentGetter import get_function_contexts
from DecodingManager import DecodedString, FunctionEmulator


floss_version = "1.0.3\n" \
                "https://github.com/fireeye/flare-floss/"

floss_logger = logging.getLogger("floss")


class IdentificationManager(viv_utils.LoggingObject):
    PLUGIN_WEIGHTS = {"XORSimplePlugin": 0.5,
                      "FunctionCrossReferencesToPlugin": 0.2,
                      "FunctionArgumentCountPlugin": 0.2,
                      "FunctionIsThunkPlugin": -1.0,
                      "FunctionBlockCountPlugin": 0.025,
                      "FunctionInstructionCountPlugin": 0.025,
                      "FunctionSizePlugin": 0.025,
                      "FunctionRecursivePlugin": 0.025,
                      "FunctionIsLibraryPlugin": -1.0, }

    def __init__(self, vw, identification_plugins):
        viv_utils.LoggingObject.__init__(self)
        self.vw = vw
        self.plugins = set(identification_plugins)
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
        return [(fva, score) for fva, score in self.sort_candidates_by_score()[:n]]

    def get_candidate_functions(self):
        return self.candidate_functions


class StringDecoder(viv_utils.LoggingObject):
    def __init__(self, vw):
        viv_utils.LoggingObject.__init__(self)
        self.vw = vw
        self.function_index = viv_utils.InstructionFunctionIndex(vw)

    def identify_decoding_functions(self, identification_plugins, functions):
        identification_manager = IdentificationManager(self.vw, identification_plugins)
        identification_manager.run_plugins(functions)
        identification_manager.apply_plugin_weights()
        return identification_manager

    def extract_decoding_contexts(self, function):
        return get_function_contexts(self.vw, function)

    def emulate_decoding_routine(self, function, context):
        emu = makeEmulator(self.vw)
        # Restore function context
        emu.setEmuSnap(context.emu_snap)  # TODO somewhere else?
        femu = FunctionEmulator(emu, function, self.function_index)
        self.d("Emulating function at 0x%08X called at 0x%08X, return address: 0x%08X",
               function, context.decoded_at_va, context.return_address)
        deltas = femu.emulate_function(context.return_address, 2000)
        return deltas

    def decode_strings(self, decoding_functions_candidates, min_length):
        decoded_strings = []
        for fva, _ in decoding_functions_candidates.get_top_candidate_functions(10):
            for ctx in self.extract_decoding_contexts(fva):
                for delta in self.emulate_decoding_routine(fva, ctx):
                    for delta_bytes in extract_delta_bytes(delta, ctx.decoded_at_va, fva):
                        for decoded_string in extract_strings(delta_bytes, min_length):
                            decoded_strings.append(decoded_string)
        return decoded_strings


def extract_delta_bytes(delta, decoded_at_va, source_fva=0x0):
    delta_bytes = []

    memory_snap_before = delta.pre_snap.memory
    memory_snap_after = delta.post_snap.memory
    sp = delta.post_snap.sp

    # maps from region start to section tuple
    mem_before = {m[0]: m for m in memory_snap_before}
    mem_after = {m[0]: m for m in memory_snap_after}

    stack_start = 0x0
    stack_end = 0x0
    for m in memory_snap_after:
        if m[0] <= sp < m[1]:
            stack_start, stack_end = m[0], m[1]

    # iterate memory from after the decoding, since if somethings been allocated,
    # we want to know. don't care if things have been deallocated.
    for section_after_start, section_after in mem_after.items():
        (_, _, _, bytes_after) = section_after
        if section_after_start not in mem_before:
            # TODO delta bytes instead of decoded strings
            delta_bytes.append(DecodedString(section_after_start, bytes_after, 
                                             decoded_at_va, source_fva, False))
            continue

        section_before = mem_before[section_after_start]
        (_, _, _, bytes_before) = section_before

        memory_diff = envi.memory.memdiff(bytes_before, bytes_after)
        for offset, length in memory_diff:
            address = section_after_start + offset

            if stack_start <= address <= sp:
                # every stack address that exceeds the stack pointer can be
                # ignored because it is local to child stack frame
                continue

            diff_bytes = bytes_after[offset:offset + length]
            global_address = False
            if not (stack_start <= address < stack_end):
                # address is in global memory
                global_address = address
            delta_bytes.append(DecodedString(address, diff_bytes, decoded_at_va,
                                             source_fva, global_address))
    return delta_bytes


def extract_strings(delta, min_length):
    ret = []
    for s in strings.extract_ascii_strings(delta.s):
        if s.s == "A" * len(s.s):
            # ignore strings of all "A", which is likely taint data
            continue
        ret.append(DecodedString(delta.va + s.offset, s.s, delta.decoded_at_va,
                                 delta.fva, delta.global_address))
    for s in strings.extract_unicode_strings(delta.s):
        if s.s == "A" * len(s.s):
            continue
        ret.append(DecodedString(delta.va + s.offset, s.s, delta.decoded_at_va,
                                 delta.fva, delta.global_address))
    return ret


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


def print_plugin_list():
    print("Available identification plugins:")
    print("\n".join([" - %s" % plugin.get_name_version() for plugin in get_all_plugins()]))


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


def make_parser():
    usage_message = "%prog [options] FILEPATH"
    parser = OptionParser(usage=usage_message, version="%prog " + floss_version)
    parser.add_option("-a", "--all_strings", dest="all_strings", action="store_true",
                        help="also extract static ASCII and UTF-16 strings from the file")
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
    parser.add_option("-n", "--minimum-length", dest="min_length",
                        help="minimum string length (default is 3)")
    parser.add_option("-p", "--plugins", dest="plugins",
                        help="apply the specified identification plugins only (comma-separated)")
    parser.add_option("-l", "--list-plugins", dest="list_plugins",
                        help="list all available identification plugins and exit",
                        action="store_true")
    parser.add_option("-q", "--quiet", dest="quiet", action="store_true",
                        help="suppress headers and formatting to print only extracted strings")
    return parser


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
        # TODO: probably should modify emulator driver to de-prioritize this
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


def parse_functions_option(functions_option):
    fvas = None
    if functions_option:
        fvas = [int(fva, 0x10) for fva in functions_option.split(",")]
    return fvas


def parse_sample_file_path(parser, args):
    try_help_msg = "Try '%s -h' for more information" % parser.get_prog_name()
    if len(args) != 1:
        parser.error("Please provide a valid file path\n%s" % try_help_msg)
    sample_file_path = args[0]
    if not os.path.exists(sample_file_path):
        parser.error("File '%s' does not exist\n%s" % (sample_file_path, try_help_msg))
    if not os.path.isfile(sample_file_path):
        parser.error("'%s' is not a file\n%s" % (sample_file_path, try_help_msg))
    return sample_file_path


def select_functions(vw, functions_option):
    """
    given a workspace and sequence of function addresses, 
     return the list of valid functions, or all valid function addresses.
    """
    function_vas = parse_functions_option(functions_option)

    workspace_functions = set(vw.getFunctions())
    if function_vas is None:
        return workspace_functions

    function_vas = set(function_vas)
    if len(function_vas - workspace_functions) > 0:
        floss_logger.warn("Functions don't exist:", function_vas - workspace_functions)
        # TODO handle exception
        raise Exception("Functions not found")

    return function_vas


def parse_plugins_option(plugins_option):
    return (plugins_option or "").split(",")


def select_plugins(plugins_option):
    """
    return the list of valid plugin names from the list of plugin names, or all valid plugin names.
    """
    plugin_names = parse_plugins_option(plugins_option)

    plugin_names = set(plugin_names)
    all_plugin_names = set(map(str, get_all_plugins()))

    if "" in plugin_names:
        plugin_names.remove("")
    if not plugin_names:
        return list(all_plugin_names)

    if len(plugin_names - all_plugin_names) > 0:
        # TODO handle exception
        raise Exception("Plugin not found")

    return plugin_names


def parse_min_length_option(min_length_option):
    default_min_length = 3
    min_length = int(min_length_option or str(default_min_length))
    return min_length


def print_identification_results(sample_file_path, decoder_results):
    print("\nMost likely decoding functions in: " + sample_file_path)
    print("address:    score:  ")
    print("----------  -------")
    for fva, score in decoder_results.get_top_candidate_functions(10):
        print("0x%08X %.5f" % (fva, score))
    print("")


def print_decoding_results(decoded_strings, min_length, group_functions, quiet=False):
    if not quiet:
        print("FLOSS decoded %d strings" % len(decoded_strings))
    if group_functions:
        fvas = set(map(lambda i: i.fva, decoded_strings))
        for fva in fvas:
            ds_filtered = filter(lambda ds: ds.fva == fva, decoded_strings)
            len_ds = len(ds_filtered)
            if len_ds > 0:
                if not quiet:
                    print("Decoding function at 0x%X (decoded %d strings)" % (fva, len_ds))
                output_strings(ds_filtered, min_length, quiet=quiet)
    else:
        output_strings(decoded_strings, min_length, quiet=quiet)


def output_strings(ds_filtered, min_length, quiet=False):
    if not quiet:
        print("Offset       Called At    String")
        print("----------   ----------   -------------------------------------")

    for ds in ds_filtered:
        va = ds.va or 0
        s = sanitize_string_for_printing(ds.s)
        if len(s) >= min_length:
            if quiet:
                print("%s" % (s))
            else:
                print("0x%08X   0x%08X   %s" % (va, ds.decoded_at_va, s))
    if not quiet:
        print("")


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


def create_script(sample_file_path, ida_python_file, decoded_strings):
    script_content = create_script_content(sample_file_path, decoded_strings)
    ida_python_file = os.path.abspath(ida_python_file)
    with open(ida_python_file, 'wb') as f:
        try:
            f.write(script_content)
            print("Wrote IDAPython script file to %s\n" % ida_python_file)
        except Exception as e:
            raise e


def print_all_strings(path, n=4, quiet=False):
    with open(path, "rb") as f:
        b = f.read()

    if quiet:
        for s in strings.extract_ascii_strings(b, n=n):
            print("%s" % (s.s))
        for s in strings.extract_unicode_strings(b, n=n):
            print("%s" % (s.s))
    else:
        print("Static ASCII strings")
        print("Offset       String")
        print("----------   -------------------------------------")
        for s in strings.extract_ascii_strings(b, n=n):
            print("0x%08X   %s" % (s.offset, s.s))
        print("")

        print("Static UTF-16 strings")
        print("Offset       String")
        print("----------   -------------------------------------")
        for s in strings.extract_unicode_strings(b, n=n):
            print("0x%08X   %s" % (s.offset, s.s))
        print("")


def main():
    # default to INFO, unless otherwise changed
    logging.basicConfig(level=logging.WARNING)

    parser = make_parser()
    options, args = parser.parse_args()

    set_logging_level(options.debug, options.verbose)

    if options.list_plugins:
        print_plugin_list()
        sys.exit(0)

    sample_file_path = parse_sample_file_path(parser, args)
    min_length = parse_min_length_option(options.min_length)

    if options.all_strings:
        floss_logger.info("Extracting static strings...")
        print_all_strings(sample_file_path, n=min_length, quiet=options.quiet)

    with open(sample_file_path, "rb") as f:
        magic = f.read(2)
    if magic != "MZ":
        floss_logger.error("FLOSS currently supports the following formats: PE")
        return

    floss_logger.info("Generating vivisect workspace")
    vw = viv_utils.getWorkspace(sample_file_path)

    selected_functions = select_functions(vw, options.functions)
    floss_logger.debug("Selected the following functions: %s", ", ".join(map(hex, selected_functions)))

    selected_plugins = select_plugins(options.plugins)
    floss_logger.debug("Selected the following plugins: %s", ", ".join(map(str, selected_plugins)))

    time0 = time()

    string_decoder = StringDecoder(vw)

    floss_logger.info("Identifying decoding functions...")
    decoding_functions_candidates = string_decoder.identify_decoding_functions(selected_plugins, selected_functions)
    if not options.quiet:
        print_identification_results(sample_file_path, decoding_functions_candidates)

    floss_logger.info("Decoding strings...")
    decoded_strings = string_decoder.decode_strings(decoding_functions_candidates, min_length)
    print_decoding_results(decoded_strings, min_length, options.group_functions, quiet=options.quiet)

    if options.ida_python_file:
        floss_logger.info("Creating IDA script...")
        create_script(sample_file_path, options.ida_python_file, decoded_strings)

    time1 = time()
    if not options.quiet:
        print("Finished execution after %f seconds" % (time1 - time0))


if __name__ == "__main__":
    main()
