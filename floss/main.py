#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
import os
import sys
import mmap
import logging
from time import time
from optparse import OptionParser, OptionGroup

import tabulate
import plugnplay
import viv_utils

import version
import strings
import stackstrings
import string_decoder
import plugins.arithmetic_plugin
import identification_manager as im
import plugins.library_function_plugin
import plugins.function_meta_data_plugin
from interfaces import DecodingRoutineIdentifier
from decoding_manager import LocationType
from base64 import b64encode
from formatters import BasicFormatter
from formatters.idapython import IdaFormatter

floss_logger = logging.getLogger("floss")

SUPPORTED_FILE_MAGIC = set(["MZ"])

KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE
MAX_FILE_SIZE = 16 * MEGABYTE
MIN_STRING_LENGTH_DEFAULT = 4


def hex(i):
    return "0x%X" % (i)


def decode_strings(vw, function_index, decoding_functions_candidates):
    """
    FLOSS string decoding algorithm
    :param vw: vivisect workspace
    :param function_index: function data
    :param decoding_functions_candidates: identification manager
    :return: list of decoded strings ([DecodedString])
    """
    decoded_strings = []
    # TODO pass function list instead of identification manager
    for fva, _ in decoding_functions_candidates.get_top_candidate_functions(10):
        for ctx in string_decoder.extract_decoding_contexts(vw, fva):
            for delta in string_decoder.emulate_decoding_routine(vw, function_index, fva, ctx):
                for delta_bytes in string_decoder.extract_delta_bytes(delta, ctx.decoded_at_va, fva):
                    for decoded_string in string_decoder.extract_strings(delta_bytes):
                        decoded_strings.append(decoded_string)
    return decoded_strings


def print_plugin_list():
    print("Available identification plugins:")
    print("\n".join([" - %s" % plugin.get_name_version() for plugin in get_all_plugins()]))


# TODO add --plugin_dir switch at some point
def get_all_plugins():
    """
    Return all plugins to be run.
    """
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
        ps.append(plugins.arithmetic_plugin.XORPlugin())
        ps.append(plugins.arithmetic_plugin.ShiftPlugin())
    return ps


def make_parser():
    usage_message = "%prog [options] FILEPATH"

    OptionParser.format_epilog = lambda self, formatter: self.epilog  # overwrite default epilog formatter
    parser = OptionParser(usage=usage_message,
                          version="%prog {:s}\nhttps://github.com/fireeye/flare-floss/".format(version.__version__),
                          epilog="""
Examples:
 floss malware.exe
 floss --no-static-strings malware.exe

""")  # TODO
    parser.add_option("-o", "--output-mode", dest="output_mode", choices="ida,r2,json".split(","),
                      help="- ida:  IDAPython script to annotate decoded strings and stackstrings in an IDB file"
                           "                       "  # fix help format
                           "- r2:   radare2 script to annotate decoded strings and stackstrings in a .r2 file"
                           "                            "
                           "- json: JSON file")

    parser.add_option("-n", dest="min_length",
                      help="minimum string length (default is %d)" % MIN_STRING_LENGTH_DEFAULT)

    parser.add_option("-f", "--functions", dest="functions",
                      help="only analyze the specified functions (comma-separated)",
                      type="string")

    parser.add_option("--save-workspace", dest="save_workspace",
                      help="save vivisect .viv workspace file in analyzed file's directory", action="store_true")

    extraction_group = OptionGroup(parser, "Extraction options", "Specify which string types FLOSS shows from a file, "
                                                                 "by default all types are shown")
    extraction_group.add_option("--no-static-strings", dest="no_static_strings", action="store_true",
                      help="do not show static ASCII and UTF-16 strings")
    extraction_group.add_option("--no-decoded-strings", dest="no_decoded_strings", action="store_true",
                      help="do not show decoded strings")
    extraction_group.add_option("--no-stack-strings", dest="no_stack_strings", action="store_true",
                      help="do not show stackstrings")
    parser.add_option_group(extraction_group)

    format_group = OptionGroup(parser, "Format Options")
    format_group.add_option("-g", "--group", dest="group_functions",
                      help="group output by virtual address of decoding functions",
                      action="store_true")
    format_group.add_option("-q", "--quiet", dest="quiet", action="store_true",
                  help="suppress headers and formatting to print only extracted strings")
    parser.add_option_group(format_group)

    logging_group = OptionGroup(parser, "Logging Options")
    logging_group.add_option("-v", "--verbose", dest="verbose",
                      help="show verbose messages and warnings", action="store_true")
    logging_group.add_option("-d", "--debug", dest="debug",
                      help="show all trace messages", action="store_true")
    parser.add_option_group(logging_group)

    identification_group = OptionGroup(parser, "Identification Options")
    identification_group.add_option("-p", "--plugins", dest="plugins",
                      help="apply the specified identification plugins only (comma-separated)")
    identification_group.add_option("-l", "--list-plugins", dest="list_plugins",
                      help="list all available identification plugins and exit",
                      action="store_true")
    parser.add_option_group(identification_group)

    profile_group = OptionGroup(parser, "FLOSS Profiles")
    profile_group.add_option("-x", "--expert", dest="expert",
                      help="show duplicate offset/string combinations", action="store_true")  # TODO
    parser.add_option_group(profile_group)

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
        # WARNING:plugins.arithmetic_plugin.XORPlugin:identify: Invalid instruction encountered in basic block, skipping: 0x4a0637
        logging.getLogger("floss.plugins.arithmetic_plugin.XORPlugin").setLevel(logging.ERROR)
        logging.getLogger("floss.plugins.arithmetic_plugin.ShiftPlugin").setLevel(logging.ERROR)


def parse_functions_option(functions_option):  # TODO check for decimals and non-existent functions
    """
    Return parsed -f command line option or None.
    """
    fvas = None
    if functions_option:
        fvas = [int(fva, 0x10) for fva in functions_option.split(",")]
    return fvas


def parse_sample_file_path(parser, args):
    """
    Return validated input file path or terminate program.
    """
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
    Given a workspace and sequence of function addresses, return the list
    of valid functions, or all valid function addresses.
    :param vw: vivisect workspace
    :param functions_option: -f command line option
    :return: list of all valid function addresses
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
    """
    Return parsed -p command line option or "".
    """
    return (plugins_option or "").split(",")


def select_plugins(plugins_option):
    """
    Return the list of valid plugin names from the list of
    plugin names, or all valid plugin names.
    :param plugins_option: -p command line argument value
    :return: list of strings of all selected plugins
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
    """
    Return parsed -n command line option or default length.
    """
    min_length = int(min_length_option or str(MIN_STRING_LENGTH_DEFAULT))
    return min_length


def get_formatter(options):
    formatter = BasicFormatter()
    available_formatters = [
        IdaFormatter(),
    ]
    for f in available_formatters:
        if f.get_name() == options.output_mode:
            formatter = f
            break
    return formatter


def is_workspace_file(sample_file_path):
    """
    Return if input file is a vivisect workspace, based on file extension
    :param sample_file_path:
    :return: True if file extension is .viv, False otherwise
    """
    if os.path.splitext(sample_file_path)[1] == ".viv":
        return True
    return False


def print_identification_results(sample_file_path, decoder_results):
    """
    Print results of string decoding routine identification phase.
    :param sample_file_path: input file
    :param decoder_results: identification_manager
    """
    # TODO pass functions instead of identification_manager
    candidates = decoder_results.get_top_candidate_functions(10)
    if len(candidates) == 0:
        print("No candidate functions found.")
    else:
        print("Most likely decoding functions in: " + sample_file_path)
        print(tabulate.tabulate(
            [(hex(fva), "%.5f" % (score,)) for fva, score in candidates],
            headers=["address", "score"]))


def create_r2_script_content(sample_file_path, decoded_strings, stack_strings):
    """
    Create r2script contents for r2 session annotations.
    :param sample_file_path: input file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param stack_strings: list of stack strings ([StackString])
    :return: content of the r2script
    """
    main_commands = []
    fvas = []
    for ds in decoded_strings:
        if ds.s != "":
            sanitized_string = b64encode("\"FLOSS: %s (floss_%x)\"" % (ds.s, ds.fva))
            if ds.characteristics["location_type"] == LocationType.GLOBAL:
                main_commands.append("CCu base64:%s @ %d" % (sanitized_string, ds.va))
                if ds.fva not in fvas:
                    main_commands.append("af @ %d" % (ds.fva))
                    main_commands.append("afn floss_%x @ %d" % (ds.fva, ds.fva))
                    fvas.append(ds.fva)
            else:
                main_commands.append("CCu base64:%s @ %d" % (sanitized_string, ds.decoded_at_va))
                if ds.fva not in fvas:
                    main_commands.append("af @ %d" % (ds.fva))
                    main_commands.append("afn floss_%x @ %d" % (ds.fva, ds.fva))
                    fvas.append(ds.fva)

    return "\n".join(main_commands)


def create_r2_script(sample_file_path, r2_script_file, decoded_strings, stack_strings):
    """
    Create an r2script to annotate r2 session with decoded strings.
    :param sample_file_path: input file path
    :param r2script_file: output file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param stack_strings: list of stack strings ([StackString])
    """
    script_content = create_r2_script_content(sample_file_path, decoded_strings, stack_strings)
    r2_script_file = os.path.abspath(r2_script_file)
    with open(r2_script_file, 'wb') as f:
        try:
            f.write(script_content)
            print("Wrote radare2script file to %s\n" % r2_script_file)
        except Exception as e:
            raise e
    # TODO return, catch exception in main()


def print_static_strings(path, min_length, quiet=False):
    """
    Print static ASCII and UTF-16 strings from provided file.
    :param path: input file
    :param min_length: minimum string length
    :param quiet: print strings only, suppresses headers
    """
    with open(path, "rb") as f:
        b = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        if quiet:
            for s in strings.extract_ascii_strings(b, n=min_length):
                print("%s" % (s.s))
            for s in strings.extract_unicode_strings(b, n=min_length):
                print("%s" % (s.s))

        elif os.path.getsize(path) > MAX_FILE_SIZE:
            # for large files, there might be a huge number of strings,
            # so don't worry about forming everything into a perfect table
            print("Static ASCII strings")
            print("Offset   String")
            print("------   ------")
            has_string = False
            for s in strings.extract_ascii_strings(b, n=min_length):
                print("%s %s" % (hex(s.offset), s.s))
                has_string = True
            if not has_string:
                print("none.")
            print("")

            print("Static Unicode strings")
            print("Offset   String")
            print("------   ------")
            has_string = False
            for s in strings.extract_unicode_strings(b, n=min_length):
                print("%s %s" % (hex(s.offset), s.s))
                has_string = True
            if not has_string:
                print("none.")
            print("")

            if os.path.getsize(path) > sys.maxint:
                floss_logger.warning("File too large, strings listings may be trucated.")
                floss_logger.warning("FLOSS cannot handle files larger than 4GB on 32bit systems.")

        else:
            # for reasonably sized files, we can read all the strings at once
            # and format them nicely in a table.
            ascii_strings = list(strings.extract_ascii_strings(b, n=min_length))
            print("Static ASCII strings")
            if len(ascii_strings) == 0:
                print("none.")
            else:
                print(tabulate.tabulate(
                    [(hex(s.offset), s.s) for s in ascii_strings],
                    headers=["Offset", "String"]))
            print("")

            uni_strings = list(strings.extract_unicode_strings(b, n=min_length))
            print("Static UTF-16 strings")
            if len(uni_strings) == 0:
                print("none.")
            else:
                print(tabulate.tabulate(
                    [(hex(s.offset), s.s) for s in uni_strings],
                    headers=["Offset", "String"]))
            print("")


def set_default_options(options):
    """
    Set default internal options
    :param options:
    """
    options.print_identification_results = False
    options.unique_decoded_strings = True
    options.show_string_offsets = False
    options.show_static_strings = not options.no_static_strings
    options.show_decoded_strings = not options.no_decoded_strings
    options.show_stack_strings = not options.no_stack_strings


def set_expert_profile_options(options):
    """
    Set options for expert profile
    :param options:
    :return:
    """
    options.save_workspace = True
    options.print_identification_results = True
    options.unique_decoded_strings = False
    options.quiet = False
    options.show_string_offsets = True


def main(argv=None):
    """
    :param argv: optional command line arguments, like sys.argv[1:]
    :return: 0 on success, non-zero on failure
    """
    logging.basicConfig(level=logging.WARNING)

    parser = make_parser()
    if argv is not None:
        options, args = parser.parse_args(argv[1:])
    else:
        options, args = parser.parse_args()

    set_logging_level(options.debug, options.verbose)

    if options.list_plugins:
        print_plugin_list()
        return 0

    sample_file_path = parse_sample_file_path(parser, args)
    min_length = parse_min_length_option(options.min_length)

    set_default_options(options)
    if options.expert:
        set_expert_profile_options(options)

    formatter = get_formatter(options)
    formatter.configure_args(sample_file_path, min_length, options)

    if not is_workspace_file(sample_file_path):
        with open(sample_file_path, "rb") as f:
            magic = f.read(2)

        if options.show_static_strings:
            floss_logger.info("Extracting static strings...")
            print_static_strings(sample_file_path, min_length, options.quiet)

        if magic not in SUPPORTED_FILE_MAGIC:
            floss_logger.error("FLOSS currently supports the following formats: PE")
            return 1

        if os.path.getsize(sample_file_path) > MAX_FILE_SIZE:
            floss_logger.error("FLOSS cannot emulate files larger than %d bytes" % (MAX_FILE_SIZE))
            return 1

        floss_logger.info("Generating vivisect workspace...")
    else:
        floss_logger.info("Loading existing vivisect workspace...")

    try:
        vw = viv_utils.getWorkspace(sample_file_path, should_save=options.save_workspace)
    except Exception, e:
        floss_logger.error("Vivisect failed to load the input file: {0}".format(e.message), exc_info=options.verbose)
        return 1

    selected_functions = select_functions(vw, options.functions)
    floss_logger.debug("Selected the following functions: %s", ", ".join(map(hex, selected_functions)))

    selected_plugin_names = select_plugins(options.plugins)
    floss_logger.debug("Selected the following plugins: %s", ", ".join(map(str, selected_plugin_names)))
    selected_plugins = filter(lambda p: str(p) in selected_plugin_names, get_all_plugins())

    time0 = time()

    decoded_strings = []
    if options.show_decoded_strings:
        floss_logger.info("Identifying decoding functions...")
        decoding_functions_candidates = im.identify_decoding_functions(vw, selected_plugins, selected_functions)
        if options.print_identification_results:
            print_identification_results(sample_file_path, decoding_functions_candidates)

        floss_logger.info("Decoding strings...")
        function_index = viv_utils.InstructionFunctionIndex(vw)
        decoded_strings = decode_strings(vw, function_index, decoding_functions_candidates)

    stack_strings = ()
    if options.show_stack_strings:
        floss_logger.info("Extracting stackstrings...")
        stack_strings = stackstrings.extract_stackstrings(vw, selected_functions)

    print(formatter.format(decoded_strings, stack_strings))

    # TODO formatters/r2.py

    time1 = time()
    if not options.quiet:
        print("\nFinished execution after %f seconds" % (time1 - time0))

    return 0


if __name__ == "__main__":
    sys.exit(main())
