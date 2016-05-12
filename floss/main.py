#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
import os
import sys
import mmap
import string
import logging
import pkg_resources
from time import time
from optparse import OptionParser

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


floss_logger = logging.getLogger("floss")


KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE
MAX_FILE_SIZE = 16 * MEGABYTE

SUPPORTED_FILE_MAGIC = set(["MZ"])

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


def sanitize_string_for_printing(s):
    """
    Return sanitized string for printing.
    :param s: input string
    :return: sanitized string
    """
    sanitized_string = s.replace('\n', '\\n')
    sanitized_string = sanitized_string.replace('\r', '\\r')
    sanitized_string = sanitized_string.replace('\t', '\\t')
    sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
    return sanitized_string


def sanitize_string_for_script(s):
    """
    Return sanitized string that is added to IDAPython script content.
    :param s: input string
    :return: sanitized string
    """
    sanitized_string = sanitize_string_for_printing(s)
    sanitized_string = sanitized_string.replace('\\', '\\\\')
    sanitized_string = sanitized_string.replace('\"', '\\\"')
    return sanitized_string


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

    parser = OptionParser(usage=usage_message, version="%prog {:s}\nhttps://github.com/fireeye/flare-floss/".format(version.__version__))
    parser.add_option("-a", "--all-strings", dest="all_strings", action="store_true",
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
                      help="minimum string length (default is %d)" % MIN_STRING_LENGTH_DEFAULT)
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
        # WARNING:plugins.arithmetic_plugin.XORPlugin:identify: Invalid instruction encountered in basic block, skipping: 0x4a0637
        logging.getLogger("floss.plugins.arithmetic_plugin.XORPlugin").setLevel(logging.ERROR)
        logging.getLogger("floss.plugins.arithmetic_plugin.ShiftPlugin").setLevel(logging.ERROR)


def parse_functions_option(functions_option):
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
    print("")


def print_decoding_results(decoded_strings, min_length, group_functions, quiet=False):
    """
    Print results of string decoding phase.
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param min_length: minimum string length
    :param group_functions: group output by VA of decoding routines
    :param quiet: print strings only, suppresses headers
    """
    long_strings = filter(lambda ds: len(ds.s) >= min_length, decoded_strings)

    if not quiet:
        print("FLOSS decoded %d strings" % len(long_strings))

    if group_functions:
        fvas = set(map(lambda i: i.fva, long_strings))
        for fva in fvas:
            grouped_strings = filter(lambda ds: ds.fva == fva, long_strings)
            len_ds = len(grouped_strings)
            if len_ds > 0:
                if not quiet:
                    print("Decoding function at 0x%X (decoded %d strings)" % (fva, len_ds))
                print_decoded_strings(grouped_strings, quiet=quiet)
    else:
        print_decoded_strings(long_strings, quiet=quiet)


def print_decoded_strings(decoded_strings, quiet=False):
    """
    Print decoded strings.
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param quiet: print strings only, suppresses headers
    """
    if quiet:
        for ds in decoded_strings:
            print(sanitize_string_for_printing(ds.s))
    else:
        ss = []
        for ds in decoded_strings:
            s = sanitize_string_for_printing(ds.s)
            if ds.characteristics["location_type"] == LocationType.STACK:
                offset_string = "[STACK]"
            elif ds.characteristics["location_type"] == LocationType.HEAP:
                offset_string = "[HEAP]"
            else:
                offset_string = hex(ds.va or 0)
            ss.append((offset_string, hex(ds.decoded_at_va), s))

        if len(ss) > 0:
            print(tabulate.tabulate(ss, headers=["Offset", "Called At", "String"]))
            print("")


def create_script_content(sample_file_path, decoded_strings):
    """
    Create IDAPython script contents for IDB file annotations.
    :param sample_file_path: input file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    :return: content of the IDAPython script
    """
    main_commands = []
    for ds in decoded_strings:
        if ds.s != "":
            sanitized_string = sanitize_string_for_script(ds.s)
            if ds.characteristics["location_type"] == LocationType.GLOBAL:
                main_commands.append("AppendComment(%d, \"FLOSS: %s\", True)" % (ds.va, sanitized_string))
                main_commands.append("print \"FLOSS: string \\\"%s\\\" at global VA 0x%X\"" % (sanitized_string, ds.va))
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
    """
    Create an IDAPython script to annotate an IDB file with decoded strings.
    :param sample_file_path: input file path
    :param ida_python_file: output file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    """
    script_content = create_script_content(sample_file_path, decoded_strings)
    ida_python_file = os.path.abspath(ida_python_file)
    with open(ida_python_file, 'wb') as f:
        try:
            f.write(script_content)
            print("Wrote IDAPython script file to %s\n" % ida_python_file)
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


def print_stack_strings(extracted_strings, min_length, quiet=False):
    """
    Print extracted stackstrings.
    :param extracted_strings: list of decoded strings ([DecodedString])
    :param min_length: minimum string length
    :param quiet: print strings only, suppresses headers
    """
    if quiet:
        for ss in extracted_strings:
            if len(ss.s) >= min_length:
                print("%s" % (ss.s))
    else:
        extracted_strings = list(filter(lambda s: len(s.s) >= min_length, extracted_strings))
        count = len(extracted_strings)

        print("FLOSS extracted %d stack strings" % (count))
        if count > 0:
            print(tabulate.tabulate(
                [(hex(s.fva), hex(s.frame_offset), s.s) for s in extracted_strings],
                headers=["Function", "Frame Offset", "String"]))
        print("")


def main(argv=None):
    """
    :param argv: optional command line arguments, like sys.argv[1:]
    """
    logging.basicConfig(level=logging.WARNING)

    parser = make_parser()
    if argv is not None:
        options, args = parser.parse_args(argv)
    else:
        options, args = parser.parse_args()

    set_logging_level(options.debug, options.verbose)

    if options.list_plugins:
        print_plugin_list()
        sys.exit(0)

    sample_file_path = parse_sample_file_path(parser, args)
    min_length = parse_min_length_option(options.min_length)

    with open(sample_file_path, "rb") as f:
        magic = f.read(2)

    if options.all_strings:
        floss_logger.info("Extracting static strings...")
        print_static_strings(sample_file_path, min_length=min_length, quiet=options.quiet)

    if magic not in SUPPORTED_FILE_MAGIC:
        floss_logger.error("FLOSS currently supports the following formats: PE")
        if not options.all_strings:
            floss_logger.error("Recommend passing flag `-a` to extract static strings from any file type.")
        return

    if os.path.getsize(sample_file_path) > MAX_FILE_SIZE:
        floss_logger.error("FLOSS cannot emulate files larger than %d bytes" % (MAX_FILE_SIZE))
        if not options.all_strings:
            floss_logger.error("Recommend passing flag `-a` to extract static strings from any sized file.")
        return

    floss_logger.info("Generating vivisect workspace")
    vw = viv_utils.getWorkspace(sample_file_path)

    selected_functions = select_functions(vw, options.functions)
    floss_logger.debug("Selected the following functions: %s", ", ".join(map(hex, selected_functions)))

    selected_plugin_names = select_plugins(options.plugins)
    floss_logger.debug("Selected the following plugins: %s", ", ".join(map(str, selected_plugin_names)))
    selected_plugins = filter(lambda p: str(p) in selected_plugin_names, get_all_plugins())

    time0 = time()

    floss_logger.info("Identifying decoding functions...")
    decoding_functions_candidates = im.identify_decoding_functions(vw, selected_plugins, selected_functions)
    if not options.quiet:
        print_identification_results(sample_file_path, decoding_functions_candidates)

    floss_logger.info("Decoding strings...")
    function_index = viv_utils.InstructionFunctionIndex(vw)
    decoded_strings = decode_strings(vw, function_index, decoding_functions_candidates)
    print_decoding_results(decoded_strings, min_length, options.group_functions, quiet=options.quiet)

    floss_logger.info("Extracting stackstrings...")
    print_stack_strings(stackstrings.extract_stackstrings(vw, selected_functions), min_length, quiet=options.quiet)

    if options.ida_python_file:
        floss_logger.info("Creating IDA script...")
        create_script(sample_file_path, options.ida_python_file, decoded_strings)

    time1 = time()
    if not options.quiet:
        print("Finished execution after %f seconds" % (time1 - time0))


if __name__ == "__main__":
    main()
