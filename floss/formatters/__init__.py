import string
import logging

import tabulate

from floss.decoding_manager import LocationType

KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE
MAX_FILE_SIZE = 16 * MEGABYTE

floss_logger = logging.getLogger("floss")

class BasicFormatter():
    __name__ = "default"

    def __init__(self):
        pass

    def get_name(self):
        return self.__name__

    def configure_args(self, sample_file_path, min_length, options):
        self.path = sample_file_path
        self.min_length = min_length
        self.expert = options.expert
        self.quiet = options.quiet
        self.group_functions = options.group_functions
        self.unique_decoded_strings = options.unique_decoded_strings
        self.show_string_offsets = options.show_string_offsets

    def format(self, decoded_strings, stack_strings):
        if decoded_strings:
            if self.unique_decoded_strings:
                decoded_strings = self.filter_unique_decoded(decoded_strings)
            self.print_decoding_results(decoded_strings)

        if stack_strings:
            if self.unique_decoded_strings:
                stack_strings = list(set(stack_strings))
            self.print_stack_strings(stack_strings)

    def filter_unique_decoded(self, decoded_strings):
        unique_values = set()
        originals = []
        for decoded in decoded_strings:
            hashable = (decoded.va, decoded.s, decoded.decoded_at_va, decoded.fva)
            if hashable not in unique_values:
                unique_values.add(hashable)
                originals.append(decoded)
        return originals

    def print_decoding_results(self, decoded_strings):
        """
        Print results of string decoding phase.
        :param decoded_strings: list of decoded strings ([DecodedString])
        :param min_length: minimum string length
        :param group_functions: group output by VA of decoding routines
        :param quiet: print strings only, suppresses headers
        :param expert: expert mode
        """
        long_strings = filter(lambda ds: len(ds.s) >= self.min_length, decoded_strings)

        if not self.quiet:
            print("\nFLOSS decoded %d strings" % len(long_strings))

        if self.group_functions:
            fvas = set(map(lambda i: i.fva, long_strings))
            for fva in fvas:
                grouped_strings = filter(lambda ds: ds.fva == fva, long_strings)
                len_ds = len(grouped_strings)
                if len_ds > 0:
                    if not self.quiet:
                        print("\nDecoding function at 0x%X (decoded %d strings)" % (fva, len_ds))
                    self.print_decoded_strings(grouped_strings)
        else:
            self.print_decoded_strings(long_strings)

    def print_decoded_strings(self, decoded_strings):
        """
        Print decoded strings.
        :param decoded_strings: list of decoded strings ([DecodedString])
        """
        if not self.show_string_offsets:
            for ds in decoded_strings:
                print(self.sanitize_string_for_printing(ds.s))
        else:
            ss = []
            for ds in decoded_strings:
                s = self.sanitize_string_for_printing(ds.s)
                if ds.characteristics["location_type"] == LocationType.STACK:
                    offset_string = "[STACK]"
                elif ds.characteristics["location_type"] == LocationType.HEAP:
                    offset_string = "[HEAP]"
                else:
                    offset_string = hex(ds.va or 0)
                ss.append((offset_string, hex(ds.decoded_at_va), s))

            if len(ss) > 0:
                print(tabulate.tabulate(ss, headers=["Offset", "Called At", "String"]))

    def sanitize_string_for_printing(self, s):
        """
        Return sanitized string for printing.
        :param s: input string
        :return: sanitized string
        """
        sanitized_string = s.encode('unicode_escape')
        sanitized_string = sanitized_string.replace('\\\\', '\\')  # print single backslashes
        sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
        return sanitized_string

    def print_stack_strings(self, extracted_strings):
        """
        Print extracted stackstrings.
        :param extracted_strings: list of decoded strings ([DecodedString])
        """
        extracted_strings = list(filter(lambda s: len(s.s) >= self.min_length, extracted_strings))
        count = len(extracted_strings)

        if not self.quiet:
            print("\nFLOSS extracted %d stackstrings" % (count))

        if self.show_string_offsets and count > 0:
            print(tabulate.tabulate(
                [(hex(s.fva), hex(s.frame_offset), s.s) for s in extracted_strings],
                headers=["Function", "Frame Offset", "String"]))
        else:
            for ss in extracted_strings:
                print("%s" % (ss.s))
