import logging

from floss.formatters import BasicFormatter
from floss.decoding_manager import LocationType

floss_logger = logging.getLogger("floss")


class IdaFormatter(BasicFormatter):
    __name__ = "ida"

    def format(self, decoded_strings, stack_strings):
        floss_logger.info("Creating IDA script...")
        return self.create_ida_script_content(decoded_strings, stack_strings)

    def create_ida_script_content(self, decoded_strings, stack_strings):
        """
        Create IDAPython script contents for IDB file annotations.
        :param decoded_strings: list of decoded strings ([DecodedString])
        :param stack_strings: list of stack strings ([StackString])
        :return: content of the IDAPython script
        """
        main_commands = []

        if self.show_decoded_strings:
            for ds in decoded_strings:
                if ds.s != "":
                    sanitized_string = self.sanitize_string_for_script(ds.s)
                    if ds.characteristics["location_type"] == LocationType.GLOBAL:
                        main_commands.append("print \"FLOSS: string \\\"%s\\\" at global VA 0x%X\"" % (sanitized_string, ds.va))
                        main_commands.append("AppendComment(%d, \"FLOSS: %s\", True)" % (ds.va, sanitized_string))
                    else:
                        main_commands.append("print \"FLOSS: string \\\"%s\\\" decoded at VA 0x%X\"" % (sanitized_string, ds.decoded_at_va))
                        main_commands.append("AppendComment(%d, \"FLOSS: %s\")" % (ds.decoded_at_va, sanitized_string))
            main_commands.append("print \"Imported decoded strings from FLOSS\"")

        if self.show_stack_strings:
            ss_len = 0
            for ss in stack_strings:
                if ss.s != "":
                    sanitized_string = self.sanitize_string_for_script(ss.s)
                    main_commands.append("AppendLvarComment(%d, %d, \"FLOSS stackstring: %s\", True)" % (ss.fva, ss.frame_offset, sanitized_string))
                    ss_len += 1
            main_commands.append("print \"Imported stackstrings from FLOSS\"")

        script_content = """from idc import RptCmt, Comment, MakeRptCmt, MakeComm, GetFrame, GetFrameLvarSize, GetMemberComment, SetMemberComment, Refresh


    def AppendComment(ea, s, repeatable=False):
        # see williutils and http://blogs.norman.com/2011/security-research/improving-ida-analysis-of-x64-exception-handling
        if repeatable:
            string = RptCmt(ea)
        else:
            string = Comment(ea)

        if not string:
            string = s  # no existing comment
        else:
            if s in string:  # ignore duplicates
                return
            string = string + "\\n" + s
        if repeatable:
            MakeRptCmt(ea, string)
        else:
            MakeComm(ea, string)


    def AppendLvarComment(fva, frame_offset, s, repeatable=False):
        stack = GetFrame(fva)
        if stack:
            lvar_offset = GetFrameLvarSize(fva) - frame_offset
            if lvar_offset and lvar_offset > 0:
                string = GetMemberComment(stack, lvar_offset, repeatable)
                if not string:
                    string = s
                else:
                    if s in string:  # ignore duplicates
                        return
                    string = string + "\\n" + s
                if SetMemberComment(stack, lvar_offset, string, repeatable):
                    print "FLOSS appended stackstring comment \\\"%%s\\\" at stack frame offset 0x%%X in function 0x%%X" %% (s, frame_offset, fva)
                    return
        print "Failed to append stackstring comment \\\"%%s\\\" at stack frame offset 0x%%X in function 0x%%X" %% (s, frame_offset, fva)


    def main():
        print "Annotating %d strings from FLOSS for %s"
        %s
    Refresh()

    if __name__ == "__main__":
        main()
    """ % (len(decoded_strings) + ss_len, self.path, "\n    ".join(main_commands))
        return script_content

    def sanitize_string_for_script(self, s):
        """
        Return sanitized string that is added to IDAPython script content.
        :param s: input string
        :return: sanitized string
        """
        sanitized_string = self.sanitize_string_for_printing(s)
        sanitized_string = sanitized_string.replace('\\', '\\\\')
        sanitized_string = sanitized_string.replace('\"', '\\\"')
        return sanitized_string
