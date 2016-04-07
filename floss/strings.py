import re
from collections import namedtuple


ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"


String = namedtuple("String", ["s", "offset"])


def extract_ascii_strings(buf, n=4):
    '''
    Extract ASCII strings from the given binary data.

    :param buf: A bytestring.
    :type buf: str
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: Sequence[String]
    '''
    reg = "([%s]{%d,})" % (ASCII_BYTE, n)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        yield String(match.group().decode("ascii"), match.start())

def extract_unicode_strings(buf, n=4):
    '''
    Extract naive UTF-16 strings from the given binary data.

    :param buf: A bytestring.
    :type buf: str
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: Sequence[String]
    '''
    reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        try:
            yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass


def main():
    import sys

    with open(sys.argv[1], 'rb') as f:
        b = f.read()

    for s in extract_ascii_strings(b):
        print('0x{:x}: {:s}'.format(s.offset, s.s))

    for s in extract_unicode_strings(b):
        print('0x{:x}: {:s}'.format(s.offset, s.s))


if __name__ == '__main__':
    main()
