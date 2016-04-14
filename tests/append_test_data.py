"""
Use this script to append data from the test.yml file to a sample.

Dictionary format:
{
 "fva_string (0x%x)":["string1","string2",...]
 <...>
 optional: "all":["stringN",...]
}

Example:
{
 "0x401000":["hostid","SYSTEM"]
 "all":["8.8.8.8","explorer.exe"]
}
"""""

import os
import sys
import yaml
import json
import struct
import logging
from pprint import pprint
from pprint import pformat


FILE_START = 0
FILE_END = 2

MAGIC = "FLSS"
SIZE_OFFSET = 4
SIZE_LEN = 4
SIZE_MAGIC = len(MAGIC)


logger = logging.getLogger(__name__)


def does_contain_magic_footer(sample_path):
    try:
        with open(sample_path, "rb") as f:
            f = open(sample_path, "rb")
            f.seek((-SIZE_MAGIC), FILE_END)
            return f.read(SIZE_MAGIC) == MAGIC
    except Exception:
        logger.warning("failed to check magic footer", exc_info=True)


class NoFooterException(Exception):
    pass


def read_test_dict_from_file(sample_path):
    if not does_contain_magic_footer(sample_path):
        raise NoFooterException()

    try:
        with open(sample_path, "rb") as f:
            f.seek((-(SIZE_MAGIC + SIZE_OFFSET + SIZE_LEN)), FILE_END)
            test_dict_meta = f.read(SIZE_OFFSET + SIZE_LEN)
            (data_offset, data_len) = struct.unpack("<II", test_dict_meta)
            f.seek(data_offset, FILE_START)
            test_dict_meta = f.read(data_len)
            return json.loads(test_dict_meta)
    except Exception as e:
        logger.warning("failed to read footer", exc_info=True)


class DuplicateFooterException(Exception):
    pass


def append_test_dict_to_file(sample_path, test_dict):
    if does_contain_magic_footer(sample_path):
        raise DuplicateFooterException()

    json_data = json.dumps(test_dict)
    data_len = len(json_data)
    file_size = os.path.getsize(sample_path)
    test_data = struct.pack("<II", file_size, data_len)
    with open(sample_path, "ab") as f:
        f.write(json_data + test_data + MAGIC)


def main():
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) != 2:
        print("Usage: %s <SPEC_FILE>" % sys.argv[0])
        return -1

    spec_path = sys.argv[1]
    spec_dir = os.path.dirname(spec_path)
    with open(spec_path, "rb") as f:
        spec = yaml.safe_load(f)

    strings = spec["Decoded strings"]
    test_dict = { "all": strings }
    logging.info("created test dictionary from %s:\n  %s", spec_path, pformat(test_dict))

    for platform, archs in spec["Output Files"].items():
        for arch, filename in archs.items():
            filepath = os.path.join(spec_dir, filename)
            if not os.path.isfile(filepath):
                logging.warning("not a file: %s", filepath)
                continue

            if does_contain_magic_footer(filepath):
                logging.info("already has footer, skipping: %s", filepath)
                continue

            append_test_dict_to_file(filepath, {"all": strings})
            logging.info("set footer: %s", filepath)


if __name__ == "__main__":
    main()
