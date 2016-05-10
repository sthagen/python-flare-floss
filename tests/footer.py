import os
import json
import struct
import logging


FILE_START = 0
FILE_END = 2

MAGIC = "FLSS"
SIZE_OFFSET = 4
SIZE_LEN = 4
SIZE_MAGIC = len(MAGIC)


logger = logging.getLogger(__name__)


def has_footer(sample_path):
    try:
        with open(sample_path, "rb") as f:
            f = open(sample_path, "rb")
            f.seek((-SIZE_MAGIC), FILE_END)
            return f.read(SIZE_MAGIC) == MAGIC
    except Exception:
        logger.warning("failed to check magic footer", exc_info=True)


class NoFooterException(Exception):
    pass


def read_footer(sample_path):
    if not has_footer(sample_path):
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


def write_footer(sample_path, test_dict):
    if has_footer(sample_path):
        raise DuplicateFooterException()

    json_data = json.dumps(test_dict)
    data_len = len(json_data)
    file_size = os.path.getsize(sample_path)
    test_data = struct.pack("<II", file_size, data_len)
    with open(sample_path, "ab") as f:
        f.write(json_data + test_data + MAGIC)
