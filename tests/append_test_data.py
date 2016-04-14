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
from pprint import pprint


FILE_START = 0
FILE_END = 2

MAGIC = "FLSS"
SIZE_OFFSET = 4
SIZE_LEN = 4
SIZE_MAGIC = len(MAGIC)


def contains_magic(sample_path):
    try:
        f = open(sample_path, "rb")
        f.seek((-SIZE_MAGIC), FILE_END)
        m = f.read(SIZE_MAGIC)
    except Exception as e:
        print str(e)
    finally:
        f.close()
    return m == MAGIC


def read_test_dict_from_file(sample_path):
    if not contains_magic(sample_path):
        return None

    test_dict = None
    try:
        f = open(sample_path, "rb")
        f.seek((-(SIZE_MAGIC + SIZE_OFFSET + SIZE_LEN)), FILE_END)
        test_dict_meta = f.read(SIZE_OFFSET + SIZE_LEN)
        (data_offset, data_len) = struct.unpack("<II", test_dict_meta)
        f.seek(data_offset, FILE_START)
        test_dict_meta = f.read(data_len)
        test_dict = json.loads(test_dict_meta)
    except Exception as e:
        print str(e)
    finally:
        f.close()

    return test_dict


def get_test_dict_from_yaml(yaml_file):
    test_dict = {}
    try:
        f = open(yaml_file, "r")
        spec = yaml.safe_load(f)
        test_dict["all"] = spec["Decoded strings"]
        # TODO add decoding function offsets
    except Exception as e:
        print str(e)
        return test_dict
    finally:
        f.close()
    return test_dict


def append_test_dict_to_file(sample_path, test_dict):
    json_data = json.dumps(test_dict)
    data_len = len(json_data)
    file_size = os.path.getsize(sample_path)
    test_data = struct.pack("<II", file_size, data_len)
    return append_data(sample_path, json_data + test_data + MAGIC)


def append_data(sample_path, data):
    try:
        f = open(sample_path, "ab")
        f.write(data)
    except Exception as e:
        print str(e)
        return False
    finally:
        f.close()
    return True


def main():
    if len(sys.argv) != 2:
        print("Usage: %s <SAMPLE_PATH>" % sys.argv[0])
        return -1

    sample_path = sys.argv[1]
    if not os.path.isfile(sample_path):
        print("%s is not a file" % sample_path)
        return

    if contains_magic(sample_path):
        print("%s already contains test data:" % sample_path)
        pprint(read_test_dict_from_file(sample_path))
        return

    testdir = os.path.dirname(os.path.dirname(sample_path))
    yaml_file = os.path.join(testdir, "test.yml")

    test_dict = get_test_dict_from_yaml(yaml_file)

    if test_dict:
        print("Created test dictionary from %s:" % yaml_file)
        pprint(test_dict)

    if append_test_dict_to_file(sample_path, test_dict):
        print("Successfully appended test data to %s" % sample_path)

if __name__ == "__main__":
    main()
