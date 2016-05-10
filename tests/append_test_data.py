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
import logging
from pprint import pprint
from pprint import pformat

import footer


logger = logging.getLogger(__name__)


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
    test_dict = {"all": strings}
    logging.info("created test dictionary from %s:\n  %s", spec_path, pformat(test_dict))

    for platform, archs in spec["Output Files"].items():
        for arch, filename in archs.items():
            filepath = os.path.join(spec_dir, filename)
            if not os.path.isfile(filepath):
                logging.warning("not a file: %s", filepath)
                continue

            if footer.has_footer(filepath):
                logging.info("already has footer, skipping: %s", filepath)
                continue

            footer.write_footer(filepath, {"all": strings})
            logging.info("set footer: %s", filepath)


if __name__ == "__main__":
    main()
