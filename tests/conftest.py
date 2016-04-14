import q
import os
import yaml
import pytest

import viv_utils

import floss.main as floss_main
import floss.identification_manager as im
import floss.stackstrings as stackstrings
from append_test_data import read_test_dict_from_file


def read_test_dict(sample_path):
    """
    Reads appended test dictionary from sample and returns "all" items for now.
    Use tests/append_test_data.py to append test data from test.yml file to a sample.
    """
    test_dict = read_test_dict_from_file(sample_path)
    if test_dict is None:
        # sample does not contain test data
        return []
    else:
        # TODO can extract decoding functions offsets from test_dict
        return test_dict["all"]


def extract_strings(sample_path):
    """
    Deobfuscate strings from sample_path
    """
    vw = viv_utils.getWorkspace(sample_path)
    function_index = viv_utils.InstructionFunctionIndex(vw)
    decoding_functions_candidates = identify_decoding_functions(vw)
    decoded_strings = floss_main.decode_strings(vw, function_index, decoding_functions_candidates)
    decoded_stackstrings = stackstrings.extract_stackstrings(vw)
    decoded_strings.extend(decoded_stackstrings)
    return [ds.s for ds in decoded_strings]


def identify_decoding_functions(vw):
    selected_functions = floss_main.select_functions(vw, None)
    selected_plugin_names = floss_main.select_plugins(None)
    selected_plugins = filter(lambda p: str(p) in selected_plugin_names, floss_main.get_all_plugins())
    decoding_functions_candidates = im.identify_decoding_functions(vw, selected_plugins, selected_functions)
    return decoding_functions_candidates


def pytest_collect_file(parent, path):
    if path.basename == "test.yml":
        return YamlFile(path, parent)


class YamlFile(pytest.File):
    def collect(self):
        spec = yaml.safe_load(self.fspath.open())
        test_dir = os.path.dirname(str(self.fspath))
        for platform, archs in spec["Output Files"].items():
            for arch, filename in archs.items():
                filepath = os.path.join(test_dir, filename)
                if os.path.exists(filepath):
                    yield FLOSSTest(self, platform, arch, filename, spec)


class FLOSSTest(pytest.Item):
    def __init__(self, path, platform, arch, filename, spec):
        name = "{name:s}::{platform:s}::{arch:s}".format(
                name=spec["Test Name"],
                platform=platform,
                arch=arch)
        super(FLOSSTest, self).__init__(name, path)
        self.spec = spec
        self.platform = platform
        self.arch = arch
        self.filename = filename

    def runtest(self):
        spec_path = self.location[0]
        test_dir = os.path.dirname(spec_path)
        test_path = os.path.join(test_dir, self.filename)

        # TODO: add support for ELF, MACHO
        if not test_path.lower().endswith(".exe"):
            pytest.xfail("unsupported file format (known issue)")

        # TODO: alternatively, get test data from appended data:
        # expected_strings = set(read_test_dict(test_path))
        expected_strings = set(self.spec["Decoded strings"])
        found_strings = set(extract_strings(test_path))

        if expected_strings:
            assert expected_strings <= found_strings

    def reportinfo(self):
        return self.fspath, 0, "usecase: %s" % self.name
