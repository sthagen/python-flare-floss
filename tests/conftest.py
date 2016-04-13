import q
import os
import yaml
import pytest


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


def extract_strings(sample_path):
    # TODO: implement me
    return []


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

        expected_strings = set(self.spec["Decoded strings"])
        found_strings = set(extract_strings(test_path))

        # TODO: enable this
        # assert expected_strings < found_strings

    def reportinfo(self):
        return self.fspath, 0, "usecase: %s" % self.name
