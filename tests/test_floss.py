import os
import sys
import pytest
from pprint import pprint

import viv_utils

from floss import main as floss_main
from floss.interfaces import DecodingRoutineIdentifier


def test_select_one_function(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00")

    sys.argv = [sys.argv[0], file_path, "-f", "0x40166C"]
    sdc = floss_main.StringDecoderConfig()
    sdc.configure()

    assert cmp([0x40166C], sdc.select_functions()) == 0


# TODO
def _test_select_multiple_functions(samples_path):
    pass


def test_select_all_functions(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00")
    vivisect_workspace = viv_utils.getWorkspace(file_path)

    sys.argv = [sys.argv[0], file_path]
    sdc = floss_main.StringDecoderConfig()
    sdc.configure()

    assert cmp(vivisect_workspace.getFunctions(), sdc.select_functions()) == 0


def test_select_one_existing_plugin(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00")

    plugin_name = "XORSimplePlugin"
    sys.argv = [sys.argv[0], file_path, "-p", plugin_name]
    sdc = floss_main.StringDecoderConfig()
    sdc.load_plugins()
    sdc.configure()
    assert cmp(plugin_name, str(sdc.select_plugins()[0])) == 0


def test_select_all_plugins(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00")
    sys.argv = [sys.argv[0], file_path]
    sdc = floss_main.StringDecoderConfig()

    all_plugin_names = map(str, DecodingRoutineIdentifier.implementors())

    assert cmp(all_plugin_names, sdc.select_plugins()) == 0


# TODO make this test_StringDecoder to test the class
def _test_main(samples_path):
    # samples_path is defined and initialized in conftest.py
    file_path = os.path.join(samples_path, "0a209ac0de4ac033f31d6ba9191a8f7a")
    sys.argv = [sys.argv[0], file_path]
    answer_vas = [0x100015F7, 0x100075CE, 0x100075EE]

    identified_functions = [function_va for (function_va, score) in floss_main.main()]

    for answer_va in answer_vas:
        if answer_va not in identified_functions:
            print "0x%08X not in candidate functions" % answer_va
            assert 0

    # all answer_vas were found
    assert 1
