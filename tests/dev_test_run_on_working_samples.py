import os
import pytest
from pprint import pprint

import viv_utils
from floss.DecodingManager import DecodingManager


def run_function(sample_file_path, decoding_routine_va):
    file_path = os.path.join(sample_file_path)
    print "\nRunning on sample %s (0x%08X)" % (sample_file_path, decoding_routine_va)

    dm = DecodingManager(file_path)
    dm.run_decoding([decoding_routine_va])

    dm.print_decoded_strings()


def test_run_on_memory_samples(samples_path):
    memory_samples = {"6ee35da59f92f71e757d4d5b964ecf00": 0x402647,  # works
                      "8c713117af4ca6bbd69292a78069e75b": 0x40104F,  # works (kind of)
                      "bf8616bbed6d804a3dea09b230c2ab0c": 0x4010BB}  # works
    # memory_samples = {"b1bf934728fcc8b1741f4f7bba9cbd42": 0x10001000,  # no
    #                   "0a209ac0de4ac033f31d6ba9191a8f7a": 0x100075FC}  # no

    for file_name, decoding_function_va in memory_samples.items():
        file_path = os.path.join(samples_path, file_name)
        run_function(file_path, decoding_function_va)

    assert 0


def test_run_on_stack_samples(samples_path):
    stack_samples = {"6ee35da59f92f71e757d4d5b964ecf00": 0x40166C,  # works
                     "8c713117af4ca6bbd69292a78069e75b": 0x401718}  # works

    for file_name, decoding_function_va in stack_samples.items():
        file_path = os.path.join(samples_path, file_name)
        run_function(file_path, decoding_function_va)

    assert 0
