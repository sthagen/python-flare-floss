import os
import pytest
from collections import namedtuple
from pprint import pprint

from floss.DecodingManager import DecodingManager


# DecodedString = namedtuple("DecodedString", ["va", "s", "decoded_at_va"])
from floss.DecodingManager import DecodedString


def test_FunctionEmulatorManager_global_mem(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00.viv")

    dm = DecodingManager(file_path)
    dm.run_decoding([0x402647])

    assert cmp(DecodedString(va=4223268, s='\\WordPlug.exe', decoded_at_va=0x40113C, fva=0x402647,
                             global_address=0x407124) in
               dm.get_decoded_strings(), True) == 0


def test_FunctionEmulatorManager_stack(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00.viv")

    dm = DecodingManager(file_path)
    dm.run_decoding([0x40166C])

    assert cmp(DecodedString(va=3216244656, s='runall=1', decoded_at_va=0x401DFB, fva=0x40166C) in
               dm.get_decoded_strings(), True) == 0
