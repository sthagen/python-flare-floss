import os
import pytest
from pprint import pprint

import viv_utils
from floss.FunctionArgumentGetter import FunctionArgumentGetter
from floss.FunctionArgumentGetter import FunctionContext


def test_FAG_get_all_function_contexts_return_addresses(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00.viv")
    vivisect_workspace = viv_utils.getWorkspace(file_path)
    emu = vivisect_workspace.getEmulator()

    fag = FunctionArgumentGetter(vivisect_workspace)
    answer = [0x40241B, 0x4023E5]

    all_return_addresses = []
    for function_context in fag.get_all_function_contexts(0x0040424E):
        all_return_addresses.append(function_context.return_address)

    assert set(answer) == set(all_return_addresses)


def test_FAG_get_caller_vas(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00.viv")
    vivisect_workspace = viv_utils.getWorkspace(file_path)
    fag = FunctionArgumentGetter(vivisect_workspace)

    caller_vas = fag.get_caller_vas(0x40166C)

    answer = set([0x401698, 0x4018AD, 0x401CE0])

    assert answer.issubset(caller_vas) and caller_vas.issubset(answer)


def test_FAG_get_context_via_monitor_return_addresses(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00.viv")
    vivisect_workspace = viv_utils.getWorkspace(file_path)
    emu = vivisect_workspace.getEmulator()

    fag = FunctionArgumentGetter(vivisect_workspace)
    caller_va = 0x401698
    function_va = 0x40166C
    all_return_addresses = []
    for function_context in fag.get_contexts_via_monitor(caller_va, function_va):
        all_return_addresses.append(function_context.return_address)

    answer = set([0x4016C8, 0x4016D3])

    assert answer == set(all_return_addresses)


# TODO now in Function
def _test_FunctionArgumentGetter_get_function_end(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00.viv")
    vivisect_workspace = viv_utils.getWorkspace(file_path)
    fag = FunctionArgumentGetter(vivisect_workspace)

    answer = {0x4018AD: 0x401CDF, 0x401CE0: 0x402108}

    ends = {}
    for function_start in answer.keys():
        function_end = fag.get_function_end(function_start)
        ends[function_start] = function_end

    assert cmp(answer, ends) == 0
