import os
import sys
import pytest
from pprint import pprint

import viv_utils
from floss import main as floss_main
from floss.main import StringDecoderConfig, IdentificationManager


def test_XORSimplePlugin(samples_path):
    file_path = os.path.join(samples_path, "0a209ac0de4ac033f31d6ba9191a8f7a")

    sys.argv = [sys.argv[0], file_path, "-p", "XORSimplePlugin"]
    decoder_config = StringDecoderConfig()
    identification_manager = IdentificationManager(decoder_config)

    identification_manager.run_plugins()

    answer_vas = [0x10001723, 0x1000AA69, 0x100075CE, 0x1000B369, 0x1000A7DE, 0x100015F7, 0x1000B0DE]
    forced_functions = identification_manager.get_forced_functions().keys()

    assert cmp(answer_vas, forced_functions) == 0


def test_FunctionCrossReferencesToPlugin(samples_path):
    file_path = os.path.join(samples_path, "0a209ac0de4ac033f31d6ba9191a8f7a")
    answer = {0x10009B69: {"FunctionCrossReferencesToPlugin": 41},
              0x1000C7E7: {"FunctionCrossReferencesToPlugin": 1},
              0x1000376D: {"FunctionCrossReferencesToPlugin": 3},
              0x1000D330: {"FunctionCrossReferencesToPlugin": 3},
              0x1000D316: {"Func"
                           "tionCrossReferencesToPlugin": 95}}
    functions = ",".join(map(hex, answer.keys()))
    sys.argv = [sys.argv[0], file_path, "-f", functions, "-p", "FunctionCrossReferencesToPlugin"]

    decoder_config = StringDecoderConfig()
    identification_manager = IdentificationManager(decoder_config)
    identification_manager.run_plugins(raw_data=True)

    assert cmp(answer, identification_manager.get_candidate_functions()) == 0


def test_FunctionArgumentCountPlugin(samples_path):
    file_path = os.path.join(samples_path, "0a209ac0de4ac033f31d6ba9191a8f7a")
    answer = {0x100015F7: {"FunctionArgumentCountPlugin": 1},
              0x100075CE: {"FunctionArgumentCountPlugin": 2},
              0x1000788E: {"FunctionArgumentCountPlugin": 4},
              0x100075FC: {"FunctionArgumentCountPlugin": 1}}

    functions = ",".join(map(hex, answer.keys()))
    sys.argv = [sys.argv[0], file_path, "-f", functions, "-p", "FunctionArgumentCountPlugin"]

    decoder_config = StringDecoderConfig()
    identification_manager = IdentificationManager(decoder_config)
    identification_manager.run_plugins(raw_data=True)

    assert cmp(answer, identification_manager.get_candidate_functions()) == 0


def test_FunctionIsThunkPlugin(samples_path):
    file_path = os.path.join(samples_path, "0a209ac0de4ac033f31d6ba9191a8f7a")
    answer = {0x1000D316: {"FunctionIsThunkPlugin": 1.0},
              0x1000D310: {"FunctionIsThunkPlugin": 1.0},
              0x1000D4B8: {"FunctionIsThunkPlugin": 1.0},
              0x1000D4C4: {"FunctionIsThunkPlugin": 1.0}}

    functions = ",".join(map(hex, answer.keys()))
    sys.argv = [sys.argv[0], file_path, "-f", functions, "-p", "FunctionIsThunkPlugin"]

    pprint(sys.modules)

    decoder_config = StringDecoderConfig()
    identification_manager = IdentificationManager(decoder_config)
    identification_manager.run_plugins(raw_data=False)

    assert cmp(answer, identification_manager.get_candidate_functions()) == 0


def test_FunctionBlockCountPlugin(samples_path):
    file_path = os.path.join(samples_path, "0a209ac0de4ac033f31d6ba9191a8f7a")
    answer = {0x1000C680: {"FunctionBlockCountPlugin": 13},
              0x1000D41B: {"FunctionBlockCountPlugin": 21},
              0x100034A7: {"FunctionBlockCountPlugin": 3},
              0x100072D2: {"FunctionBlockCountPlugin": 5},
              0x100092F6: {"FunctionBlockCountPlugin": 1}}

    functions = ",".join(map(hex, answer.keys()))
    sys.argv = [sys.argv[0], file_path, "-f", functions, "-p", "FunctionBlockCountPlugin"]

    decoder_config = StringDecoderConfig()
    identification_manager = IdentificationManager(decoder_config)
    identification_manager.run_plugins(raw_data=True)

    assert cmp(answer, identification_manager.get_candidate_functions()) == 0


def test_FunctionInstructionCountPlugin(samples_path):
    file_path = os.path.join(samples_path, "0a209ac0de4ac033f31d6ba9191a8f7a")
    answer = {0x1000D316: {"FunctionInstructionCountPlugin": 1.0},
              0x1000D310: {"FunctionInstructionCountPlugin": 1.0},
              0x1000D4B8: {"FunctionInstructionCountPlugin": 1.0},
              0x1000D4C4: {"FunctionInstructionCountPlugin": 1.0}}

    functions = ",".join(map(hex, answer.keys()))
    sys.argv = [sys.argv[0], file_path, "-f", functions, "-p", "FunctionInstructionCountPlugin"]

    decoder_config = StringDecoderConfig()
    identification_manager = IdentificationManager(decoder_config)
    identification_manager.run_plugins(raw_data=True)

    assert cmp(answer, identification_manager.get_candidate_functions()) == 0


def test_FunctionSizePlugin(samples_path):
    file_path = os.path.join(samples_path, "0a209ac0de4ac033f31d6ba9191a8f7a")
    answer = {0x1000788E: {"FunctionSizePlugin": 1101},
              0x100075FC: {"FunctionSizePlugin": 14},
              0x100014C9: {"FunctionSizePlugin": 302},
              0x100075CE: {"FunctionSizePlugin": 32}}

    functions = ",".join(map(hex, answer.keys()))
    sys.argv = [sys.argv[0], file_path, "-f", functions, "-p", "FunctionSizePlugin"]

    decoder_config = StringDecoderConfig()
    identification_manager = IdentificationManager(decoder_config)
    identification_manager.run_plugins(raw_data=True)

    assert cmp(answer, identification_manager.get_candidate_functions()) == 0


def test_FunctionRecursivePlugin(samples_path):
    file_path = os.path.join(samples_path, "6ee35da59f92f71e757d4d5b964ecf00")
    answer = {0x004034EA: {"FunctionRecursivePlugin": 1}}

    sys.argv = [sys.argv[0], file_path, "-p", "FunctionRecursivePlugin"]
    decoder_config = StringDecoderConfig()

    identification_manager = IdentificationManager(decoder_config)
    identification_manager.run_plugins(raw_data=True)

    assert cmp(answer, identification_manager.get_candidate_functions()) == 0
