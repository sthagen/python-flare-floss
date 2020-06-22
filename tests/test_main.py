import pytest
import floss.main


def test_main_help():
    # via https://medium.com/python-pandemonium/testing-sys-exit-with-pytest-10c6e5f7726f
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        floss.main.main(["", "-h"])
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 0


def test_main():
    # see tests/src/decode-to-stack
    assert floss.main.main(["", "data/test-decode-to-stack.exe"]) == 0
