import pytest


def pytest_addoption(parser):
    parser.addoption("--sp", action="store", dest="sample_path", help="Path where samples are located")


@pytest.fixture
def samples_path(request):
    return request.config.getoption("--sp")
