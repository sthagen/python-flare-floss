# FireEye Labs Obfuscated String Solver

## Testing

We use [py.test](http://pytest.org/latest/usage.html) to test
 FLOSS and ensure it adheres to our specifications.
You can run test cases using the following steps
 to confirm that FLOSS behaves as expected on your platform.

First, make sure that `py.test` is installed:

    pip install py.test

When invoking `py.test`, use the `--sp` option to configure the
 filesystem path of the directory containing sample files.
Please contact us for an archive containing the test files.

Now you can run all the tests:

    py.test --sp samples/malicious/ tests/

Or, you can run all the tests from a specific file:

    py.test --sp samples/malicious/ tests/test_floss.py

Finally, you can run a specific test case:

    py.test --sp samples/malicious/ tests/test_floss.py::test_plugins
