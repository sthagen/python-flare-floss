<img src="resources/logo.png?raw=true " width="350"/>
# FireEye Labs Obfuscated String Solver

Rather than heavily protecting backdoors with hardcore packers, many
malware authors evade heuristic detections by obfuscating only key
portions of an executable. Often, these portions are strings and resources
used to configure domains, files, and other artifacts of an infection.
These key features will not show up as plaintext in output of the `strings.exe` utility
that we commonly use during basic static analysis.

The FireEye Labs Obfuscated String Solver (FLOSS) uses advanced
static analysis techniques to automatically deobfuscate strings from
malware binaries. You can use it just like `strings.exe` to enhance
basic static analysis of unknown binaries.

# Quick Run
To try FLOSS right away, download a standalone executable file from the releases page: https://github.com/fireeye/flare-floss/releases

# Quick Installation
Use the following steps to install FLOSS via the standard Python installer: pip.
This will add an executable `floss` (or `floss.exe` on Windows) to your `$PATH`.

- Install vivisect:

    `$ pip install https://github.com/williballenthin/vivisect/zipball/master`

- Install FLOSS:

    `$ pip install https://github.com/fireeye/flare-floss/zipball/master`


# Usage
Extract obfuscated strings from a malware binary:

    $ floss /path/to/malware/binary

Test individual functions (or a list of functions) using the `-f` switch.

    $ floss /path/to/malware/binary -f 0x40166C,0x402647

Display the help/usage screen to see all available switches.

    $ ./floss -h


# Detailed Setup
To install FLOSS from source for development, use the following instructions.

## Requirements
First, install a few required dependencies.
Here's the easiest way:

- `vivisect` - https://github.com/vivisect/vivisect, installable module from https://github.com/williballenthin/vivisect.git

    $ pip install https://github.com/williballenthin/vivisect/zipball/master

- `viv-utils` - https://www.github.com/williballenthin/viv-utils

    $ pip install viv-utils

- `pytest` - http://pytest.org

    $ pip install pytest


## Installation from Github
This technique installs FLOSS to your local Python environment,
but does not keep editable source files around for you to hack on.

- Install vivisect:

    `$ pip install https://github.com/williballenthin/vivisect/zipball/master`

- Install FLOSS:

    `$ pip install https://github.com/fireeye/flare-floss/zipball/master`


## Installation from source
Use this technique to install FLOSS, yet also keep source files in
the `flare-floss` directory for you to hack on.

- Install vivisect:

    `$ pip install https://github.com/williballenthin/vivisect/zipball/master`

- Clone this git repository:

    `$ git clone https://github.com/fireeye/flare-floss`

- Install FLOSS:

    `$ pip install -e flare-floss`

- (optional) Install pytest:

    `$ pip install pytest`

## Building standalone executables

- Install pyinstaller:

    `$ pip install pyinstaller`

- Build standalone executable:

    `$ pyinstaller floss.spec`

- Distribute standalone executable:

    `$ cp ./dist/floss.exe /the/internet`


## Test
Individual plugins and the whole program can be tested using `py.test` (http://pytest.org/latest/usage.html).
The `--sp` option is required to configure the filesystem path of the directory containing sample files.

## Examples
Run all tests:

    py.test --sp samples/malicious/ tests/

Run all tests from file:

    py.test --sp samples/malicious/ tests/test_floss.py

Run test from file

    py.test --sp samples/malicious/ tests/test_floss.py::test_plugins
