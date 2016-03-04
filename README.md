<img src="resources/logo.png?raw=true " width="350"/>
# FireEye Labs Obfuscated String Solver

Malware authors encode data in binary files to hide malicious activity and
impede reverse engineering.

The goal of this project is to develop a tool that can automatically detect,
extract, and decode obfuscated strings in PE executable files.


# Quick Installation
- Install vivisect:

    `$ pip install https://github.com/williballenthin/vivisect/zipball/master`

- Install FLOSS:

    `$ pip install https://github.com/fireeye/flare-floss/zipball/master`


# Usage
Extract obfuscated strings from a malware binary:

    $ floss /path/to/malware/binary

Invoke the string decoder on a file.

    $ floss /path/to/malware/binary

Test individual functions (or a list of functions) using the `-f` switch.

    $ floss /path/to/malware/binary -f 0x40166C,0x402647

Display the help/usage screen to see all available switches.

    $ ./floss -h



# Setup
## Requirements
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

# Known Decoding Functions
| Sample Hash | Function Offset |
| --- | --- |
|6ee35da59f92f71e757d4d5b964ecf00|0x40166C|
|6ee35da59f92f71e757d4d5b964ecf00|0x402647|
|8c713117af4ca6bbd69292a78069e75b|0x40104F|
|8c713117af4ca6bbd69292a78069e75b|0x401718|
|bf8616bbed6d804a3dea09b230c2ab0c|0x4010BB|
