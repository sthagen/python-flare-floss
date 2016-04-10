<img src="resources/logo.png?raw=true " width="350"/>
# FireEye Labs Obfuscated String Solver

## Installation
You can install FLOSS in a few different ways.
First, if you simply want to use FLOSS to extract strings, just download the standalone binaries:
 https://github.com/fireeye/flare-floss/releases
However, if you want to use FLOSS as a Python library,
 you can install the package  directly from Github using `pip`.
Finally, if youd like to contribute patches or features to FLOSS,
 youll need to work with a local copy of the source code.

## Method 1: Using FLOSS standalone

If you simply want to use FLOSS to extract strings,
use the standalone binaries we host on Github:

 https://github.com/fireeye/flare-floss/releases

These binary executable files contain all the Python source code,
 Python interpreter, and associated resources needed to make FLOSS run.
This means you can run it without any installation!
Just invoke the file using the command line to see the help documentation.

We used PyInstaller to create these packages.


## Method 2: Using FLOSS as a Python library

If youd like to use FLOSS as part of an automated analysis system,
 you might want to invoke it as a Python library.
This will be easier and less messy than using `system()` to shell-out
 to FLOSS and parse its output stream.
We designed FLOSS to be as easy to use from a client program as from
 the command line.

To install FLOSS as a Python library, youll need to install a few
 dependencies, and then use `pip` to fetch the FLOSS module.

### Step 1: Install requirements

First, install a few required dependencies.
Heres the easiest way:

- `vivisect` - https://github.com/vivisect/vivisect, installable module from https://github.com/williballenthin/vivisect.git

    $ pip install https://github.com/williballenthin/vivisect/zipball/master

### Step 2: Install FLOSS module

Second, use `pip` to install the FLOSS module to your local
 Python environment.
This fetches the library code to your computer, but does not keep
 editable source files around for you to hack on.
If youd like to edit the source files, see Method 3.

- Install FLOSS:

    `$ pip install https://github.com/fireeye/flare-floss/zipball/master`


## Method 3: Inspecting the FLOSS source code

If youd like to review and modify the FLOSS source code,
 youll need to check it out from Github and install it locally.
By following these instructions, youll maintain a local directory
 of source code that you can modify and run easily.

### Step 1: Install requirements

First, install a few required dependencies.
Heres the easiest way:

- `vivisect` - https://github.com/vivisect/vivisect, installable module from https://github.com/williballenthin/vivisect.git

    $ pip install https://github.com/williballenthin/vivisect/zipball/master

- `pytest` - http://pytest.org

    $ pip install pytest

### Step 2: Check out source code

- Clone the FLOSS git repository:

    `$ git clone https://github.com/fireeye/flare-floss /local/path/to/src`

### Step 3: Install the local source code

Next, use `pip` to install the source code in "editable" mode.
This means that Python will load the FLOSS module from this local
 directory rather than copying it to `site-packages` or `dist-packages.
This is good, because it means its easy for us to modify and see the
 effects reflected immediately.
But be careful not to remove this directory unless uninstalling FLOSS!

- Install FLOSS:

    `$ pip install -e ./local/path/to/src`

Youll find that the `FLOSS.exe` (windows) or `floss` (linux) executables
 in your path also invoke the FLOSS binary from this directory.

### Step 4: Building standalone executables

Once youre happy with your contribution to FLOSS, you can package and
 distribute a standalone exectuable to your friends using PyInstaller.
This combines the source code, Python interpreter, and required resources
 into a single file that can be run without installation.

- Install pyinstaller:

    `$ pip install pyinstaller`

- Build standalone executable:

    `$ pyinstaller floss.spec`

- Distribute standalone executable:

    `$ cp ./dist/floss.exe /the/internet`
