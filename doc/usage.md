# FireEye Labs Obfuscated String Solver

## Usage

You can use FLOSS just like you'd use `strings.exe`:
 to extract human readable strings from binary data.
The enhancement that FLOSS provides is that it staticly
 analyzes exectuable files and decodes obfuscated strings.
These include strings encrypted in global memory,
 deobfuscated onto the heap, or manually created on the
 stack (stackstrings).
Since FLOSS also extracts static strings (like `strings.exe`),
 you should consider replacing `strings.exe` with FLOSS
 within your analysis workflow.

Here's a summary of the command line flags and options you
 can provide to FLOSS to modify its behavior.


### Extract static, obfuscated, and stack strings (default mode)

The default mode for FLOSS is to extract the following string types from an executable file:
- static ASCII and UTF16LE strings
- obfuscated strings
- stackstrings

See the section on [Shellcode analysis](#shellcode) below on how to analyze raw binary files
containing shellcode.

By default FLOSS uses a minimum string length of four.

    floss.exe malware.bin


### Disable string type extraction (`--no-<STRING-TYPE>-strings`)

When FLOSS searches for static strings, it looks for
 human-readable ASCII and UTF-16 strings across the
 entire binary contents of the file.
This means you may be able to replace `strings.exe` with
 FLOSS in your analysis workflow. However, you may disable
 the extraction of static strings via the `--no-static-strings` switch.

    floss.exe --no-static-strings malware.bin

Analogous, you can disable the extraction of obfuscated strings or stackstrings.

    floss.exe --no-decoded-strings malware.bin
    floss.exe --no-stack-strings malware.bin


### Quiet mode (`-q`)

You can supress the formatting of FLOSS output by providing
 the flags `-q` or `--quiet`.
These flags are appropriate if you will pipe the results of FLOSS
 into a filtering or searching program such as grep, and
 want to avoid matches on the section headers.
In quiet mode, each recovered string is printed on its
 own line.
The "type" of the string (static, decoded, or stackstring)
 is not included.

     floss.exe -q malware.bin
     floss.exe --quiet malware.bin


### Minimum string length (`-n`)

By default, FLOSS searches for human-readable strings
 with a length of at least four characters.
You can use the `-n` or `--minimum-length` options to
 specific a different minimum length.
Supplying a larger minimum length reduces the chances
 of identifying random data that appears to be ASCII;
 however, FLOSS may then pass over short legitimate
 human-readable strings

    floss.exe -n 10 malware.bin
    floss.exe --minimum-length=10 malware.bin


### Group output strings (`-g`)

Sometimes malware uses more than one decoding routine
 to deobfuscate different sets of strings.
FLOSS identifies all decoding routines and prints
 their data in one invocation.
You can instruct FLOSS to group the recovered strings
 by decoding routine (rather than RVA) using the
 `-g` or `--group` flags.
This is useful to illustrate how malware decodes
 strings of different sensitivity.

    floss.exe -g malware.bin
    floss.exe --group malware.bin


### Decoding function specification (`-f`)

You can instruct FLOSS to decode the strings provided
 to specific functions by using the `-f` or `--functions`
 option.
By default, FLOSS uses heuristics to identify decoding
 routines in malware.
This mode circumvents the identification phase and skips
 directly to the decoding phase.
If you've previously done analysis on an executable program
 and manually identified the decoding routines, use
 this mode.
This can improve performance as FLOSS by perhaps one-third
 (on the order of seconds, so it is usually _not_ worth it
  to always manually identify decoding routines).
Specify functions by using their hex-encoded virtual address.

    floss.exe -f 0x401000,0x402000 malware.bin
    floss.exe --functions=0x401000,0x402000 malware.bin


### Save vivisect workspace (`--save-workspace`)

Save the vivisect .viv workspace file to the current directory. Run
FLOSS on a .viv workspace file to save the time it takes to generate
the workspace.


### Display vivisect workspace meta information (`-m`)

You can display basic meta information about the generated vivisect
workspace using the `-m` or `--show-metainfo` option. The information
includes details such as architecture, discovered executable surface area,
and number of discovered functions. In conjunction with the `-f` or
`--functions` option FLOSS will display meta information about the selected
functions.


### Do not filter deobfuscated strings (`--no-filter`)

The FLOSS emulation process can result in many false positive deobfuscated
strings. By default, various filters are applied to remove most strings
stemming from vivisect's memory initializations as well as taint and pointer
handling, among other things. Use the `--no-filter` option to obtain the
raw and unfiltered deobfuscated strings.


### Generate annotation scripts (`-i`, `-j`, `-r`, and `--x64dbg`)

FLOSS can generate an IDA Pro Python script that will
 annotate the idb database of the malware sample with
 its decoded strings.
The script appends comments to the virtual addresses
 of the encoded data so its easy to interpet.
Provide the option `-i` or `--ida` to instruct FLOSS to
 write the script to the specified file.

    floss.exe -i myscript.py malware.bin
    floss.exe --ida=myscript.py malware.bin

To create an annotation script for Binary Ninja, use the `-j`, or `--binja` switch.

    floss.exe -j myscript.py malware.bin
    floss.exe --binja myscript.py malware.bin

To create an annotation script for radare2, use the `-r`
or `--radare` switch.

    floss.exe -r myr2script malware.bin
    floss.exe --radare=myr2script malware.bin

To create a x64dbg database/json file to annotate the decoded strings
in x64dbg, use the `--x64dbg` switch.

    floss.exe --x64dbg=myx64dbgdatabase malware.bin


### Verbose and debug modes (`-v`/`-d`)

If FLOSS seems to encounter any issues, try re-running the program
 in the verbose (`-v` or `--verbose`) or debug (`-d` or
 `--debug`) modes.
In these modes, FLOSS prints status and debugging output
 to the standard error stream.
This provides additional context if FLOSS encounters an
 exception or appears to be running slowly.
The verbose mode enables a moderate amount of logging output,
 while the debug mode enables a large amount of logging output.

     floss.exe -v malware.bin
     floss.exe --verbose malware.bin

     floss.exe -d malware.bin
     floss.exe --debug malware.bin


### Detection plugin specification (`-p`/`-l`)

FLOSS uses a plugin-based system to run heuristics
 that identify decoding routines.
You can list the installed plugins by providing the
 flag `-l` or `--list-plugins`.
To selectively enable only a subset of the installed plugins,
 provide a comma-separated list to the `-p` or `--plugins`
 option.
Manipulating the plugin list may be useful during the development
 of new plugins that search for specific features in a known
 binary executable file.

    floss.exe -l
    Available identification plugins:
    - XORPlugin (v1.0)
    - ShiftPlugin (v1.0)
    - FunctionIsLibraryPlugin (v1.0)
    - FunctionCrossReferencesToPlugin (v1.0)
    - FunctionArgumentCountPlugin (v1.0)
    - FunctionIsThunkPlugin (v1.0)
    - FunctionBlockCountPlugin (v1.0)
    - FunctionInstructionCountPlugin (v1.0)
    - FunctionSizePlugin (v1.0)
    - FunctionRecursivePlugin (v1.0)

    floss.exe -p XORPlugin,ShiftPlugin malware.bin
    floss.exe --plugins=XORPlugin,ShiftPlugin malware.bin


## <a name="shellcode"></a>Shellcode analysis options

Malicious shellcode often times contains obfuscated strings and/or stackstrings.
FLOSS can analyze raw binary files containing shellcode via the `-s` switch. All
options mentioned above can also be applied when analyzing shellcode.

    floss.exe -s malware.bin

If you want to specify a base address for the shellcode, use the the `-b` or
`--shellcode_base` switch.

    floss.exe -s malware.bin -b 0x1000000

You can specify an entry point for the shellcode with the `-e` or `--shellcode_ep`
option. The `entry point` value is the relative offset from `base` where the shellcode starts executing. Although vivisect does a good job identifying code, providing an entry point
might improve code analysis.

    floss.exe -s malware.bin -b 0x1000000 -e 0x100
