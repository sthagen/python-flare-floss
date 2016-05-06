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

Please review the theory behind FLOSS [here](doc/theory.md).


## Quick Run
To try FLOSS right away, download a standalone executable file from the releases page:
https://github.com/fireeye/flare-floss/releases

For a detailed description of *installing* FLOSS, review the documention
 [here](doc/installation.md).

Standalone nightly builds:
  - Windows: [here](http://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/appveyor/dist/floss.exe)
  - Linux: [here](https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/dist/floss)


## Usage
Extract obfuscated strings from a malware binary:

    $ floss /path/to/malware/binary

Display the help/usage screen to see all available switches.

    $ ./floss -h

For a detailed description of *using* FLOSS, review the documention
 [here](doc/usage.md).

For a detailed description of *testing* FLOSS, review the documention
 [here](doc/test.md).


## Sample Output

```
$ ~/env/bin/floss -a malware.bin

Static ASCII strings
Offset       String
----------   -------------------------------------
0x0000004D   !This program cannot be run in DOS mode.
0x00000083   _YY
0x000000D0   RichYY
0x000000F0   MdfQ
0x000001E0   .text
0x00000207   `.rdata
0x0000022F   @.data
0x00000258   .idata
0x00000280   .didat
0x000002A8   .reloc
0x000005B6   U  F
0x000005F1   ?;}
0x000006D4   A@;E
0x000006E4   _^[
0x000008E0   HttHt-H
0x0000099A   '9U
0x00007020   WS2_32.dll
0x00007C4E   FreeLibrary
0x00007C5C   GetProcAddress
0x00007C6E   LoadLibraryA
0x00007C7E   GetModuleHandleA
0x00007C92   GetVersionExA
0x00007CA2   MultiByteToWideChar
0x00007CB8   WideCharToMultiByte
0x00007CCE   Sleep
0x00007CD6   GetLastError
0x00007CE6   DeleteFileA
0x00007CF4   WriteFile
[..snip...]

Static UTF-16 strings
Offset       String
----------   -------------------------------------
0x00007614   ,%d

Most likely decoding functions in: malware.bin
address:    score:
----------  -------
0x0040102D 0.71000
0x0040101E 0.23000
0x00401046 0.23000
0x00401005 0.21000
0x0040100F 0.21000
0x00401014 0.21000
0x00401023 0.21000
0x004069BF 0.21000
0x00401041 0.21000
0x00406736 0.21000

FLOSS decoded 10 strings
Offset       Called At    String
----------   ----------   -------------------------------------
0xBFB3B4E8   0x0040595F   WinSta0\Default
0xBFB3B4A0   0x0040472E   Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
0xBFB3B4A0   0x0040472E   Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
0xBFB3B4EC   0x0040472E   ProxyEnable
0xBFB3B4A0   0x0040472E   Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
0xBFB3B4E0   0x0040472E   ProxyServer
0xBFB3B4EC   0x0040472E   ProxyEnable
0xBFB3B4A0   0x0040472E   Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
0xBFB3B4E0   0x0040472E   ProxyServer
0xBFB3B4EC   0x0040472E   ProxyEnable
[..snip...]

FLOSS extracted 81 stack strings
Function:   Frame offset  String:
----------  ------------  -------
0x00401005  0x001c    WinSta0\Default
0x0040100f  0x0010    WinSta0\Default
0x0040100f  0x007f    pVAD
0x0040100f  0x0034    '%s' executed.
0x0040100f  0x0038    ERR '%s' error[%d].
0x00401014  0x005c    Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
0x00401014  0x0010    ProxyEnable
0x00401014  0x001c    ProxyServer
0x00401019  0x000c    wininet.dll
0x00401019  0x001c    InternetOpenA
0x00401019  0x0107    0\A4
0x00401019  0x00c8    InternetSetOptionA
0x00401019  0x0064    InternetConnectA
0x00401019  0x00f7    pVAInternetQueryOptionA
0x0040100a  0x0080    Mozilla/4.0 (compatible; MSIE 7.0; Win32)
0x0040100a  0x004c    -ERR
0x0040100a  0x0020    FILE(%s) wrote(%d).
0x0040100a  0x0038    Invalid ojbect.
0x0040100a  0x0040    SetFilepoint error[%d].
0x0040100a  0x003c    b64_ntop error[%d].
0x0040100a  0x0024    GetFileSize error[%d].
0x0040100a  0x0024    Creates file error[%d].
0x00401041  0x0047    pVAKCeID5Y/96QTJc1pzi0ZhEBqVG83OnXaL+oxsRdymHS4bFgl7UrWfP2v=wtjNukM
[..snip...]
```
