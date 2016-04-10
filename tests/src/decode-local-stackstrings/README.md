# FLOSS test: test-decode-local-stackstrings

Purpose: Demonstrate extraction of local stackstrings.
Decoding algorithm: stackstrings
Input buffer location: n/a
Output buffer location: stack

Decoded strings:
hello world
goodbye world

Source files:
test-decode-local-stackstrings.c

Build instructions (Windows):
cl.exe test-decode-local-stackstrings.c /Fetest-decode-local-stackstrings.exe

Build instructions (Linux):
clang test-decode-local-stackstrings.c -o test-decode-local-stackstrings

Build instructions (Cross compile for Windows on Linux):
i686-w64-mingw32-clang++ test-decode-local-stackstrings.c -o test-decode-decode-stackstrings.exe
