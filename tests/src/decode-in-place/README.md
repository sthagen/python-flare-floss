# FLOSS test: test-decode-in-place

Purpose: Demonstrate extraction of strings decoded in place.
Decoding algorithm: single byte xor
Input buffer location: stack
Output buffer location: stack

Decoded strings:
hello world

Source files:
test-decode-in-place.c

Build instructions (Windows):
eg. cl.exe test-decode-in-place.c /Fetest-decode-in-place.exe

Build instructions (Linux):
eg. clang test-decode-in-place.c -o test-decode-in-place

Build instructions (Cross compile for Windows on Linux):
i686-w64-mingw32-clang test-decode-in-place.c -o test-decode-in-place.exe
