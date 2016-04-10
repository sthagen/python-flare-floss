# FLOSS test: test-decode-base64

Purpose: Demonstrate detection of base64 routine and decoding of base64 data.
Decoding algorithm: Base64
Input buffer location: global
Output buffer location: stack

Decoded strings:
hello world

Source files:
test-decode-base64.c
base64.h
base64.c

Build instructions (Windows):
cl.exe test-decode-base64.c base64.c /Fetest-decode-base64.exe

Build instructions (Linux):
clang test-decode-base64.c base64.c -o test-decode-base64

Build instructions (Cross compile for Windows on Linux):
i686-w64-mingw32-clang++ test-decode-base64.c base64.c -o test-decode-base64.exe
