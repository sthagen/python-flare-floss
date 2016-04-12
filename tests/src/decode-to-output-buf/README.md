# FLOSS test: test-decode-to-output-buf

Purpose: Demonstrate extraction of strings decoded to an output buffer.
Decoding algorithm: single byte xor
Input buffer location: stack
Output buffer location: stack

Decoded strings:
hello world

Source files:
test-decode-to-output-buf.c

Build instructions (Windows):
eg. cl.exe test-decode-to-output-buf.c /Fetest-decode-to-output-buf.exe

Build instructions (Linux):
eg. clang test-decode-to-output-buf.c -o test-decode-to-output-buf

Build instructions (Cross compile for Windows on Linux):
i686-w64-mingw32-clang test-decode-to-output-buf.c -o test-decode-to-output-buf.exe
