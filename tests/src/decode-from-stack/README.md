# FLOSS test: test-decode-from-stack

Purpose: Demonstrate extraction of strings decoded from the stack.
Decoding algorithm: single byte xor
Input buffer location: stack
Output buffer location: stack

Decoded strings:
hello world

Source files:
test-decode-from-stack.c

Build instructions (Windows):
eg. cl.exe test-decode-from-stack.c /Fetest-decode-from-stack.exe

Build instructions (Linux):
eg. clang test-decode-from-stack.c -o test-decode-from-stack

Build instructions (Cross compile for Windows on Linux):
i686-w64-mingw32-clang test-decode-from-stack.c -o test-decode-from-stack.exe
