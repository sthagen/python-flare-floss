# FLOSS test: test-decode-to-heap

Purpose: Demonstrate extraction of strings decoded to a newly allocated heap buffer.
Decoding algorithm: single byte xor
Input buffer location: stack
Output buffer location: heap

Decoded strings:
hello world

Source files:
test-decode-to-heap.c

Build instructions (Windows):
eg. cl.exe test-decode-to-heap.c /Fetest-decode-to-heap.exe

Build instructions (Linux):
eg. clang test-decode-to-heap.c -o test-decode-to-heap

Build instructions (Cross compile for Windows on Linux):
i686-w64-mingw32-clang test-decode-to-heap.c -o test-decode-to-heap.exe
