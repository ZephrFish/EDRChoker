# EDRChoker BOF — Makefile
#
# Cross-compiles to Windows COFF object files from Linux or macOS.
#
# Requirements:
#   mingw-w64 >= 5.0  (ships wbemidl.h)
#
#   macOS:  brew install mingw-w64
#   Debian: apt install mingw-w64
#
# Outputs:
#   edrchoker.o      — x86-64 (64-bit Beacon)
#   edrchoker.x86.o  — x86    (32-bit Beacon)

CC64    = x86_64-w64-mingw32-gcc
CC32    = i686-w64-mingw32-gcc

CFLAGS  = -Wall -Wextra \
          -std=c11 \
          -masm=att \
          -DCOBJMACROS \
          -D_WIN32_WINNT=0x0601 \
          -c

.PHONY: all clean

all: edrchoker.o edrchoker.x86.o

edrchoker.o: edrchoker.c beacon.h
	$(CC64) $(CFLAGS) -o edrchoker.o edrchoker.c

# x86: CS BOF loader strips stdcall @N decoration automatically.
edrchoker.x86.o: edrchoker.c beacon.h
	$(CC32) $(CFLAGS) -o edrchoker.x86.o edrchoker.c

clean:
	rm -f edrchoker.o edrchoker.x86.o
