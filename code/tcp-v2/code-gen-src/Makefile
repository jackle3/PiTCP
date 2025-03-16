PROGS = code-gen.c

all:: $(CODE_GEN) hello.bin byte-array-hello.h

CODE_GEN = ./code-gen
byte-array-%.h: %.bin $(CODE_GEN)
	$(CODE_GEN)  $< > byte-array-$*.h

byte-array-hello.h: hello.bin $(CODE_GEN)
	$(CODE_GEN) hello.bin > byte-array-hello.h

# CS140E_USE_STAFF = 1
include $(CS140E_2025_PATH)/libunix/mk/Makefile.unix
