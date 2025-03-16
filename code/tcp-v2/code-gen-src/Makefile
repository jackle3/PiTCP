PROGS = code-gen.c

SRCS = hello.bin 1mb-file.txt small-file.txt

# Generate byte-array headers for all source files
ALL = $(CODE_GEN) $(SRCS) $(patsubst %.bin,byte-array-%.h,$(filter %.bin,$(SRCS))) $(patsubst %.txt,byte-array-%.h,$(filter %.txt,$(SRCS)))

all:: $(ALL)

CODE_GEN = ./code-gen
byte-array-%.h: %.bin $(CODE_GEN)
	$(CODE_GEN)  $< > byte-array-$*.h

byte-array-%.h: %.txt $(CODE_GEN)
	$(CODE_GEN)  $< > byte-array-$*.h

# CS140E_USE_STAFF = 1
include $(CS140E_2025_PATH)/libunix/mk/Makefile.unix
