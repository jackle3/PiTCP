# PROGS += tests/test-rcp.c
# PROGS += tests/test-bytestream.c
# PROGS += tests/test-sender.c
# PROGS += tests/test-receiver.c
# PROGS += tests/test-tcp-mock-nrf.c
# PROGS += tests/test-tcp-nrf.c
PROGS += tests/test-tcp-loopback.c

LIBS += $(CS140E_PITCP)/lib/libgcc.a

# Common source files
COMMON_SRC += bytestream.h
COMMON_SRC += rcp-datagram.h
COMMON_SRC += rcp-header.h
COMMON_SRC += receiver.h
COMMON_SRC += router.h
COMMON_SRC += sender.h
COMMON_SRC += tcp.h
COMMON_SRC += types.h

COMMON_SRC += $(CS140E_PITCP)/code/nrf/nrf-driver.c
COMMON_SRC += $(CS140E_PITCP)/code/nrf/nrf-hw-support.c
COMMON_SRC += $(CS140E_PITCP)/code/nrf/nrf-public.c

# Flags for include paths
CFLAGS += -I$(CS140E_PITCP)/code/nrf
CFLAGS += -I$(CS140E_PITCP)/code/nrf/tests


STAFF_OBJS += $(CS140E_PITCP)/libpi/staff-objs/staff-hw-spi.o

# we give you a kmalloc
STAFF_OBJS += $(CS140E_PITCP)/libpi/staff-objs/kmalloc.o

RUN=1

BOOTLOADER = my-install
EXCLUDE ?= grep -v simple_boot
GREP_STR := 'HASH:\|ERROR:\|PANIC:\|SUCCESS:\|NRF:\|PASS:\|FAIL:'
include $(CS140E_PITCP)/libpi/mk/Makefile.robust

# Run all tests
test: all
	@echo "Running TCP tests..."
	./tests/test-tcp.bin

checkoff:
	make -f ./Makefile PROGS="$(wildcard tests/[0123]-*.c)" check