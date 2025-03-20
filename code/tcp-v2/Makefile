# PROGS += tests/test-bytestream.c
# PROGS += tests/test-tcp-loopback.c
PROGS += tests/test-tcp-loopback-file.c
PROGS += tests/test-uart.c
PROGS += programs/tcp-router.c
PROGS += programs/tcp-p2p-client.c
PROGS += programs/tcp-p2p-server.c
PROGS += programs/tcp-uart.c

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
CFLAGS += -I$(CS140E_PITCP)/code/tcp-v2/code-gen-src


STAFF_OBJS += $(CS140E_PITCP)/libpi/staff-objs/staff-hw-spi.o

# we give you a kmalloc
STAFF_OBJS += $(CS140E_PITCP)/libpi/staff-objs/kmalloc.o

RUN=0

BOOTLOADER = my-install
EXCLUDE ?= grep -v simple_boot
GREP_STR := 'HASH:\|ERROR:\|PANIC:\|SUCCESS:\|NRF:\|PASS:\|FAIL:'
include $(CS140E_PITCP)/libpi/mk/Makefile.robust