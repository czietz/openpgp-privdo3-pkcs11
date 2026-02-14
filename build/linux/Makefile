# Display exported symbols:
#  nm -D openpgp-privdo3-pkcs11.so | grep ' T '

SRC_DIR=../../src

ARCH ?= $(shell uname -m)
CC ?= gcc
CFLAGS = $(ARCH_FLAGS) -Wall -Wextra -Werror -O2 -I$(SRC_DIR)
CFLAGS  += $(shell pkg-config --cflags libpcsclite)
LDFLAGS += $(shell pkg-config --libs libpcsclite)
LIBNAME = openpgp-privdo3-pkcs11-$(ARCH).so

all: openpgp-privdo3-pkcs11.o
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) \
	-Wl,-soname,$(LIBNAME) \
	-Wl,--version-script,openpgp-privdo3-pkcs11.version \
	openpgp-privdo3-pkcs11.o $(LDFLAGS)
	strip --strip-all $(LIBNAME)

openpgp-privdo3-pkcs11.o: $(SRC_DIR)/openpgp-privdo3-pkcs11.c $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/openpgp-privdo3-pkcs11.c

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.so
