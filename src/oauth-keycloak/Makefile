#
# Keycloak OAuth validator module for PgBouncer.
#
# The module is a standalone shared object: it is not linked into the
# pgbouncer binary, only dlopen'ed by it, so it is built on its own and only
# needs include/oauth.h.
#
#   make
#   make check
#   make install PREFIX=/usr/local
#

CC ?= cc
PKG_CONFIG ?= pkg-config

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib/pgbouncer

MODULE = keycloak.so
SOURCES = keycloak.c kc_crypto.c kc_http.c kc_jwt.c
OBJECTS = $(SOURCES:.c=.o)

DEPS_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcurl jansson openssl)
DEPS_LIBS := $(shell $(PKG_CONFIG) --libs libcurl jansson openssl)

CFLAGS ?= -O2 -g
override CFLAGS += -Wall -Wextra -Wno-unused-parameter -fPIC -pthread
override CPPFLAGS += -I../../include $(DEPS_CFLAGS)
override LDLIBS += $(DEPS_LIBS) -pthread

TEST = kc_test
TEST_OBJECTS = kc_test.o kc_crypto.o kc_jwt.o kc_http.o

all: $(MODULE)

$(MODULE): $(OBJECTS)
	$(CC) -shared $(CFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

$(TEST): $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJECTS) $(LDLIBS)

check: $(TEST)
	./$(TEST)

install: $(MODULE)
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 $(MODULE) $(DESTDIR)$(LIBDIR)/$(MODULE)

clean:
	rm -f $(MODULE) $(OBJECTS) $(TEST) kc_test.o

.PHONY: all check install clean
