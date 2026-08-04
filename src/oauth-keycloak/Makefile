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
# The top-level Makefile drives these same targets when the tree was
# configured --with-oauth, passing CC, CFLAGS, PKG_CONFIG and an install
# directory of its own; keep them overridable from the command line.
#

CC ?= cc
PKG_CONFIG ?= pkg-config

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib/pgbouncer

# The shared OIDC core is compiled into the module rather than linked from
# somewhere else, so that the installed module is a single self-contained .so.
COMMON = ../oauth-common

MODULE = keycloak.so
SOURCES = keycloak.c \
	$(COMMON)/oidc_crypto.c $(COMMON)/oidc_http.c \
	$(COMMON)/oidc_jwt.c $(COMMON)/oidc_util.c
OBJECTS = $(SOURCES:.c=.o)

DEPS_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcurl jansson openssl)
DEPS_LIBS := $(shell $(PKG_CONFIG) --libs libcurl jansson openssl)

CFLAGS ?= -O2 -g
override CFLAGS += -Wall -Wextra -Wno-unused-parameter -fPIC -pthread
override CPPFLAGS += -I$(COMMON) -I../../include $(DEPS_CFLAGS)
override LDLIBS += $(DEPS_LIBS) -pthread

all: $(MODULE)

$(MODULE): $(OBJECTS)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

# This module has no unit tests of its own: what it adds to the shared core is
# configuration handling, which the pytest suite covers end to end (see
# test/test_oauth.py).  The core's tests live with the core.
check:
	@echo "no unit tests here; run 'make check' in $(COMMON)"

install: $(MODULE)
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 $(MODULE) $(DESTDIR)$(LIBDIR)/$(MODULE)

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(MODULE)

clean:
	rm -f $(MODULE) $(OBJECTS)

.PHONY: all check install uninstall clean
