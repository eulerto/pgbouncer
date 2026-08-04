#
# Microsoft Entra ID OAuth validator module for PgBouncer.
#
# The module is a standalone shared object: it is not linked into the
# pgbouncer binary, only dlopen'ed by it, so it is built on its own and only
# needs include/oauth.h and the shared OIDC core in ../oauth-common.
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

MODULE = entra.so
SOURCES = entra.c \
	$(COMMON)/oidc_crypto.c $(COMMON)/oidc_http.c \
	$(COMMON)/oidc_jwt.c $(COMMON)/oidc_util.c
OBJECTS = $(SOURCES:.c=.o)

DEPS_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcurl jansson openssl)
DEPS_LIBS := $(shell $(PKG_CONFIG) --libs libcurl jansson openssl)

CFLAGS ?= -O2 -g
override CFLAGS += -Wall -Wextra -Wno-unused-parameter -fPIC -pthread
override CPPFLAGS += -I$(COMMON) -I../../include $(DEPS_CFLAGS)
override LDLIBS += $(DEPS_LIBS) -pthread

# entra_test.c includes entra.c to reach the configuration and policy code,
# so the module object is deliberately not in this list.
TEST = entra_test
TEST_OBJECTS = entra_test.o \
	$(COMMON)/oidc_crypto.o $(COMMON)/oidc_http.o \
	$(COMMON)/oidc_jwt.o $(COMMON)/oidc_util.o \
	$(COMMON)/oidc_testutil.o

all: $(MODULE)

$(MODULE): $(OBJECTS)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

$(TEST): $(TEST_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TEST_OBJECTS) $(LDLIBS)

# Covers what this module adds to the core; the core's own tests are in
# $(COMMON), run there with `make check`.
check: $(TEST)
	./$(TEST)

install: $(MODULE)
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 $(MODULE) $(DESTDIR)$(LIBDIR)/$(MODULE)

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(MODULE)

clean:
	rm -f $(MODULE) $(OBJECTS) $(TEST) entra_test.o

.PHONY: all check install uninstall clean
