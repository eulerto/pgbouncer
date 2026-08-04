#
# Shared OIDC core for PgBouncer's OAuth validator modules.
#
# There is nothing to build or install here on its own: each validator module
# compiles these sources into its own shared object (see
# ../oauth-keycloak/Makefile).  This Makefile exists for the unit tests that
# cover the core, and to clean up the objects the modules leave behind.
#
#   make check
#
# The top-level Makefile drives `check` when the tree was configured
# --with-oauth, passing CC, CFLAGS and PKG_CONFIG; keep them overridable.
#

CC ?= cc
PKG_CONFIG ?= pkg-config

SOURCES = oidc_crypto.c oidc_http.c oidc_jwt.c oidc_util.c
OBJECTS = $(SOURCES:.c=.o)

DEPS_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcurl jansson openssl)
DEPS_LIBS := $(shell $(PKG_CONFIG) --libs libcurl jansson openssl)

CFLAGS ?= -O2 -g
override CFLAGS += -Wall -Wextra -Wno-unused-parameter -fPIC -pthread
override CPPFLAGS += -I. -I../../include $(DEPS_CFLAGS)
override LDLIBS += $(DEPS_LIBS) -pthread

TEST = oidc_test
TEST_OBJECTS = oidc_test.o oidc_testutil.o $(OBJECTS)

all:
	@echo "Nothing to build here; the validator modules compile these sources."

$(TEST): $(TEST_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TEST_OBJECTS) $(LDLIBS)

check: $(TEST)
	./$(TEST)

clean:
	rm -f $(OBJECTS) $(TEST) oidc_test.o oidc_testutil.o

.PHONY: all check clean
