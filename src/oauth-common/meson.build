# ----------------------------------------------------------------------
# Shared OIDC core for the OAuth validator modules
#
# Not a library of its own: there is nothing to install here and nothing links
# against it at run time.  Each validator module compiles these sources into
# its own shared object, so a module stays a single self-contained .so that
# PgBouncer can dlopen() without a search path.
#
# This file only publishes the source list and the flags the modules need;
# it builds the unit tests that cover the core.
# ----------------------------------------------------------------------

oidc_deps = [libcurl, jansson, openssl, threads]
oidc_incdirs = include_directories('.', '../../include')
oidc_sources = files(
  'oidc_crypto.c',
  'oidc_http.c',
  'oidc_jwt.c',
  'oidc_util.c',
)

# Stands in for an identity provider; linked only into the test binaries.
oidc_test_sources = files('oidc_testutil.c')

# Unit tests. They mint their own keys and serve a JWKS from a throwaway HTTP
# server on localhost, so they need no identity provider.
oidc_test = executable('oidc_test',
                       'oidc_test.c',
                       oidc_sources,
                       oidc_test_sources,
                       build_by_default: false,
                       include_directories: oidc_incdirs,
                       dependencies: oidc_deps,
                      )

test('oidc_test', oidc_test)
