# ----------------------------------------------------------------------
# Keycloak OAuth validator module
#
# A standalone shared object: nothing links against it, pgbouncer dlopen()s it
# when it is named in oauth_validator_libraries, and it needs nothing from the
# rest of the build but include/oauth.h.
#
# The autoconf build drives this module's own Makefile (it cannot express a
# shared library); here it is built directly, so the sources are listed twice.
# Keep the two lists in step.
# ----------------------------------------------------------------------

keycloak_deps = [libcurl, jansson, openssl, threads]
keycloak_incdirs = include_directories('../../include')

shared_module('keycloak',
  'keycloak.c',
  'kc_crypto.c',
  'kc_http.c',
  'kc_jwt.c',
  # pgbouncer.ini names the module by file name, so produce the same
  # keycloak.so the standalone Makefile does rather than meson's platform
  # default (libkeycloak.so, or a .dylib on macOS).
  name_prefix: '',
  name_suffix: windows ? 'dll' : 'so',
  include_directories: keycloak_incdirs,
  dependencies: keycloak_deps,
  install: true,
  install_dir: get_option('libdir') / 'pgbouncer',
)

# Unit tests. They mint their own keys and serve a JWKS from a throwaway HTTP
# server on localhost, so they need no Keycloak; kc_test.c links the module's
# internals directly instead of dlopen()ing the module.
kc_test = executable('kc_test',
                     'kc_test.c',
                     'kc_crypto.c',
                     'kc_http.c',
                     'kc_jwt.c',
                     build_by_default: false,
                     include_directories: keycloak_incdirs,
                     dependencies: keycloak_deps,
                    )

test('kc_test', kc_test)
