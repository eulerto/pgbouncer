# ----------------------------------------------------------------------
# Microsoft Entra ID OAuth validator module
#
# A standalone shared object: nothing links against it, pgbouncer dlopen()s it
# when it is named in oauth_validator_libraries, and it needs nothing from the
# rest of the build but include/oauth.h and the shared OIDC core in
# src/oauth-common (see its meson.build for oidc_sources and friends).
#
# The autoconf build drives this module's own Makefile (it cannot express a
# shared library); here it is built directly, so the sources are listed twice.
# Keep the two lists in step.
# ----------------------------------------------------------------------

shared_module('entra',
  'entra.c',
  oidc_sources,
  # pgbouncer.ini names the module by file name, so produce the same entra.so
  # the standalone Makefile does rather than meson's platform default
  # (libentra.so, or a .dylib on macOS).
  name_prefix: '',
  name_suffix: windows ? 'dll' : 'so',
  include_directories: oidc_incdirs,
  dependencies: oidc_deps,
  install: true,
  install_dir: get_option('libdir') / 'pgbouncer',
)

# Unit tests for what this module adds to the core: the settings, the issuer
# and endpoint URLs it derives from them, and the Entra-shaped claim policy.
# entra_test.c includes entra.c, so the module sources are not listed again.
entra_test = executable('entra_test',
                        'entra_test.c',
                        oidc_sources,
                        oidc_test_sources,
                        build_by_default: false,
                        include_directories: oidc_incdirs,
                        dependencies: oidc_deps,
                       )

test('entra_test', entra_test)
