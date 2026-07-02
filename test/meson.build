# The '..' include dir also brings in the build root (its build-tree
# counterpart), which is where the generated test_config.h lives.
test_incdirs = include_directories('..', '../include', '../lib')

hba_test = executable('hba_test',
                      'hba_test.c',
                      '../src/hba.c',
                      '../src/util.c',
                      libusual_sources,
                      config_h,
                      build_by_default: false,
                      include_directories: test_incdirs,
                      dependencies: [libevent, openssl, systemd, threads] + net_deps,
                     )

libpq = dependency('libpq', required: false, disabler: true)

asynctest = executable('asynctest',
                       'asynctest.c',
                       libusual_sources,
                       config_h,
                       build_by_default: false,
                       include_directories: test_incdirs,
                       dependencies: [libevent, libpq, systemd, threads] + net_deps,
                      )

test('hba_test',
     hba_test,
     workdir: meson.project_source_root() / 'test',
    )

# Standalone smoke test for the example OAuth validator module: build the
# validator as a shared object, build the dlopen()-based driver, and run the
# driver against the validator.  Neither pulls in PgBouncer or libusual code,
# only include/oauth.h.  Guarded by oauth_support because the driver needs
# dlopen() (and the module is pointless without it).
if oauth_support
  oauth_validator = shared_module('oauth_validator',
                                  'oauth_validator.c',
                                  build_by_default: false,
                                  include_directories: test_incdirs,
                                  name_prefix: '',
                                 )

  oauth_validator_test = executable('oauth_validator_test',
                                    'oauth_validator_test.c',
                                    build_by_default: false,
                                    include_directories: test_incdirs,
                                    dependencies: [libdl],
                                   )

  test('oauth_validator_test',
       oauth_validator_test,
       args: [oauth_validator.full_path()],
       depends: [oauth_validator],
      )
endif
