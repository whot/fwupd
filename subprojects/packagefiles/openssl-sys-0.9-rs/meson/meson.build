# Replaces openssl-sys's build.rs for meson builds.
#
# Detects the system OpenSSL version and sets the appropriate cfg flags
# that build.rs would normally set via cargo:rustc-cfg.

cc = meson.get_compiler('c')
openssl_dep = dependency('openssl')

# Detect OpenSSL version via pkg-config
openssl_version = openssl_dep.version()
v = openssl_version.split('.')
openssl_major = v[0].to_int()
openssl_minor = v[1].to_int()
openssl_patch = v[2].to_int()

extra_args += ['--cfg', 'openssl']

# Version-gate cfgs matching openssl-sys/build/cfgs.rs
# All of these are unconditionally set for OpenSSL >= 1.0.1
extra_args += ['--cfg', 'ossl101']
extra_args += ['--cfg', 'ossl102']
extra_args += ['--cfg', 'ossl102f']
extra_args += ['--cfg', 'ossl102h']
extra_args += ['--cfg', 'ossl110']

# ossl110f: >= 1.1.0f
extra_args += ['--cfg', 'ossl110f']
extra_args += ['--cfg', 'ossl110g']
extra_args += ['--cfg', 'ossl110h']
extra_args += ['--cfg', 'ossl111']
extra_args += ['--cfg', 'ossl111b']
extra_args += ['--cfg', 'ossl111c']
extra_args += ['--cfg', 'ossl111d']

if openssl_major >= 3
  extra_args += ['--cfg', 'ossl300']
endif
if openssl_major > 3 or (openssl_major == 3 and openssl_minor >= 2)
  extra_args += ['--cfg', 'ossl320']
endif
if openssl_major > 3 or (openssl_major == 3 and openssl_minor >= 3)
  extra_args += ['--cfg', 'ossl330']
endif
if openssl_major > 3 or (openssl_major == 3 and openssl_minor >= 4)
  extra_args += ['--cfg', 'ossl340']
endif
# Note: ossl350 is NOT set because openssl-sys 0.9.117 does not have
# ossl350-gated FFI bindings, and the openssl 0.10.81 crate's ossl350
# code paths expect API changes not present in these binding versions.

# Detect OPENSSL_NO_* macros from the system headers.
# These match the checks in openssl-sys/build/expando.c.
openssl_no_macros = [
  'BF', 'BUF_FREELISTS', 'CHACHA', 'IDEA', 'CAMELLIA', 'CAST',
  'CMS', 'COMP', 'EC', 'EC2M', 'ENGINE', 'KRB5', 'NEXTPROTONEG',
  'OCSP', 'OCB', 'PSK', 'RC4', 'RC2', 'RFC3779', 'RMD160', 'SHA',
  'SRP', 'SRTP', 'SSL3_METHOD', 'TLSEXT', 'SOCK', 'STDIO',
  'SM3', 'SM4', 'DEPRECATED_3_0', 'SEED', 'SCRYPT',
]

foreach m : openssl_no_macros
  if cc.has_header_symbol('openssl/opensslconf.h', 'OPENSSL_NO_' + m,
                          dependencies: openssl_dep)
    extra_args += ['--cfg', 'osslconf="OPENSSL_NO_' + m + '"']
  endif
endforeach

# Link against OpenSSL
extra_deps += [openssl_dep]
