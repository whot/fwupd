cargo_env = environment()
cargo_env.set('MESON_BUILDTYPE', get_option('buildtype'))
cargo_env.set('MESON_BUILD_ROOT', meson.project_build_root())
cargo_env.set('WORKSPACE_CARGO_TOML', join_paths(meson.project_source_root(), 'Cargo.toml'))

fwupd_rust_src = [
  join_paths(meson.project_source_root(), 'Cargo.toml'),
  join_paths(meson.project_source_root(), 'Cargo.lock'),
  'fwupd/src/bitflags.rs',
  'fwupd/src/compressor/mod.rs',
  'fwupd/src/compressor/zlib.rs',
  'fwupd/src/lib.rs',
  'fwupd/src/streams/composite_input_stream.rs',
  'fwupd/src/streams/compressor_stream.rs',
  'fwupd/src/streams/file_input_stream.rs',
  'fwupd/src/streams/memory_input_stream.rs',
  'fwupd/src/streams/mod.rs',
  'fwupd/src/streams/partial_input_stream.rs',
  'fwupd/src/units.rs',
]

fwupd_ffi_src = [
  join_paths(meson.project_source_root(), 'Cargo.toml'),
  join_paths(meson.project_source_root(), 'Cargo.lock'),
  'fwupd-ffi/src/compressor.rs',
  'fwupd-ffi/src/cstream.rs',
  'fwupd-ffi/src/glib/gerror.rs',
  'fwupd-ffi/src/glib/gstring.rs',
  'fwupd-ffi/src/glib/mod.rs',
  'fwupd-ffi/src/lib.rs',
  'fwupd-ffi/src/streams.rs',
]

# The pure Rust library
fwupd_rust_lib = custom_target(
  'fwupd-rust',
  output: 'fwupd-rust.stamp',
  command: [
    cargo_wrapper,
    '-p',
    'fwupd',
    '--stamp',
    'build',
    '@OUTPUT@',
  ],
  env: cargo_env,
  console: true,
  install: false,
  build_by_default: false,
  depend_files: fwupd_rust_src,
)

# The FFI lib to call into Rust
fwupd_ffi_lib = custom_target(
  'fwupd-ffi',
  output: 'libfwupd_ffi.a',
  command: [
    cargo_wrapper,
    '-p',
    'fwupd-ffi',
    'build',
    '@OUTPUT@',
  ],
  env: cargo_env,
  console: true,
  install: host_machine.system() == 'android',
  build_by_default: false,
  depend_files: fwupd_ffi_src,
  depends: [fwupd_rust_lib],
)

fwupd_rust_ffi_incdir = include_directories('fwupd-ffi')
fwupd_rust_ffi_dep = declare_dependency(
  # We can't use link_with here because custom_target output
  # isn't accepted. So all users of our crate need an explicit
  # link_with in addition to the dependencies
  include_directories: [fwupd_rust_ffi_incdir],
  dependencies: [zlib],
)

if build_docs
  custom_target(
    'rust-doc',
    output: 'doc',
    command: [cargo_wrapper, 'doc', '@OUTPUT@'],
    env: cargo_env,
    console: true,
    install: false,
    build_by_default: true,
    depend_files: [fwupd_rust_src, fwupd_ffi_src],
  )
endif

if get_option('tests')
  test(
    'fwupd-rust',
    cargo_wrapper,
    args: ['-p', 'fwupd', 'test'],
    env: cargo_env,
    timeout: 120,
    suite: 'rust',
  )
  test(
    'fwupd-rust-ffi',
    cargo_wrapper,
    args: ['-p', 'fwupd-ffi', 'test'],
    env: cargo_env,
    timeout: 120,
    suite: 'rust',
  )
  if build_docs
    test(
      'fwupd-doctest',
      cargo_wrapper,
      args: ['-p', 'fwupd', 'test', '--doc'],
      env: cargo_env,
      timeout: 120,
      suite: 'rust',
    )
  endif
endif
