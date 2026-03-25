# Build profile: use release for install builds, debug for development
if get_option('buildtype') == 'release' or get_option('buildtype') == 'plain'
  cargo_profile = 'release'
  cargo_profile_dir = 'release'
else
  cargo_profile = 'dev'
  cargo_profile_dir = 'debug'
endif

# cargo needs PKG_CONFIG_PATH to find fwupdplugin-uninstalled.pc.
# Setting PKG_CONFIG_PATH overrides the default search path, so we must
# also include the system pkg-config directories for transitive
# dependencies (glib, gio, libusb, etc.).
pkgconfig = find_program('pkg-config')
pkg_config_system_path = run_command(
  pkgconfig, '--variable', 'pc_path', 'pkg-config',
  check: true,
).stdout().strip()
cargo_env = environment()
cargo_env.set('PKG_CONFIG_PATH',
  join_paths(meson.project_build_root(), 'meson-uninstalled') + ':' + pkg_config_system_path,
)
# Don't inherit CFLAGS from the environment -- the cargo test ABI checks
# compile C code and stray flags break the compilation.
cargo_env.set('CFLAGS', '')

cargo_target_dir = join_paths(meson.project_build_root(), 'rust-target')

# We need to build with --all-targets so meson test doesn't recompile and
# hit the test timeouts. Also, this way we catch compilation errors when
# building, not when testing.
cargo_args = [
  '--manifest-path', join_paths(meson.current_source_dir(), 'Cargo.toml'),
  '--target-dir', cargo_target_dir,
  '--profile', cargo_profile,
  '--all-targets',
]

if build_docs
  cargo_doc_args = [
    '--manifest-path', join_paths(meson.current_source_dir(), 'Cargo.toml'),
    '--target-dir', cargo_target_dir,
    '--no-deps',
  ]

  custom_target(
    'rust-doc',
    output: 'doc',
    command: [
      'sh', '-c',
      ' '.join([
        cargo.full_path(), 'doc',
      ] + cargo_doc_args + [
        '&&',
        'cp', '-a',
        join_paths(cargo_target_dir, 'doc'),
        '@OUTPUT@',
      ]),
    ],
    env: cargo_env,
    depends: [fwupdplugin],
    console: true,
    install: false,
    build_by_default: true,
  )
endif

# ABI/constant validation tests for the -sys crates.
# These compile C code to cross-validate struct layouts and constant values
# against the Rust FFI bindings.
test(
  'fwupd-sys-abi',
  cargo,
  args: ['test'] + cargo_args + ['-p', 'fwupd-sys'],
  env: cargo_env,
  depends: [fwupd],
  timeout: 120,
  suite: 'rust',
)
test(
  'fwupdplugin-sys-abi',
  cargo,
  args: ['test'] + cargo_args + ['-p', 'fwupdplugin-sys'],
  env: cargo_env,
  depends: [fwupdplugin],
  timeout: 120,
  suite: 'rust',
)
test(
  'fwupdplugin',
  cargo,
  args: ['test'] + cargo_args + ['-p', 'fwupdplugin'],
  env: cargo_env,
  depends: [fwupdplugin],
  timeout: 120,
  suite: 'rust',
)
