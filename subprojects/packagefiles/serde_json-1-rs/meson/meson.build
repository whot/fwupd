# Replaces serde_json's build.rs for meson builds.
#
# Sets the fast_arithmetic cfg based on the target architecture.

host_cpu = host_machine.cpu_family()

if host_cpu in ['x86_64', 'aarch64', 'loongarch64', 'mips64', 'ppc64', 'riscv64']
  extra_args += ['--cfg', 'fast_arithmetic="64"']
elif host_machine.cpu() == 'wasm32'
  extra_args += ['--cfg', 'fast_arithmetic="64"']
else
  extra_args += ['--cfg', 'fast_arithmetic="32"']
endif
