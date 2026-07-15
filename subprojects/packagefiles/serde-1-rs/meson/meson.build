# Replaces serde's build.rs for meson builds.
#
# The build.rs generates private.rs (handled by patching src/lib.rs)
# and sets cfg flags based on the rustc version.
# With rustc >= 1.81, no compat cfgs need to be set.

extra_args += ['--cfg', 'if_docsrs_then_no_serde_core']
