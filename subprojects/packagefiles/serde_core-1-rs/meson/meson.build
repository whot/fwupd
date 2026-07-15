# Replaces serde_core's build.rs for meson builds.
#
# The build.rs generates private.rs (handled by patching src/crate_root.rs)
# and sets cfg flags based on the rustc version.
# With rustc >= 1.81, none of the compat cfgs need to be set.

extra_args += ['--cfg', 'if_docsrs_then_no_serde_core']
