# Replaces proc-macro2's build.rs for meson builds.
#
# The build.rs probes the compiler for feature support and sets cfg flags.
# For rustc >= 1.79 (stable), the key flags are:
# - wrap_proc_macro: wraps real proc_macro types instead of polyfilling
# - proc_macro_span_location: enables Span::start/end (rustc >= 1.88)

# wrap_proc_macro is set by build.rs when not using procmacro2_semver_exempt.
# This is essential for proc macros to work correctly with the real compiler.
extra_args += ['--cfg', 'wrap_proc_macro']

# proc_macro_span_location was added in Rust 1.88
# proc_macro_span_file was added in Rust 1.88
# We could probe for these but they're not critical for compilation.
