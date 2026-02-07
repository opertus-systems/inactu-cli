//! Inactu host crate.
//!
//! The implementation is split across repository modules and will be
//! promoted into Rust crates as v0 execution surfaces are finalized.

/// Returns the current crate identity string.
pub fn crate_id() -> &'static str {
    "inactu-host"
}
