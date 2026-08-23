//! Thin by design. Everything lives in the library — see `ssh_control::cli`,
//! which is in there rather than here because this is a separate crate and can
//! only see the library's `pub` API, while the headless unlock has to drive
//! `App`'s `pub(crate)` internals.
fn main() {
    ssh_control::cli::main();
}
