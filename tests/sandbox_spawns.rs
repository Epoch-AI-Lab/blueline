//! The `may_spawn_child` guard, from outside the test harness.
//!
//! `src/sandbox.rs` pins that a `#[cfg(test)]` build always refuses to spawn
//! (incident 2026-10-09: an unguarded self-exec re-ran the suite and fork-bombed
//! the machine). That test cannot tell the guard from a hardcoded `false`: under
//! `cfg(test)` the marker branch is never reached, so a function that returned
//! `false` outright would pass it.
//!
//! An integration test links the library *without* `cfg(test)`, so here both
//! arms are live. They are reached through `may_spawn_child_given`, which takes
//! the marker as an argument: the previous version of this file set the real
//! environment variable with `unsafe { set_var }`, whose safety argument was
//! "this is the only thread in this binary that touches the environment". That
//! holds until someone adds a second test, at which point it is a data race and
//! `set_var` has been `unsafe` since edition 2024 for exactly that reason.
//!
//! Nothing here spawns anything, and nothing writes the environment, so the
//! tests run in parallel and any number of them is free.

use blueline::sandbox::{may_spawn_child, may_spawn_child_given};

#[test]
fn a_production_process_may_spawn_an_extraction_child() {
    // The half a unit test cannot reach. Returning `false` here would disable
    // the sandbox for every real review and make each one disclose
    // `P05_SANDBOX_UNAVAILABLE` on a kernel that supports it.
    assert!(
        may_spawn_child_given(false),
        "a production process with no child marker must be allowed to spawn \
         the extraction child"
    );
    // The real environment too: a marker leaked in from a parent process would
    // fail here, which is the whole point — the guard reads the environment,
    // and this binary must not have one to read.
    assert!(
        may_spawn_child(),
        "a real process must agree with the pure form when no marker is set"
    );
}

#[test]
fn a_process_holding_the_marker_may_not_spawn_a_child_of_its_own() {
    // The other half: this is what stops an extraction child from spawning a
    // child of its own. The recursion it prevents is the incident above.
    assert!(
        !may_spawn_child_given(true),
        "a process holding BLUELINE_SANDBOX_CHILD is an extraction child and \
         must not spawn one; allowing it is the unbounded recursion the marker \
         prevents"
    );
}
