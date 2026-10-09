//! The `may_spawn_child` guard's *production* half, from outside the test
//! harness.
//!
//! `src/sandbox.rs` pins that a `#[cfg(test)]` build always refuses to spawn
//! (incident 2026-10-09: an unguarded self-exec re-ran the suite and fork-bombed
//! the machine). That test cannot tell the guard from a hardcoded `false`: under
//! `cfg(test)` the marker branch is never reached, so a function that returned
//! `false` outright would pass it.
//!
//! An integration test links the library *without* `cfg(test)`, so here the
//! marker branch is live. Nothing in this file spawns anything: the guard is a
//! pure function of the environment, and setting the marker is cheaper than the
//! process it would otherwise create.

use blueline::sandbox::{CHILD_ENV, may_spawn_child};

#[test]
fn the_guard_refuses_the_harness_and_a_marker_but_allows_a_normal_process() {
    // One test, not three, because the marker is process-global and libtest
    // runs tests in parallel threads. Separate tests would race: a second
    // thread reading the environment while this one holds it set would assert
    // against whatever value it happened to observe, which is how an
    // environment test becomes a coin flip.
    assert!(
        !std::env::var_os(CHILD_ENV).is_some(),
        "this test needs a clean environment; the marker leaked in from a parent"
    );

    // The half a unit test cannot reach. Returning `false` here would disable
    // the sandbox for every real review and make each one disclose
    // `P05_SANDBOX_UNAVAILABLE` on a kernel that supports it.
    assert!(
        may_spawn_child(),
        "a production process with no child marker must be allowed to spawn \
         the extraction child"
    );

    let prior = std::env::var_os(CHILD_ENV);
    // Safety: this is the only thread in this binary that touches the
    // environment, and it reads the variable back through `may_spawn_child` in
    // the same thread, so nothing else can observe the window.
    unsafe {
        std::env::set_var(CHILD_ENV, "1");
    }
    let allowed = may_spawn_child();
    unsafe {
        match prior {
            Some(v) => std::env::set_var(CHILD_ENV, v),
            None => std::env::remove_var(CHILD_ENV),
        }
    }

    // The other half: this is what stops an extraction child from spawning a
    // child of its own. The recursion it prevents is the incident above.
    assert!(
        !allowed,
        "a process holding {CHILD_ENV} is an extraction child and must not \
         spawn one; allowing it is the unbounded recursion the marker prevents"
    );
    assert!(
        !std::env::var_os(CHILD_ENV).is_some(),
        "the marker must be restored, or every later guard assertion in this \
         binary is meaningless"
    );
}
