//! The one clock behind every timestamp: the system's, unless a simulator set its own for this thread.

use std::cell::Cell;

use n0_future::time::SystemTime;

thread_local! {
    static CLOCK: Cell<Option<fn() -> u64>> = const { Cell::new(None) };
}

/// Milliseconds since the Unix epoch.
pub fn now() -> u64 {
    match CLOCK.get() {
        Some(clock) => clock(),
        None => SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64,
    }
}

/// Reads `clock` instead of the system's on this thread.
pub fn set(clock: fn() -> u64) {
    CLOCK.set(Some(clock));
}
