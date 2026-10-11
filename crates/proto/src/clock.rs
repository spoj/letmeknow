//! The one clock behind every timestamp: the system's, unless a test set its own for this thread; and how far the
//! membership service's clock is from it, for the times other members see.

use std::cell::Cell;
use std::sync::Mutex;

use n0_future::time::SystemTime;

/// How long the reading with the shortest round trip stands before any newer one replaces it, so that a clock set
/// meanwhile shows: 10 minutes.
const KEEP: u64 = 10 * 60 * 1000;

thread_local! {
    static CLOCK: Cell<Option<fn() -> u64>> = const { Cell::new(None) };
}

/// The reading of the service's clock with the shortest round trip: the trip, the service's offset from this clock,
/// and when it came, in milliseconds.
static READING: Mutex<Option<(u64, i64, u64)>> = Mutex::new(None);

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

/// Takes a reading of the membership service's clock: `service`, its time in its answer to a request sent at `sent`
/// and answered at `received`, by this clock.
pub fn heard(sent: u64, received: u64, service: u64) {
    let trip = received.saturating_sub(sent);
    let offset = service as i64 - (sent + trip / 2) as i64;
    let mut kept = READING.lock().unwrap();
    if kept.is_none_or(|(best, _, at)| trip <= best || received.saturating_sub(at) > KEEP) {
        *kept = Some((trip, offset, received));
    }
}

/// Milliseconds since the Unix epoch by the membership service's clock, as far as heard: for the times other members
/// see, such as when a message was sent.
pub fn corrected() -> u64 {
    let offset = READING.lock().unwrap().map_or(0, |(_, offset, _)| offset);
    now().saturating_add_signed(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reading_with_the_shortest_round_trip_stands_until_it_is_old() {
        heard(1_000, 1_400, 11_000);
        heard(2_000, 2_100, 12_050);
        heard(3_000, 3_900, 3_450);
        assert_eq!(READING.lock().unwrap().map(|(_, offset, _)| offset), Some(10_000));
        heard(2_100 + KEEP + 1, 2_100 + KEEP + 901, 2_100 + KEEP + 451 + 5_000);
        set(|| 1_000);
        assert_eq!(corrected(), 6_000);
    }
}
