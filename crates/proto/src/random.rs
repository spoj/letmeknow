//! The one source of randomness: the system's, unless a simulator seeded its own for this thread.

use std::cell::Cell;

thread_local! {
    static SEEDED: Cell<Option<u64>> = const { Cell::new(None) };
}

pub fn fill(bytes: &mut [u8]) {
    let Some(mut state) = SEEDED.get() else {
        getrandom::fill(bytes).expect("the system has randomness");
        return;
    };
    for chunk in bytes.chunks_mut(8) {
        // SplitMix64.
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes()[..chunk.len()]);
    }
    SEEDED.set(Some(state));
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    fill(&mut bytes);
    bytes
}

/// Draws from a generator seeded with `seed` instead of the system on this thread.
pub fn seed(seed: u64) {
    SEEDED.set(Some(seed));
}
