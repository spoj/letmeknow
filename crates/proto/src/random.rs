//! The system's randomness.

pub fn fill(bytes: &mut [u8]) {
    getrandom::fill(bytes).expect("the system has randomness");
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    fill(&mut bytes);
    bytes
}
