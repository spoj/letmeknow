//! The pure parts of catching up: comparing heads, chaining entries, negentropy's item range.

use lmk_proto::{Bytes, head::Head, peer::Hello};
use negentropy::{Id, NegentropyStorageVector};

/// Whether `theirs` proves the service showed us a different log: our chain at its length differs.
/// A longer head is judged once we reach its length.
pub fn contradicts(theirs: &Head, ours: &Head, chain: impl FnOnce(u64) -> Option<[u8; 32]>) -> bool {
    theirs.length <= ours.length && chain(theirs.length).is_some_and(|hash| hash[..] != theirs.hash.0[..])
}

/// The chain hash after `entries`, from `start`.
pub fn extend(start: [u8; 32], entries: &[Bytes]) -> [u8; 32] {
    entries.iter().fold(start, |hash, entry| lmk_proto::head::next(&hash, &entry.0))
}

/// The lowest epoch two members reconcile: neither offers what predates the later join, and the
/// range starts at the lower floor (each side filters against the other's floor when it sends).
pub fn lowest(mine: &Hello, theirs: &Hello) -> u64 {
    mine.joined.max(theirs.joined).max(mine.floor.min(theirs.floor))
}

pub fn storage(items: &[(u64, [u8; 32])]) -> NegentropyStorageVector {
    let mut storage = NegentropyStorageVector::with_capacity(items.len());
    for &(epoch, id) in items {
        storage.insert(epoch, Id::from_byte_array(id)).expect("the storage is not sealed yet");
    }
    storage.seal().expect("sealed once");
    storage
}

#[cfg(test)]
mod tests {
    use super::*;
    use negentropy::Negentropy;

    fn head(length: u64, hash: [u8; 32]) -> Head {
        Head { log: Bytes(b"g".to_vec()), length, hash: hash.into(), time: 0, sig: Bytes::default() }
    }

    #[test]
    fn heads() {
        let entries: Vec<Bytes> = [b"a", b"b", b"c"].iter().map(|e| Bytes(e.to_vec())).collect();
        let chain: Vec<[u8; 32]> = (0..=3).map(|n| extend(lmk_proto::head::start(b"g"), &entries[..n])).collect();
        let ours = head(3, chain[3]);
        let at = |n: u64| Some(chain[n as usize]);
        assert!(!contradicts(&head(3, chain[3]), &ours, at));
        assert!(!contradicts(&head(2, chain[2]), &ours, at));
        assert!(contradicts(&head(3, chain[2]), &ours, at));
        assert!(contradicts(&head(1, chain[2]), &ours, at));
        assert!(!contradicts(&head(5, [9; 32]), &ours, at), "a longer head waits for its entries");
        assert!(!contradicts(&head(1, [9; 32]), &ours, |_| None), "a position before we joined proves nothing");
    }

    #[test]
    fn lowest_epoch() {
        let hello = |floor, joined| Hello { group: Bytes::default(), epoch: 9, floor, joined };
        assert_eq!(lowest(&hello(2, 1), &hello(4, 3)), 3, "the later join");
        assert_eq!(lowest(&hello(5, 1), &hello(6, 3)), 5, "the lower floor");
    }

    #[test]
    fn reconcile() {
        let id = |n: u8| [n; 32];
        let a = storage(&[(1, id(1)), (2, id(2)), (3, id(3))]);
        let b = storage(&[(2, id(2)), (3, id(4))]);
        let mut initiator = Negentropy::borrowed(&a, 0).unwrap();
        let mut responder = Negentropy::borrowed(&b, 0).unwrap();
        let mut query = initiator.initiate().unwrap();
        let (mut have, mut need) = (Vec::new(), Vec::new());
        loop {
            let reply = responder.reconcile(&query).unwrap();
            match initiator.reconcile_with_ids(&reply, &mut have, &mut need).unwrap() {
                Some(next) => query = next,
                None => break,
            }
        }
        have.sort();
        assert_eq!(have, vec![Id::from_byte_array(id(1)), Id::from_byte_array(id(3))]);
        assert_eq!(need, vec![Id::from_byte_array(id(4))]);
    }
}
