//! Identity: revoking a device removes its sessions from every group.

use std::collections::BTreeMap;

use lmk_proto::Bytes;

use super::{CONVERGE, KEYS_READ, short};
use crate::trace::{Trace, What};

/// A device off its identity's list since well before a quiet period (`KEYS_READ`) has no session in any group as its
/// active members see it at the period's end, but in its own stale view.
pub fn revocation(t: &Trace) -> Result<(), String> {
    let mut listed: BTreeMap<(&Bytes, &Bytes), (bool, u64)> = BTreeMap::new();
    for o in &t.0 {
        match &o.what {
            What::Device { identity, device, listed: on } => drop(listed.insert((identity, device), (*on, o.at))),
            What::Quiet { views } => {
                let started = o.at.saturating_sub(CONVERGE);
                for ((identity, device), _) in listed.iter().filter(|(_, (on, since))| !on && since + KEYS_READ <= started) {
                    for v in views.iter().filter(|v| v.active()) {
                        let own = v.leaves.iter().find(|leaf| leaf.key == v.key).and_then(|leaf| leaf.device.as_ref());
                        if own == Some(*device) {
                            continue;
                        }
                        if v.leaves.iter().any(|leaf| leaf.identity.as_ref() == Some(*identity) && leaf.device.as_ref() == Some(*device)) {
                            return Err(format!(
                                "device {} of {}, taken off, is still in {} as m{} sees it at {}",
                                short(device),
                                short(identity),
                                short(&v.group),
                                v.m,
                                super::clock(o.at)
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::props::build::*;
    use crate::trace::Leaf;

    #[test]
    fn a_dropped_device_is_gone_after_a_while() {
        let identity = Bytes(vec![9]);
        let device = |m: usize| Leaf { identity: Some(identity.clone()), device: Some(key(m)), ..leaf(m) };
        let drop1 = What::Device { identity: identity.clone(), device: key(1), listed: false };
        let still = |at| {
            let mut v = view(0, 2, &[0, 1]);
            v.leaves = vec![leaf(0), device(1)];
            (at, What::Quiet { views: vec![v] })
        };
        assert!(revocation(&trace(vec![(0, drop1.clone()), still(KEYS_READ)])).is_ok(), "too soon to tell");
        assert!(revocation(&trace(vec![(0, drop1.clone()), still(KEYS_READ + CONVERGE)])).unwrap_err().contains("still in"));
        let relinked = What::Device { identity: identity.clone(), device: key(1), listed: true };
        assert!(revocation(&trace(vec![(0, drop1.clone()), (5, relinked), still(KEYS_READ + CONVERGE)])).is_ok());
        let mut own = view(1, 2, &[0, 1]);
        own.leaves = vec![leaf(0), device(1)];
        assert!(revocation(&trace(vec![(0, drop1), (KEYS_READ + CONVERGE, What::Quiet { views: vec![own] })])).is_ok(), "its own stale view");
    }
}
