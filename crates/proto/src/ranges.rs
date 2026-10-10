//! Sets of log positions as inclusive ranges, "1-10, 13-50", carried in JSON as `[[1,10],[13,50]]`.

use serde::{Deserialize, Deserializer, Serialize};

/// Sorted, disjoint, non-adjacent inclusive ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    pub fn range(first: u64, last: u64) -> Self {
        Self::from(vec![(first, last)])
    }

    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn first(&self) -> Option<u64> {
        self.0.first().map(|&(first, _)| first)
    }

    pub fn len(&self) -> u64 {
        self.0.iter().map(|&(first, last)| last - first + 1).sum()
    }

    pub fn contains(&self, position: u64) -> bool {
        let i = self.0.partition_point(|&(_, last)| last < position);
        self.0.get(i).is_some_and(|&(first, _)| first <= position)
    }

    pub fn insert(&mut self, position: u64) {
        *self = self.union(&Self::range(position, position));
    }

    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().flat_map(|&(first, last)| first..=last)
    }

    pub fn union(&self, other: &Self) -> Self {
        Self::from([&self.0[..], &other.0[..]].concat())
    }

    pub fn intersection(&self, other: &Self) -> Self {
        let (mut out, mut i, mut j) = (Vec::new(), 0, 0);
        while let (Some(&(a0, a1)), Some(&(b0, b1))) = (self.0.get(i), other.0.get(j)) {
            if a0.max(b0) <= a1.min(b1) {
                out.push((a0.max(b0), a1.min(b1)));
            }
            if a1 < b1 { i += 1 } else { j += 1 }
        }
        Self(out)
    }

    pub fn difference(&self, other: &Self) -> Self {
        let mut out = Vec::new();
        let mut j = 0;
        for &(first, last) in &self.0 {
            let mut from = Some(first);
            while let (Some(f), Some(&(b0, b1))) = (from, other.0.get(j)) {
                if b1 < f {
                    j += 1;
                    continue;
                }
                if b0 > last {
                    break;
                }
                if b0 > f {
                    out.push((f, b0 - 1));
                }
                from = b1.checked_add(1).filter(|&next| next <= last);
                if b1 > last {
                    break;
                }
                j += 1;
            }
            if let Some(f) = from {
                out.push((f, last));
            }
        }
        Self(out)
    }

    /// The positions up to `last`.
    pub fn through(&self, last: u64) -> Self {
        self.intersection(&Self::range(0, last))
    }
}

impl From<Vec<(u64, u64)>> for Ranges {
    /// Sorts and merges any ranges, dropping empty ones.
    fn from(mut ranges: Vec<(u64, u64)>) -> Self {
        ranges.retain(|&(first, last)| first <= last);
        ranges.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (first, last) in ranges {
            match out.last_mut() {
                Some(prev) if first <= prev.1.saturating_add(1) => prev.1 = prev.1.max(last),
                _ => out.push((first, last)),
            }
        }
        Self(out)
    }
}

impl FromIterator<u64> for Ranges {
    fn from_iter<I: IntoIterator<Item = u64>>(positions: I) -> Self {
        Self::from(positions.into_iter().map(|p| (p, p)).collect::<Vec<_>>())
    }
}

impl<'de> Deserialize<'de> for Ranges {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(Vec::<(u64, u64)>::deserialize(d)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(r: &Ranges) -> Vec<u64> {
        r.iter().collect()
    }

    #[test]
    fn normalizes_what_a_peer_sends() {
        let r: Ranges = serde_json::from_str("[[13,50],[1,10],[11,11],[60,59],[5,7]]").unwrap();
        assert_eq!(r.ranges(), &[(1, 11), (13, 50)]);
        assert_eq!(serde_json::to_string(&r).unwrap(), "[[1,11],[13,50]]");
        assert_eq!(r.len(), 49);
        assert!(r.contains(11) && !r.contains(12) && r.contains(50) && !r.contains(0));
    }

    #[test]
    fn set_operations_match_sets() {
        let mut seed = 7u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % 40
        };
        for _ in 0..500 {
            let a: Ranges = (0..10).map(|_| next()).collect();
            let b: Ranges = (0..10).map(|_| next()).collect();
            let (sa, sb) = (set(&a), set(&b));
            assert_eq!(set(&a.union(&b)), { let mut u = [&sa[..], &sb[..]].concat(); u.sort(); u.dedup(); u });
            assert_eq!(set(&a.intersection(&b)), sa.iter().copied().filter(|p| sb.contains(p)).collect::<Vec<_>>());
            assert_eq!(set(&a.difference(&b)), sa.iter().copied().filter(|p| !sb.contains(p)).collect::<Vec<_>>());
            assert_eq!(set(&a.through(20)), sa.iter().copied().filter(|&p| p <= 20).collect::<Vec<_>>());
        }
    }

    #[test]
    fn edges() {
        let max = Ranges::range(u64::MAX - 1, u64::MAX);
        assert_eq!(max.difference(&Ranges::range(u64::MAX, u64::MAX)).ranges(), &[(u64::MAX - 1, u64::MAX - 1)]);
        assert!(max.difference(&max).is_empty());
        assert_eq!(Ranges::range(0, 5).difference(&Ranges::range(2, 3)).ranges(), &[(0, 1), (4, 5)]);
    }
}
