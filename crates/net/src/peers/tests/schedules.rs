//! Members of one group on a simulated network, driving `Peers` as a node would.

use super::*;

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

struct Member {
    peers: Peers,
    head: u64,
    held: BTreeSet<u64>,
    lost: BTreeSet<u64>,
    /// Positions past its H, which it dropped.
    expired: BTreeSet<u64>,
    /// The commit that deletes keys it has yet to apply.
    commit: Option<u64>,
    /// When it applied its commit.
    applied: Option<u64>,
    /// What the core must go by, recorded apart: the summaries heard from connected peers on their connection.
    views: BTreeMap<usize, Summary>,
    progress: u64,
    /// The holder of its request.
    asking: Option<usize>,
}

struct Net {
    now: u64,
    rng: Rng,
    /// Whether each position, from 1, holds a message or a commit.
    log: Vec<bool>,
    members: Vec<Member>,
    links: BTreeSet<(usize, usize)>,
    jitter: u64,
    /// Ciphertext bytes, and bytes per second on links slower than instant.
    size: usize,
    bandwidth: BTreeMap<(usize, usize), u64>,
    flight: Vec<(u64, usize, usize, Frame)>,
    /// What each member asked of each holder since its last summary.
    asked: BTreeMap<(usize, usize), Ranges>,
    wants: usize,
}

impl Net {
    fn new(seed: u64, log: Vec<bool>, held: Vec<BTreeSet<u64>>, jitter: u64) -> Self {
        let members = held
            .into_iter()
            .map(|held| Member {
                peers: Peers::new(0),
                head: log.len() as u64,
                held,
                lost: BTreeSet::new(),
                expired: BTreeSet::new(),
                commit: None,
                applied: None,
                views: BTreeMap::new(),
                progress: 0,
                asking: None,
            })
            .collect();
        let mut net = Self {
            now: 0,
            rng: Rng(seed * 2 + 1),
            log,
            members,
            links: BTreeSet::new(),
            jitter,
            size: 1,
            bandwidth: BTreeMap::new(),
            flight: Vec::new(),
            asked: BTreeMap::new(),
            wants: 0,
        };
        for m in 0..net.members.len() {
            let own = net.own(m);
            net.members[m].peers.group(id(G), own, 0);
        }
        net
    }

    fn own(&self, m: usize) -> Own {
        let me = &self.members[m];
        let positions = || (1..=me.head).filter(|p| self.log[*p as usize - 1]);
        let commits: Ranges = (1..=me.head).filter(|p| !self.log[*p as usize - 1]).collect();
        let held = commits.union(&me.held.iter().copied().filter(|&p| p <= me.head).collect());
        let gone: Ranges = me.lost.union(&me.expired).copied().collect();
        let lacking = positions().collect::<Ranges>().difference(&held).difference(&gone);
        Own { head: head(G, me.head), held, read: Ranges::default(), lacking, keys: vec![] }
    }

    fn connect(&mut self, a: usize, b: usize) {
        self.links.insert((a.min(b), a.max(b)));
        for (x, y) in [(a, b), (b, a)] {
            let me = &mut self.members[x];
            me.peers.connect(key(y as u8), served(&[G]), self.now);
            me.views.remove(&y);
            me.progress = self.now;
            me.asking.take_if(|h| *h == y);
            self.asked.remove(&(x, y));
        }
    }

    fn disconnect(&mut self, a: usize, b: usize) {
        self.links.remove(&(a.min(b), a.max(b)));
        self.flight.retain(|&(_, from, to, _)| (from, to) != (a, b) && (from, to) != (b, a));
        for (x, y) in [(a, b), (b, a)] {
            let me = &mut self.members[x];
            me.peers.disconnect(&key(y as u8));
            me.views.remove(&y);
            me.asking.take_if(|h| *h == y);
            self.asked.remove(&(x, y));
        }
    }

    fn send(&mut self, from: usize, to: usize, frame: Frame) {
        let bytes = match &frame {
            Frame::Messages { items, .. } => items.iter().map(|i| i.ciphertext.0.len() as u64).sum(),
            _ => 0,
        };
        let slow = self.bandwidth.get(&(from, to)).map_or(0, |bps| bytes * 1000 / bps);
        let delay = 20 + self.rng.below(self.jitter + 1) + slow;
        self.flight.push((self.now + delay, from, to, frame));
    }

    fn deliver(&mut self, from: usize, to: usize, frame: Frame) {
        let lacking = self.own(to).lacking;
        let me = &mut self.members[to];
        match &frame {
            Frame::Hello { groups, .. } => {
                if me.views.get(&from) != Some(&groups[0]) {
                    me.progress = self.now;
                }
                me.views.insert(from, groups[0].clone());
                self.asked.remove(&(to, from));
            }
            Frame::Messages { items, answers, .. } => {
                for item in items {
                    if !me.lost.contains(&item.position) && !me.expired.contains(&item.position) && me.held.insert(item.position) && lacking.contains(item.position) {
                        me.progress = self.now;
                    }
                }
                if answers.is_some() {
                    me.asking.take_if(|h| *h == from);
                }
            }
            Frame::Want { positions, .. } => {
                let (held, size) = (me.held.clone(), self.size);
                let reply = answer(id(G), positions, &self.own(to).held, |p| held.contains(&p).then(|| vec![p as u8; size]));
                self.send(to, from, reply);
            }
            _ => {}
        }
        self.members[to].peers.frame(&key(from as u8), &frame, self.now);
        let own = self.own(to);
        self.members[to].peers.group(id(G), own, self.now);
    }

    /// Advances time a little: delivers what is due, then each member waits or applies, and polls.
    fn step(&mut self) {
        self.now += 1 + self.rng.below(100);
        while let Some(i) = (0..self.flight.len()).filter(|&i| self.flight[i].0 <= self.now).min_by_key(|&i| self.flight[i].0) {
            let (_, from, to, frame) = self.flight.remove(i);
            self.deliver(from, to, frame);
        }
        for m in 0..self.members.len() {
            let own = self.own(m);
            let now = self.now;
            let me = &mut self.members[m];
            me.peers.group(id(G), own.clone(), now);
            if let Some(commit) = me.commit
                && me.head >= commit
            {
                let lacking = own.lacking.through(commit);
                let decision = me.peers.wait(&id(G), &lacking, now);
                if decision != Decision::Wait {
                    let pending = me.views.values().any(|s| !lacking.intersection(&s.held.union(&s.fetching)).is_empty());
                    assert!(!pending || now - me.progress >= QUIET, "member {m} applied at {now} while a connected peer holds or fetches {lacking:?}");
                    if let Decision::Lose(lost) = decision {
                        me.lost.extend(lost.iter());
                    }
                    me.commit = None;
                    me.applied = Some(now);
                    let own = self.own(m);
                    self.members[m].peers.group(id(G), own, now);
                }
            }
            for out in self.members[m].peers.poll(now) {
                let Out::Frame(k, frame) = out else { continue };
                let to = k[0] as usize;
                if let Frame::Want { positions, .. } = &frame {
                    assert!(self.members[m].asking.replace(to).is_none(), "member {m} has two requests outstanding");
                    let asked = self.asked.entry((m, to)).or_default();
                    assert!(asked.intersection(positions).is_empty(), "member {m} asked {to} again for {positions:?}, before its next summary");
                    *asked = asked.union(positions);
                    self.wants += 1;
                }
                self.send(m, to, frame);
            }
        }
    }

    fn run_until(&mut self, until: u64) {
        while self.now < until {
            self.step();
        }
    }
}

fn messages(log: &[bool]) -> impl Iterator<Item = u64> + '_ {
    (1..=log.len() as u64).filter(|p| log[*p as usize - 1])
}

#[test]
fn random_schedules_converge_without_livelock_or_duplicate_asks_and_the_wait_holds() {
    for seed in 0..60 {
        let mut rng = Rng(seed * 7 + 3);
        let n = 3 + rng.below(3) as usize;
        let log: Vec<bool> = (0..20).map(|_| rng.below(5) != 0).collect();
        let held = (0..n).map(|_| messages(&log).filter(|_| rng.below(3) == 0).collect()).collect();
        let mut net = Net::new(seed, log, held, 400);
        for m in 0..n {
            net.members[m].commit = (1..=net.log.len() as u64).rfind(|p| !net.log[*p as usize - 1]);
        }
        while net.now < 60_000 {
            match net.rng.below(100) {
                0..3 => {
                    let (a, b) = (net.rng.below(n as u64) as usize, net.rng.below(n as u64) as usize);
                    if a != b && net.links.contains(&(a.min(b), a.max(b))) {
                        net.disconnect(a, b);
                    } else if a != b {
                        net.connect(a, b);
                    }
                }
                3..5 => {
                    let m = net.rng.below(n as u64) as usize;
                    net.log.push(true);
                    let p = net.log.len() as u64;
                    net.members[m].held.insert(p);
                    net.members[m].head = p;
                    let to: Vec<usize> = (0..n).filter(|&o| o != m && net.links.contains(&(m.min(o), m.max(o)))).collect();
                    for o in to {
                        let push = Frame::Messages { group: id(G), items: vec![Item { position: p, ciphertext: Bytes(vec![1]) }], answers: None };
                        net.send(m, o, push);
                    }
                }
                5 => {
                    net.log.push(false);
                    let p = net.log.len() as u64;
                    for m in 0..n {
                        if net.members[m].commit.is_none() && net.rng.below(2) == 0 {
                            net.members[m].commit = Some(p);
                        }
                    }
                }
                6..8 => {
                    let m = net.rng.below(n as u64) as usize;
                    let me = &mut net.members[m];
                    if let Some(&p) = me.held.iter().nth(net.rng.below(me.held.len() as u64 + 1) as usize) {
                        me.held.remove(&p);
                        me.expired.insert(p);
                    }
                }
                8..18 => {
                    let m = net.rng.below(n as u64) as usize;
                    net.members[m].head = net.log.len() as u64;
                }
                _ => {}
            }
            net.step();
        }
        for a in 0..n {
            for b in a + 1..n {
                if !net.links.contains(&(a, b)) {
                    net.connect(a, b);
                }
            }
            net.members[a].head = net.log.len() as u64;
        }
        net.run_until(120_000);
        let log = net.log.clone();
        for p in messages(&log) {
            if net.members.iter().any(|m| m.held.contains(&p)) {
                for (i, m) in net.members.iter().enumerate() {
                    assert!(m.held.contains(&p) || m.lost.contains(&p) || m.expired.contains(&p), "seed {seed}: member {i} lacks {p}, which a connected member holds");
                }
            }
        }
        let wants = net.wants;
        net.run_until(150_000);
        assert_eq!(net.wants, wants, "seed {seed}: asks go on after convergence");
        assert!(net.members.iter().all(|m| m.asking.is_none()));
    }
}

/// S holds p; Q, connected to S on a slow link, fetches it; R, connected only to Q, waits before the commit after p.
fn line(cut: Option<u64>) -> Net {
    let mut net = Net::new(1, vec![true, false], vec![[1].into(), BTreeSet::new(), BTreeSet::new()], 0);
    net.size = 400_000;
    net.bandwidth.insert((0, 1), 50_000);
    net.members[2].commit = Some(2);
    net.connect(0, 1);
    net.connect(1, 2);
    while net.now < 30_000 {
        if cut.is_some_and(|cut| net.now >= cut) && net.links.contains(&(0, 1)) {
            net.disconnect(0, 1);
        }
        net.step();
    }
    net
}

#[test]
fn a_member_waits_while_the_member_between_it_and_the_holder_fetches() {
    let net = line(None);
    let r = &net.members[2];
    assert!(r.held.contains(&1) && r.lost.is_empty());
    assert!(r.applied.unwrap() > 8_000, "Q got p from S only after 8 s");
}

#[test]
fn a_member_applies_once_the_member_between_stops_fetching() {
    let net = line(Some(5_000));
    let r = &net.members[2];
    assert_eq!(r.lost, [1].into());
    assert!((5_000..8_000).contains(&r.applied.unwrap()));
}
