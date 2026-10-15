use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signature, VerifyingKey};
use lmk_membership::{
    service::{Policy, Route, Service},
    store::Store,
};
use lmk_proto::{
    Bytes, clock, head,
    membership::{Answer, Append, Appended, Heads, Known, Moved, Page, Read, Refusal, expiry_message, refusal_message},
};
use serde::de::DeserializeOwned;

const T0: u64 = 1_800_000_000_000;
/// Far enough ahead that every log is older than the retention.
const FAR: u64 = 10_000_000_000_000;

fn fixed() -> u64 { T0 }

struct Http {
    _dir: tempfile::TempDir,
    service: Service,
    key: VerifyingKey,
}

impl Http {
    fn new(policy: Policy) -> Self {
        clock::set(fixed);
        let dir = tempfile::tempdir().unwrap();
        let store = Store::initialize(&dir.path().join("state")).unwrap();
        let key = store.key().verifying_key();
        Self { _dir: dir, service: Service::new(store, policy), key }
    }

    async fn post<T: DeserializeOwned>(&self, route: Route, from: &str, body: &[u8]) -> Answer<T> {
        let admission = self.service.admit(from.parse().unwrap(), route, body.len()).unwrap();
        let answer = self.service.post(route, &admission, body).await.unwrap();
        serde_json::from_slice(&answer).unwrap()
    }

    async fn append(&self, from: &str, capability: u8, entries: &[Vec<u8>], public: bool) -> Option<Refusal> {
        let body = append_body(capability, entries, public);
        match self.post::<Appended>(Route::Append, from, &body).await {
            Answer::Ok(_) => None,
            Answer::Refused { refusal, .. } => Some(refusal),
            Answer::Expired { .. } => panic!("an append to a live log expired"),
        }
    }

    fn signed(&self, refusal: Refusal, request: &[u8], sig: &Bytes) -> bool {
        Signature::from_slice(&sig.0).is_ok_and(|sig| self.key.verify_strict(&refusal_message(refusal, request), &sig).is_ok())
    }

    fn expiry_signed(&self, log_ref: &[u8; 32], sig: &Bytes) -> bool {
        Signature::from_slice(&sig.0).is_ok_and(|sig| self.key.verify_strict(&expiry_message(log_ref), &sig).is_ok())
    }

    async fn expire_all(&self) {
        clock::set(|| FAR);
        while self.service.expire().await {}
    }
}

fn append_body(capability: u8, entries: &[Vec<u8>], public: bool) -> Vec<u8> {
    let entries = entries.iter().map(|e| Bytes(e.clone())).collect();
    serde_json::to_vec(&Append { capability: [capability; 32], entries, public }).unwrap()
}

fn one(entry: &[u8]) -> Vec<Vec<u8>> { vec![entry.to_vec()] }

#[tokio::test]
async fn routes_answer_appends_reads_and_heads_with_signed_heads() {
    let http = Http::new(Policy::default());
    assert!(Route::parse("/membership/2/append").is_none());
    assert!(matches!(Route::parse("/membership/1/heads"), Some(Route::Heads)));
    let Answer::Ok(appended) = http.post::<Appended>(Route::Append, "192.0.2.1", &append_body(7, &one(b"one"), false)).await else {
        panic!("append refused")
    };
    assert_eq!(appended.position, 1);
    assert!(appended.head.verify(&http.key));
    let read = serde_json::to_vec(&Read { capability: [7; 32], after: 0 }).unwrap();
    let Answer::Ok(page) = http.post::<Page>(Route::Read, "192.0.2.1", &read).await else { panic!("read refused") };
    assert_eq!(page.entries, [Bytes(b"one".to_vec())]);
    assert!(page.head.verify(&http.key));
    let heads = |logs| serde_json::to_vec(&Heads { logs }).unwrap();
    let Answer::Ok(moved) = http.post::<Moved>(Route::Heads, "192.0.2.1", &heads(vec![Known([7; 32], 0), Known([8; 32], 0)])).await else {
        panic!("heads refused")
    };
    assert_eq!(moved.heads.len(), 1);
    assert_eq!(moved.heads[0].length, 1);
    assert!(moved.heads[0].verify(&http.key));
    let Answer::Ok(moved) = http.post::<Moved>(Route::Heads, "192.0.2.1", &heads(vec![Known([7; 32], 1)])).await else {
        panic!("heads refused")
    };
    assert!(moved.heads.is_empty());
}

#[tokio::test]
async fn expired_logs_answer_signed_expiries_on_every_route() {
    let http = Http::new(Policy::default());
    let reference = head::reference(http.key.as_bytes(), &[7; 32]);
    let Answer::Ok(_) = http.post::<Appended>(Route::Append, "192.0.2.1", &append_body(7, &one(b"one"), false)).await else {
        panic!("append refused")
    };
    http.expire_all().await;
    let read = serde_json::to_vec(&Read { capability: [7; 32], after: 0 }).unwrap();
    let Answer::<Page>::Expired { sig } = http.post(Route::Read, "192.0.2.1", &read).await else { panic!("read answered") };
    assert!(http.expiry_signed(&reference, &sig));
    let Answer::<Appended>::Expired { sig } = http.post(Route::Append, "192.0.2.1", &append_body(7, &one(b"two"), false)).await else {
        panic!("append answered")
    };
    assert!(http.expiry_signed(&reference, &sig));
    let heads = serde_json::to_vec(&Heads { logs: vec![Known([7; 32], 0), Known([8; 32], 0)] }).unwrap();
    let Answer::<Moved>::Ok(moved) = http.post(Route::Heads, "192.0.2.1", &heads).await else { panic!("heads refused") };
    assert!(moved.heads.is_empty());
    assert_eq!(moved.expired.len(), 1);
    assert_eq!(moved.expired[0].log_ref, reference);
    assert!(http.expiry_signed(&reference, &moved.expired[0].sig));
}

#[tokio::test]
async fn refusals_are_signed_over_their_request_and_code() {
    let http = Http::new(Policy::default());
    let Answer::<()>::Refused { refusal, sig } = http.post(Route::Append, "192.0.2.1", b"{}").await else { panic!("accepted") };
    assert!(matches!(refusal, Refusal::Policy));
    assert!(http.signed(Refusal::Policy, b"{}", &sig));
    assert!(!http.signed(Refusal::Policy, b"{ }", &sig));
    assert!(!http.signed(Refusal::Busy, b"{}", &sig));
    let public = append_body(7, &[vec![1; (16 << 10) + 1]], true);
    let Answer::<()>::Refused { refusal, sig } = http.post(Route::Append, "192.0.2.1", &public).await else { panic!("accepted") };
    assert!(matches!(refusal, Refusal::Size));
    assert!(http.signed(Refusal::Size, &public, &sig));
    let heads = serde_json::to_vec(&Heads { logs: vec![Known([1; 32], 0); 257] }).unwrap();
    let Answer::<()>::Refused { refusal, .. } = http.post(Route::Heads, "192.0.2.1", &heads).await else { panic!("accepted") };
    assert!(matches!(refusal, Refusal::Policy));
}

#[tokio::test]
async fn appends_per_minute_count_an_ipv4_address_and_its_mapped_form_alike() {
    let http = Http::new(Policy { appends_per_minute: 2, ..Policy::default() });
    assert!(http.append("192.0.2.1", 1, &one(b"x"), false).await.is_none());
    assert!(http.append("192.0.2.1", 1, &one(b"x"), false).await.is_none());
    assert!(matches!(http.append("192.0.2.1", 1, &one(b"x"), false).await, Some(Refusal::Rate)));
    assert!(matches!(http.append("::ffff:192.0.2.1", 1, &one(b"x"), false).await, Some(Refusal::Rate)));
    assert!(http.append("192.0.2.2", 1, &one(b"x"), false).await.is_none());
}

#[tokio::test]
async fn ipv6_budgets_are_per_slash_64_and_a_slash_48_holds_16_of_them() {
    let http = Http::new(Policy { appends_per_minute: 1, ..Policy::default() });
    assert!(http.append("2001:db8:1:1::1", 1, &one(b"x"), false).await.is_none());
    assert!(matches!(http.append("2001:db8:1:1::2", 1, &one(b"x"), false).await, Some(Refusal::Rate)));
    for i in 2..=16 {
        assert!(http.append(&format!("2001:db8:1:{i:x}::1"), 1, &one(b"x"), false).await.is_none(), "/64 {i:x}");
    }
    assert!(matches!(http.append("2001:db8:1:11::1", 1, &one(b"x"), false).await, Some(Refusal::Rate)));
    assert!(http.append("2001:db8:2:1::1", 1, &one(b"x"), false).await.is_none());
}

#[tokio::test]
async fn new_logs_are_budgeted_per_address() {
    let http = Http::new(Policy { new_logs_per_day: 2, ..Policy::default() });
    assert!(http.append("192.0.2.1", 1, &one(b"x"), false).await.is_none());
    assert!(http.append("192.0.2.1", 2, &one(b"x"), false).await.is_none());
    assert!(matches!(http.append("192.0.2.1", 3, &one(b"x"), false).await, Some(Refusal::Rate)));
    assert!(http.append("192.0.2.1", 1, &one(b"y"), false).await.is_none(), "an existing log is not new");
    assert!(http.append("192.0.2.2", 3, &one(b"x"), false).await.is_none());
    assert!(http.append("192.0.2.2", 4, &one(b"x"), false).await.is_none());
}

#[tokio::test]
async fn public_logs_take_small_entries_and_few_new_and_stored_appends() {
    let http = Http::new(Policy { new_public_logs_per_day: 1, public_appends_per_day: 2, ..Policy::default() });
    assert!(http.append("192.0.2.1", 1, &one(&[1; 16 << 10]), true).await.is_none());
    assert!(matches!(http.append("192.0.2.1", 2, &one(b"x"), true).await, Some(Refusal::Rate)));
    assert!(http.append("192.0.2.1", 2, &one(b"x"), false).await.is_none(), "a private log is not public");
    assert!(http.append("192.0.2.1", 1, &one(b"x"), true).await.is_none());
    assert!(http.append("192.0.2.1", 1, &one(b"x"), true).await.is_none(), "a touch of the last entry stores nothing, and is not charged");
    assert!(matches!(http.append("192.0.2.1", 1, &one(b"z"), true).await, Some(Refusal::Rate)));
    assert!(http.append("192.0.2.2", 3, &one(b"x"), true).await.is_none());
}

#[tokio::test]
async fn a_public_log_counts_its_stored_appends_per_address() {
    let http = Http::new(Policy::default());
    for i in 0..10u8 {
        assert!(http.append("192.0.2.1", 1, &one(&[i]), true).await.is_none());
    }
    assert!(matches!(http.append("192.0.2.1", 1, &one(b"x"), true).await, Some(Refusal::Rate)));
    assert!(http.append("192.0.2.2", 1, &one(b"y"), true).await.is_none());
}

#[tokio::test]
async fn a_public_log_keeps_its_caps_whatever_flag_an_append_sends() {
    let http = Http::new(Policy { public_appends_per_day: 2, ..Policy::default() });
    assert!(http.append("192.0.2.1", 1, &one(b"x"), true).await.is_none());
    assert!(matches!(http.append("192.0.2.1", 1, &one(&[1; (16 << 10) + 1]), false).await, Some(Refusal::Policy)));
    assert!(matches!(http.append("192.0.2.1", 1, &one(b"x"), false).await, Some(Refusal::Policy)));
    assert!(matches!(http.append("192.0.2.1", 1, &[b"y".to_vec(), b"z".to_vec()], true).await, Some(Refusal::Rate)));
    assert!(http.append("192.0.2.1", 1, &one(b"y"), true).await.is_none());
    assert!(matches!(http.append("192.0.2.1", 1, &one(b"z"), true).await, Some(Refusal::Rate)));
}

#[tokio::test]
async fn reads_and_heads_share_a_request_budget_and_a_byte_budget() {
    let http = Http::new(Policy { reads_per_minute: 2, ..Policy::default() });
    let read = serde_json::to_vec(&Read { capability: [1; 32], after: 0 }).unwrap();
    for _ in 0..2 {
        assert!(matches!(http.post::<Page>(Route::Read, "192.0.2.1", &read).await, Answer::Ok(_)));
    }
    assert!(matches!(http.post::<Page>(Route::Read, "192.0.2.1", &read).await, Answer::Refused { refusal: Refusal::Rate, .. }));
    let heads = serde_json::to_vec(&Heads { logs: vec![] }).unwrap();
    assert!(matches!(http.post::<Moved>(Route::Heads, "192.0.2.1", &heads).await, Answer::Refused { refusal: Refusal::Rate, .. }));

    let http = Http::new(Policy { read_bytes_per_minute: 1, ..Policy::default() });
    assert!(http.append("192.0.2.1", 1, &one(b"x"), false).await.is_none());
    let read = serde_json::to_vec(&Read { capability: [1; 32], after: 0 }).unwrap();
    assert!(matches!(http.post::<Page>(Route::Read, "192.0.2.1", &read).await, Answer::Ok(_)));
    assert!(matches!(http.post::<Page>(Route::Read, "192.0.2.1", &read).await, Answer::Refused { refusal: Refusal::Rate, .. }));
}

static NOW: AtomicU64 = AtomicU64::new(T0);

fn stepped() -> u64 { NOW.load(Ordering::SeqCst) }

#[tokio::test]
async fn budgets_renew_with_their_window() {
    let http = Http::new(Policy { appends_per_minute: 1, ..Policy::default() });
    clock::set(stepped);
    assert!(http.append("192.0.2.1", 1, &one(b"x"), false).await.is_none());
    assert!(matches!(http.append("192.0.2.1", 1, &one(b"x"), false).await, Some(Refusal::Rate)));
    NOW.fetch_add(60_000, Ordering::SeqCst);
    assert!(http.append("192.0.2.1", 1, &one(b"x"), false).await.is_none());
}
