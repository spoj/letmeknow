use std::{net::IpAddr, sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}}, time::Duration};

use ed25519_dalek::{Signer, SigningKey};
use lmk_membership::{
    Expired, Frontier, InvalidProof, Refused, Unsupported, WrongDirectory,
    client::{Post, ServeClient, answered},
    service::{Policy, Route, Service},
    store::Store,
};
use lmk_proto::{
    Bytes,
    group::Service as Wire,
    head,
    membership::{self, Answer, Expiry, Moved, Page, Refusal, expiry_message, refusal_message},
};
use lmk_proto::clock;
use n0_future::boxed::BoxFuture;

struct Membership {
    _dir: tempfile::TempDir,
    service: Service,
    key: SigningKey,
}

impl Membership {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::initialize(&dir.path().join("state")).unwrap();
        let key = SigningKey::from_bytes(&store.key().to_bytes());
        Self { _dir: dir, service: Service::new(store, Policy::default()), key }
    }

    fn wire(&self, domain: &str) -> Wire {
        Wire::Serve { key: Bytes(self.key.verifying_key().to_bytes().to_vec()), domain: domain.into(), rest: Default::default() }
    }

    /// A post that the service answers in process, route by route, as its HTTPS listener would.
    fn post(&self) -> Post {
        let service = self.service.clone();
        Arc::new(move |_: String, route: &'static str, body: Vec<u8>| -> BoxFuture<anyhow::Result<Vec<u8>>> {
            let service = service.clone();
            Box::pin(async move {
                let route = Route::parse(route).unwrap();
                let admission = service.admit(IpAddr::from([127, 0, 0, 1]), route, body.len()).unwrap();
                service.post(route, &admission, &body).await
            })
        })
    }

    fn client(&self) -> ServeClient {
        ServeClient::for_service(self.post(), &self.wire("membership.example"), false).unwrap()
    }
}

/// Far enough ahead that every log is older than the retention.
const FAR: u64 = 10_000_000_000_000;

fn log(seed: u8) -> [u8; 32] { [seed; 32] }

fn anchor(key: &SigningKey, capability: &[u8; 32]) -> Frontier {
    let service = key.verifying_key().to_bytes();
    Frontier::empty(service, head::reference(&service, capability))
}

#[tokio::test]
async fn appends_reads_and_heads_check_against_the_service_key() {
    let membership = Membership::new();
    let client = membership.client();
    let capability = log(1);
    let appended = client.append(&capability, &[b"one".to_vec(), b"two".to_vec()]).await.unwrap();
    let page = client.read(&capability, &anchor(&membership.key, &capability)).await.unwrap();
    assert_eq!(page.entries, [Bytes(b"one".to_vec()), Bytes(b"two".to_vec())]);
    let moved = client.heads(&[capability, log(2)]).await.unwrap();
    let (head, empty) = (moved[0].as_ref().unwrap(), moved[1].as_ref().unwrap());
    assert_eq!((moved.len(), head.length, head.hash, empty.length), (2, 2, appended.head.hash, 0));
}

#[tokio::test]
async fn only_a_client_that_sets_the_clock_records_head_times() {
    let membership = Membership::new();
    let lag = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 - 3_600_000;
    clock::set(lag);
    let capability = log(1);
    let foreign = ServeClient::for_service(membership.post(), &membership.wire("foreign.example"), false).unwrap();
    foreign.append(&capability, &[b"one".to_vec()]).await.unwrap();
    foreign.read(&capability, &anchor(&membership.key, &capability)).await.unwrap();
    foreign.heads(&[capability]).await.unwrap();
    assert_eq!(clock::corrected(), clock::now());

    let own = ServeClient::for_service(membership.post(), &membership.wire("own.example"), true).unwrap();
    own.heads(&[capability]).await.unwrap();
    assert!(clock::corrected().abs_diff(clock::now() + 3_600_000) < 5_000);
}

#[tokio::test]
async fn heads_ask_256_logs_to_a_request_and_answer_each() {
    let membership = Membership::new();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let post = membership.post();
    let counting: Post = {
        let requests = requests.clone();
        Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
            requests.lock().unwrap().push(body.clone());
            post(domain, route, body)
        })
    };
    let client = ServeClient::for_service(counting, &membership.wire("membership.example"), false).unwrap();
    let client_for_appends = membership.client();
    client_for_appends.append(&log(7), &[b"x".to_vec()]).await.unwrap();
    let distinct = |i: u16| { let mut capability = [0; 32]; capability[..2].copy_from_slice(&i.to_be_bytes()); capability };
    let capabilities: Vec<[u8; 32]> = (0..600).map(distinct).chain([log(7)]).collect();
    let moved = client.heads(&capabilities).await.unwrap();
    let lengths: Vec<u64> = moved.iter().map(|answer| answer.as_ref().unwrap().length).collect();
    assert_eq!(lengths, [vec![0; 600], vec![1]].concat());
    assert_eq!(moved[600].as_ref().unwrap().log_ref, head::reference(&membership.key.verifying_key().to_bytes(), &log(7)));
    assert_eq!(requests.lock().unwrap().len(), 3, "601 logs ask for 256 at a time");
}

#[tokio::test]
async fn a_reply_another_key_signed_is_the_directorys_name() {
    let served = Membership::new();
    let other = Membership::new();
    let wrong = ServeClient::for_service(served.post(), &other.wire("membership.example"), false).unwrap();
    let error = wrong.heads(&[log(1)]).await.unwrap_err();
    assert!(error.is::<WrongDirectory>(), "{error}");
    let error = wrong.append(&log(1), &[b"x".to_vec()]).await.unwrap_err();
    assert!(error.is::<WrongDirectory>(), "{error}");
    let error = wrong.read(&log(1), &anchor(&other.key, &log(1))).await.unwrap_err();
    assert!(error.is::<WrongDirectory>(), "{error}");
}

#[tokio::test]
async fn a_refusal_acts_only_when_the_service_signed_it() {
    let membership = Membership::new();
    let request = serde_json::to_vec(&membership::Append { capability: log(1), entries: vec![Bytes(b"x".to_vec())] }).unwrap();
    let refused = |sig: [u8; 64]| serde_json::to_vec(&Answer::<()>::Refused { refusal: Refusal::Rate, sig: Bytes(sig.to_vec()) }).unwrap();
    let signed = membership.key.sign(&refusal_message(Refusal::Rate, &request)).to_bytes();
    let client = |reply: Vec<u8>| ServeClient::for_service(answering(reply), &membership.wire("membership.example"), false).unwrap();
    let error = client(refused(signed)).append(&log(1), &[b"x".to_vec()]).await.unwrap_err();
    assert!(error.downcast_ref::<Refused>().is_some_and(|refused| refused.0 == "rate"), "{error}");
    let error = client(refused([9; 64])).append(&log(1), &[b"x".to_vec()]).await.unwrap_err();
    assert!(error.is::<WrongDirectory>(), "a refusal another key signed is no refusal: {error}");
}

/// A post that answers every route with `reply`.
fn answering(reply: Vec<u8>) -> Post {
    Arc::new(move |_: String, _: &'static str, _: Vec<u8>| -> BoxFuture<anyhow::Result<Vec<u8>>> {
        let reply = reply.clone();
        Box::pin(async move { Ok(reply) })
    })
}

#[tokio::test]
async fn an_expiry_acts_only_when_the_service_signed_it() {
    let membership = Membership::new();
    let (capability, other) = (log(1), log(2));
    membership.client().append(&capability, &[b"one".to_vec()]).await.unwrap();
    clock::set(|| FAR);
    while membership.service.expire().await {}
    let key = membership.key.verifying_key().to_bytes();
    let (reference, other_reference) = (head::reference(&key, &capability), head::reference(&key, &other));
    let anchored = anchor(&membership.key, &capability);
    let expired = membership.client();
    let error = expired.read(&capability, &anchored).await.unwrap_err();
    assert_eq!(error.downcast_ref::<Expired>().map(|e| e.0), Some(reference));
    assert_eq!(expired.append(&capability, &[b"two".to_vec()]).await.unwrap_err().downcast_ref::<Expired>().map(|e| e.0), Some(reference));
    let heads = expired.heads(&[capability]).await.unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].as_ref().unwrap_err().log_ref, reference);

    let signed = |message: Vec<u8>| Bytes(membership.key.sign(&message).to_bytes().to_vec());
    let unsigned = Bytes(vec![9; 64]);
    let read = |sig: Bytes| serde_json::to_vec(&Answer::<Page>::Expired { sig }).unwrap();
    let client = |reply: Vec<u8>| ServeClient::for_service(answering(reply), &membership.wire("membership.example"), false).unwrap();
    let error = client(read(unsigned.clone())).read(&capability, &anchored).await.unwrap_err();
    assert!(error.is::<WrongDirectory>(), "{error}");
    let error = client(read(signed(expiry_message(&other_reference)))).read(&capability, &anchored).await.unwrap_err();
    assert!(error.is::<WrongDirectory>(), "an expiry of another log is no expiry of this one: {error}");
    let heads = |expired: Vec<Expiry>| serde_json::to_vec(&Answer::Ok(Moved { heads: vec![], expired })).unwrap();
    let listed = |log_ref, sig| Expiry { log_ref, sig };
    for (expired, what) in [
        (vec![], "a reply with nothing of the log asked"),
        (vec![listed(reference, unsigned)], "an unsigned expiry"),
        (vec![listed(other_reference, signed(expiry_message(&other_reference)))], "an expiry of a log the request did not name"),
    ] {
        let error = client(heads(expired)).heads(&[capability]).await.unwrap_err();
        assert!(error.is::<WrongDirectory>(), "{what} is no answer: {error}");
    }
    let signed_heads = client(heads(vec![listed(reference, signed(expiry_message(&reference)))])).heads(&[capability]).await.unwrap();
    assert_eq!(signed_heads.len(), 1);
    assert_eq!(signed_heads[0].as_ref().unwrap_err().log_ref, reference);
}

#[tokio::test]
async fn a_404_stops_the_client_and_echoes_no_text() {
    let membership = Membership::new();
    let asked = Arc::new(Mutex::new(0));
    let post: Post = {
        let asked = asked.clone();
        Arc::new(move |domain: String, _: &'static str, _: Vec<u8>| -> BoxFuture<anyhow::Result<Vec<u8>>> {
            *asked.lock().unwrap() += 1;
            let reply = answered(&domain, 404, b"<script>sent by the service</script>".to_vec());
            Box::pin(async move { reply })
        })
    };
    let client = ServeClient::for_service(post, &membership.wire("membership.example"), false).unwrap();
    for _ in 0..2 {
        let error = client.heads(&[log(1)]).await.unwrap_err();
        assert!(error.is::<Unsupported>() && error.to_string() == "the membership service at membership.example runs another minor", "{error}");
    }
    assert_eq!(*asked.lock().unwrap(), 1, "the client asks no more once it stopped");
}

#[test]
fn replies_are_bounded_and_only_200_is_an_answer() {
    assert!(answered("d", 200, vec![0; membership::MAX_BODY]).is_ok());
    assert!(answered("d", 200, vec![0; membership::MAX_BODY + 1]).is_err());
    assert!(answered("d", 503, Vec::new()).unwrap_err().to_string().contains("answered 503"));
}

#[tokio::test]
async fn a_page_that_does_not_chain_to_the_anchor_is_refused() {
    let membership = Membership::new();
    let capability = log(3);
    membership.client().append(&capability, &[b"one".to_vec()]).await.unwrap();
    let post = membership.post();
    let tampered: Post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
        let post = post.clone();
        Box::pin(async move {
            let reply = post(domain, route, body).await?;
            let Answer::Ok(mut page) = serde_json::from_slice::<Answer<membership::Page>>(&reply)? else { return Ok(reply) };
            page.entries[0] = Bytes(b"forged".to_vec());
            Ok(serde_json::to_vec(&Answer::Ok(page))?)
        }) as BoxFuture<anyhow::Result<Vec<u8>>>
    });
    let client = ServeClient::for_service(tampered, &membership.wire("membership.example"), false).unwrap();
    let error = client.read(&capability, &anchor(&membership.key, &capability)).await.unwrap_err();
    assert!(error.is::<InvalidProof>(), "{error}");
}

#[tokio::test]
async fn concurrent_reads_fit_a_default_services_bytes_in_flight() {
    let membership = Membership::new();
    let service = membership.service.clone();
    let post: Post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| -> BoxFuture<anyhow::Result<Vec<u8>>> {
        let service = service.clone();
        Box::pin(async move {
            let route = Route::parse(route).unwrap();
            let Some(admission) = service.admit(IpAddr::from([127, 0, 0, 1]), route, body.len()) else {
                return answered(&domain, 503, Vec::new());
            };
            tokio::time::sleep(Duration::from_millis(20)).await;
            answered(&domain, 200, service.post(route, &admission, &body).await?)
        })
    });
    let client = ServeClient::for_service(post, &membership.wire("membership.example"), false).unwrap();
    let key = membership.key.clone();
    let tasks: Vec<_> = (0..10).map(|i| {
        let (client, key) = (client.clone(), key.clone());
        tokio::spawn(async move { client.read(&log(i), &anchor(&key, &log(i))).await })
    }).collect();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn at_most_three_requests_are_in_flight_to_a_service() {
    let membership = Membership::new();
    let post = membership.post();
    let (now, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let slow: Post = {
        let (now, peak) = (now.clone(), peak.clone());
        Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| -> BoxFuture<anyhow::Result<Vec<u8>>> {
            let (now, peak, post) = (now.clone(), peak.clone(), post.clone());
            Box::pin(async move {
                peak.fetch_max(now.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                now.fetch_sub(1, Ordering::SeqCst);
                post(domain, route, body).await
            })
        })
    };
    let client = ServeClient::for_service(slow, &membership.wire("membership.example"), false).unwrap();
    let tasks: Vec<_> = (0..10).map(|i| {
        let client = client.clone();
        tokio::spawn(async move { client.heads(&[log(i)]).await })
    }).collect();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(peak.load(Ordering::SeqCst), 3);
}
