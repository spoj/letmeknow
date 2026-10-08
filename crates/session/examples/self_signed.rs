//! Writes a self-signed certificate for localhost, and its key, as PEM to the two paths given: for test/e2e.py, which
//! runs a local `letmeknow serve` with them.

fn main() {
    let mut paths = std::env::args().skip(1);
    let (cert, key) = (paths.next().expect("a certificate path"), paths.next().expect("a key path"));
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(cert, certified.cert.pem()).unwrap();
    std::fs::write(key, certified.signing_key.serialize_pem()).unwrap();
}
