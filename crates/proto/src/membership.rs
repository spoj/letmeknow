//! A `membership` stream: one request and its answer, or a subscription.

use serde::{Deserialize, Serialize};

use crate::{Bytes, head::Head};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Entries appended one after another, counted as one append.
    Append { log: Bytes, entries: Vec<Bytes> },
    Read { log: Bytes, after: u64 },
    Head { log: Bytes },
    Subscribe { logs: Vec<Bytes> },
}

/// The answer to `append`: the first entry's position, and the head after the last.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Appended {
    pub position: u64,
    pub head: Head,
}

/// The answer to `read`: entries after the position asked for; `head` covers the last of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub entries: Vec<Bytes>,
    pub head: Head,
}

/// The answer to `head`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Latest {
    pub head: Head,
}

/// A frame on a subscription: a new entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    pub log: Bytes,
    pub position: u64,
    pub entry: Bytes,
    pub head: Head,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Answer;

    #[test]
    fn shapes() {
        let append = Request::Append { log: Bytes(vec![1]), entries: vec![Bytes(vec![2])] };
        assert_eq!(serde_json::to_string(&append).unwrap(), r#"{"append":{"log":"AQ","entries":["Ag"]}}"#);
        let refused: Answer<Appended> = serde_json::from_str(r#"{"refused":"rate"}"#).unwrap();
        assert_eq!(refused, Answer::Refused { refused: "rate".into() });
    }
}
