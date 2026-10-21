//! What wakes the agent, and so prints at once. Everything goes to the session's log, which the agent reads at its pace.

use serde_json::Value;

/// Another member's message addressed to this session, answering one of its messages, or urgent; `removed`; and another
/// member's `lost` of this session's messages, which it may send again.
pub fn wakes(item: &Value, mine: impl Fn(&str) -> bool) -> bool {
    match item["type"].as_str() {
        Some("message") if item["from"]["you"] != true => {
            let to_me = item["to"].as_array().is_some_and(|to| to.iter().any(|member| member["you"] == true));
            to_me || item["urgent"] == true || item["reply_to"].as_str().is_some_and(mine)
        }
        Some("lost") => item["member"]["you"] != true,
        Some("removed" | "warning") => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_what_concerns_this_session_wakes_it() {
        let mine = |id: &str| id == "m1";
        let message = |extra: Value| {
            let mut item = json!({ "type": "message", "group": "g", "from": { "fp": "c" }, "to": [{ "fp": "a" }] });
            item.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            item
        };
        assert!(!wakes(&message(json!({})), mine));
        assert!(wakes(&message(json!({ "to": [{ "fp": "a" }, { "fp": "b", "you": true }] })), mine));
        assert!(wakes(&message(json!({ "urgent": true })), mine));
        assert!(!wakes(&message(json!({ "urgent": true, "from": { "fp": "b", "you": true } })), mine), "its own");
        assert!(wakes(&message(json!({ "reply_to": "m1" })), mine));
        assert!(!wakes(&message(json!({ "reply_to": "m2" })), mine));
        assert!(!wakes(&json!({ "type": "joined", "by": { "fp": "b", "you": true } }), mine));
        assert!(!wakes(&json!({ "type": "left" }), mine));
        assert!(wakes(&json!({ "type": "removed" }), mine));
        assert!(wakes(&json!({ "type": "warning" }), mine));
        assert!(wakes(&json!({ "type": "lost", "member": { "fp": "a" }, "ids": ["x"] }), mine));
        assert!(!wakes(&json!({ "type": "lost", "member": { "fp": "b", "you": true } }), mine));
    }
}
