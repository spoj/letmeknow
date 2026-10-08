//! The delivery policy. Printing wakes the agent, so only what concerns this session prints at once; the rest waits,
//! then prints in order just before the next thing that wakes it, after its next command, or once `--hold` runs out.

use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;

/// How many items that arrived while catching up are printed; older ones are counted as `omitted`.
const CATCH_UP: usize = 20;

/// Whether a described member answers to `name`, in any case: its name, the first word of it, or its identity's name
/// when this identity knows it: a contact's name, or one of its own.
pub fn answers(member: &Value, name: &str) -> bool {
    let (name, own) = (name.to_lowercase(), member["name"].as_str().unwrap_or_default().to_lowercase());
    let first: String = own.chars().take_while(|c| c.is_alphanumeric()).collect();
    let identity = &member["identity"];
    own == name
        || first == name
        || identity["error"].is_null()
            && identity["how"] != "unknown"
            && identity["name"].as_str().is_some_and(|identity| identity.to_lowercase() == name)
}

/// Whether `text` mentions `member`: "@" and a name it answers to, as "@claude" does "Claude, Matthew's coding agent".
pub fn mentions(text: &str, member: &Value) -> bool {
    text.match_indices('@').any(|(at, _)| {
        let name: String = text[at + 1..].chars().take_while(|c| c.is_alphanumeric() || "-_".contains(*c)).collect();
        !text[..at].ends_with(char::is_alphanumeric) && !name.is_empty() && answers(member, &name)
    })
}

/// Membership changes; messages addressed to this session (by `to` or by mention), answering one of its messages, or
/// urgent; and doc edits that mention it.
pub fn wakes(item: &Value, mine: impl Fn(&str) -> bool) -> bool {
    match item["type"].as_str() {
        Some("message") => {
            item["direct"] == true || item["urgent"] == true || item["reply_to"].as_str().is_some_and(mine)
        }
        Some("edited") => item["direct"] == true,
        Some("attachment") | Some("introduced") => false,
        _ => true,
    }
}

#[derive(Default)]
pub struct Outbox {
    held: Vec<Value>,
    held_since: Option<Instant>,
    /// Groups catching up, and what arrived for them meanwhile.
    backlog: HashMap<String, Vec<Value>>,
    out: Vec<Value>,
}

impl Outbox {
    pub fn catch_up(&mut self, group: &str) {
        self.backlog.entry(group.to_owned()).or_default();
    }

    /// Prints what arrived while a group caught up: the last CATCH_UP items, after an `omitted` count.
    pub fn caught_up(&mut self) {
        for (group, items) in std::mem::take(&mut self.backlog) {
            let omitted = items.len().saturating_sub(CATCH_UP);
            if omitted > 0 {
                self.out.push(serde_json::json!({ "type": "omitted", "group": group, "count": omitted }));
            }
            self.out.extend(items.into_iter().skip(omitted));
        }
    }

    pub fn deliver(&mut self, item: Value, wakes: bool) {
        if let Some(backlog) = item["group"].as_str().and_then(|group| self.backlog.get_mut(group)) {
            backlog.push(item);
        } else if wakes {
            self.flush_held();
            self.out.push(item);
        } else {
            self.held_since.get_or_insert_with(Instant::now);
            self.held.push(item);
        }
    }

    /// Prints at once, ahead of anything held: answers to the agent's own commands and warnings.
    pub fn print(&mut self, item: Value) {
        self.out.push(item);
    }

    pub fn flush_held(&mut self) {
        self.held_since = None;
        self.out.append(&mut self.held);
    }

    /// When held items print anyway.
    pub fn deadline(&self, hold: Duration) -> Option<Instant> {
        self.held_since.map(|since| since + hold)
    }

    /// Takes the held `edited` event of a doc, so a newer one can tell of both.
    pub fn take_edited(&mut self, group: &str) -> Option<Value> {
        let at = self.held.iter().position(|item| item["type"] == "edited" && item["group"] == group)?;
        Some(self.held.remove(at))
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    pub fn take(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_member_answers_to_its_name_the_first_word_of_it_and_its_identitys_name() {
        let member = json!({ "name": "Claude, Matthew's coding agent", "identity": { "id": "e", "name": "Matthew", "how": "verified" } });
        assert!(["claude, matthew's coding agent", "Claude", "MATTHEW"].iter().all(|name| answers(&member, name)));
        assert!(!answers(&member, "Matt"));
        let unverified = json!({ "name": "Claude", "identity": { "id": "e", "name": "Matthew", "how": "unknown", "claim": true, "error": "not on its list" } });
        assert!(!answers(&unverified, "Matthew"));
        let stranger = json!({ "name": "Claude", "identity": { "id": "e", "name": "Matthew", "how": "unknown", "claim": true } });
        assert!(!answers(&stranger, "Matthew"));
        assert!(mentions("@Claude please check", &member));
        assert!(mentions("ok, @claude.", &member));
        assert!(!mentions("@Claudette, look", &member));
        assert!(!mentions("Claude, look", &member));
        assert!(!mentions("mail claude@example.com", &member));
        assert!(!mentions("@ (", &json!({ "name": "(bot)" })));
    }

    #[test]
    fn only_what_concerns_this_session_wakes_it() {
        let mine = |id: &str| id == "m1";
        let message = |extra: Value| {
            let mut item = json!({ "type": "message", "group": "g", "direct": false });
            item.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            item
        };
        assert!(!wakes(&message(json!({})), mine));
        assert!(wakes(&message(json!({ "direct": true })), mine));
        assert!(wakes(&message(json!({ "urgent": true })), mine));
        assert!(wakes(&message(json!({ "reply_to": "m1" })), mine));
        assert!(!wakes(&message(json!({ "reply_to": "m2" })), mine));
        assert!(!wakes(&json!({ "type": "edited", "direct": false }), mine));
        assert!(wakes(&json!({ "type": "edited", "direct": true }), mine));
        assert!(wakes(&json!({ "type": "joined" }), mine));
        assert!(wakes(&json!({ "type": "removed" }), mine));
        assert!(!wakes(&json!({ "type": "attachment" }), mine));
    }

    #[test]
    fn held_items_print_in_order_before_the_next_that_wakes() {
        let mut outbox = Outbox::default();
        outbox.deliver(json!({ "n": 1 }), false);
        outbox.deliver(json!({ "n": 2 }), false);
        assert!(outbox.is_empty());
        assert!(outbox.deadline(Duration::from_secs(60)).is_some());
        outbox.deliver(json!({ "n": 3 }), true);
        let printed: Vec<Value> = outbox.take().iter().map(|item| item["n"].clone()).collect();
        assert_eq!(printed, [1, 2, 3]);
        assert_eq!(outbox.deadline(Duration::from_secs(60)), None);
        outbox.deliver(json!({ "n": 4 }), false);
        outbox.flush_held();
        assert_eq!(outbox.take().len(), 1);
    }

    #[test]
    fn a_group_catching_up_prints_only_its_latest_items() {
        let mut outbox = Outbox::default();
        outbox.catch_up("g");
        for n in 0..25 {
            outbox.deliver(json!({ "group": "g", "n": n }), n % 2 == 0);
        }
        outbox.deliver(json!({ "group": "h", "n": 99 }), true);
        assert_eq!(outbox.take().len(), 1);
        outbox.caught_up();
        let printed = outbox.take();
        assert_eq!(printed[0], json!({ "type": "omitted", "group": "g", "count": 5 }));
        assert_eq!(printed[1]["n"], 5);
        assert_eq!(printed.len(), 21);
    }

    #[test]
    fn a_held_edit_is_taken_back_to_be_merged() {
        let mut outbox = Outbox::default();
        outbox.deliver(json!({ "type": "edited", "group": "g", "by": [] }), false);
        assert!(outbox.take_edited("h").is_none());
        assert!(outbox.take_edited("g").is_some());
        assert!(outbox.take_edited("g").is_none());
    }
}
