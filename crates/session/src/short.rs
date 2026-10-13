//! What the agent reads, made short: it pays for every character.

use lmk_client::shown;
use serde_json::Value;

/// How many characters of a message id show; commands take any unique beginning of one.
pub const ID: usize = 12;

/// Makes `value` short: a member shows as its name ([`shown`]); a message id by its first `ID` characters; and neither a
/// group's membership service, where it is letmeknow.dev, nor a field that is false, null or empty shows at all.
pub fn compact(value: &mut Value) {
    match value {
        Value::Object(map) if map.contains_key("fp") && map.contains_key("name") => *value = Value::String(shown(value)),
        Value::Object(map) => {
            if map.get("membership").is_some_and(|service| *service == serde_json::json!(lmk_client::letmeknow_dev())) {
                map.remove("membership");
            }
            for (key, v) in map.iter_mut() {
                match (key.as_str(), v) {
                    ("id" | "reply_to" | "message" | "answered", Value::String(id)) => short(id),
                    ("ids" | "not_kept", Value::Array(ids)) => ids.iter_mut().for_each(|id| if let Value::String(id) = id { short(id) }),
                    (_, v) => compact(v),
                }
            }
            map.retain(|_, v| match v {
                Value::Null | Value::Bool(false) => false,
                Value::String(s) => !s.is_empty(),
                Value::Array(items) => !items.is_empty(),
                Value::Object(fields) => !fields.is_empty(),
                _ => true,
            });
        }
        Value::Array(items) => items.iter_mut().for_each(compact),
        _ => {}
    }
}

fn short(id: &mut String) {
    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        id.truncate(ID);
    }
}

/// `value` as one line of JSON, with `type` and `group` first, and `content` and `text`, which may be long, last.
pub fn line(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut fields: Vec<_> = map.iter().collect();
            fields.sort_by_key(|(key, _)| match key.as_str() {
                "type" => 0,
                "group" => 1,
                "content" | "text" => 3,
                _ => 2,
            });
            let fields: Vec<String> = fields.into_iter().map(|(key, value)| format!("{}:{}", Value::from(key.as_str()), line(value))).collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => format!("[{}]", items.iter().map(line).collect::<Vec<_>>().join(",")),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn members_show_by_name_and_ids_by_their_beginning() {
        let ann = |shows: &str, you: bool| json!({ "fp": shows, "name": format!("Ann · {shows}"), "you": you, "identity": { "id": "i", "name": "Ann", "how": "self" } });
        let mut item = json!({
            "type": "message",
            "group": "Plans",
            "id": "a".repeat(64),
            "seq": 7,
            "from": ann("desk (dog)", false),
            "to": [ann("laptop", true), ann("desk (cat)", false)],
            "direct": false,
            "content": "hi \"there\"",
            "ids": ["b".repeat(64)],
            "settings": { "name": "", "carry": false, "membership": lmk_client::letmeknow_dev() },
            "members": [
                { "fp": "f2", "name": "Bob · phone", "identity": { "id": "j", "name": "Bob", "how": "unknown" } },
                { "fp": "f3", "name": "f3", "identity": { "id": "i", "name": "Ann", "how": "self", "error": "not on its list" } }
            ]
        });
        compact(&mut item);
        assert_eq!(
            line(&item),
            format!(
                r#"{{"type":"message","group":"Plans","from":"desk (dog)","id":"{}","ids":["{}"],"members":["Bob · phone","f3"],"seq":7,"to":["you","desk (cat)"],"content":"hi \"there\""}}"#,
                "a".repeat(ID),
                "b".repeat(ID)
            )
        );
    }
}
