//! What the agent reads, made short: it pays for every character.

use crate::shown;
use serde_json::Value;

/// How many characters of a message id show; commands take any unique beginning of one.
pub const ID: usize = 12;

/// Makes `value` short: a member shows as "you" or its fingerprint ([`shown`]); a message id by its first `ID`
/// characters; and neither a group's membership service, where it is letmeknow.dev, nor a field that is false, null or
/// empty shows at all.
pub fn compact(value: &mut Value) {
    match value {
        Value::Object(map) if map.contains_key("fp") => *value = Value::String(shown(value)),
        Value::Object(map) => {
            if map.get("membership").is_some_and(|service| *service == serde_json::json!(crate::letmeknow_dev())) {
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

/// A time in milliseconds since the Unix epoch as UTC to the second, as "2026-10-21T08:39:12Z".
pub fn iso(ms: u64) -> String {
    let (days, secs) = ((ms / 1000 / 86_400) as i64, ms / 1000 % 86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs / 60 % 60, secs % 60)
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
    fn members_show_by_fingerprint_and_ids_by_their_beginning() {
        let member = |fp: &str, you: bool| json!({ "fp": fp, "you": you });
        let mut item = json!({
            "type": "message",
            "group": "g",
            "id": "a".repeat(64),
            "seq": 7,
            "from": member("f1", false),
            "to": [member("f2", true), member("f3", false)],
            "content": "hi \"there\"",
            "ids": ["b".repeat(64)],
            "carry": false,
            "membership": crate::letmeknow_dev(),
        });
        compact(&mut item);
        assert_eq!(
            line(&item),
            format!(
                r#"{{"type":"message","group":"g","from":"f1","id":"{}","ids":["{}"],"seq":7,"to":["you","f3"],"content":"hi \"there\""}}"#,
                "a".repeat(ID),
                "b".repeat(ID)
            )
        );
    }

    #[test]
    fn times_show_as_utc_to_the_second() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(iso(1_792_533_552_590), "2026-10-20T21:59:12Z");
    }
}
