//! A group's files: Yjs documents holding one text, so the browser (Yjs) and the session process (yrs) edit the same
//! document. A file's state is a Yjs update holding everything; the version shown to agents is a hash of it.
use anyhow::Result;
use similar::{ChangeTag, DiffTag, TextDiff};
use yrs::updates::decoder::Decode;
use yrs::{Doc, GetString, Options, ReadTxn, StateVector, Text, Transact, Update};

/// The name of the text inside every file's document, which the browser binds to its editor.
const TEXT: &str = "text";

/// The state of a new file holding `text`.
pub fn new(text: &str) -> Vec<u8> {
    let doc = Doc::new();
    let body = doc.get_or_insert_text(TEXT);
    body.insert(&mut doc.transact_mut(), 0, text);
    doc.transact().encode_state_as_update_v1(&StateVector::default())
}

fn load(state: &[u8]) -> Result<Doc> {
    // A fresh client id for every load: edits made here must never reuse the clock of an earlier client.
    let doc = Doc::with_options(Options::default());
    doc.transact_mut().apply_update(Update::decode_v1(state)?)?;
    Ok(doc)
}

/// Applies an update to a file's state (none for a file not seen before). An update may arrive before the updates it
/// builds on; until those arrive it is kept as it came.
pub fn apply(state: Option<&[u8]>, update: &[u8]) -> Result<Vec<u8>> {
    let Some(state) = state else { return apply(Some(&new("")), update) };
    let doc = load(state)?;
    doc.transact_mut().apply_update(Update::decode_v1(update)?)?;
    let txn = doc.transact();
    if txn.store().pending_update().is_none() && txn.store().pending_ds().is_none() {
        return Ok(txn.encode_state_as_update_v1(&StateVector::default()));
    }
    Ok(yrs::merge_updates_v1([state, update])?)
}

pub fn text(state: &[u8]) -> Result<String> {
    let doc = load(state)?;
    let body = doc.get_or_insert_text(TEXT);
    Ok(body.get_string(&doc.transact()))
}

pub fn version(state: &[u8]) -> String {
    letmeknow::proto::digest(state)[..16].to_owned()
}

/// The update that makes the text of `state` read `new`, as edits on `state`.
pub fn edit(state: &[u8], new: &str) -> Result<Vec<u8>> {
    let doc = load(state)?;
    let body = doc.get_or_insert_text(TEXT);
    let old = body.get_string(&doc.transact());
    let before = doc.transact().state_vector();
    {
        let mut txn = doc.transact_mut();
        let mut at = 0;
        for change in TextDiff::from_chars(old.as_str(), new).iter_all_changes() {
            let value = change.value();
            let len = value.len() as u32;
            match change.tag() {
                ChangeTag::Equal => at += len,
                ChangeTag::Delete => body.remove_range(&mut txn, at, len),
                ChangeTag::Insert => {
                    body.insert(&mut txn, at, value);
                    at += len;
                }
            }
        }
    }
    Ok(doc.transact().encode_state_as_update_v1(&before))
}

/// Carries the changes an agent made to `base` (giving `new`) over to `current`, the text as it is now, line by line:
/// a line it changed or deleted is found by its text wherever it is now; a line it added goes after the line it
/// followed. Returns the text to write, and the changed lines whose original someone else changed or deleted meanwhile.
pub fn rebase(base: &str, new: &str, current: &str) -> (String, Vec<String>) {
    if base == current {
        return (new.to_owned(), Vec::new());
    }
    let (base_lines, new_lines): (Vec<&str>, Vec<&str>) = (base.lines().collect(), new.lines().collect());
    let mut out: Vec<&str> = current.lines().collect();
    let mut lost = Vec::new();
    // Where `line` is now: of several equal lines, the one nearest where it was.
    let find = |out: &[&str], line: &str, near: usize| out.iter().enumerate().filter(|(_, l)| **l == line).min_by_key(|(i, _)| i.abs_diff(near)).map(|(i, _)| i);
    for op in TextDiff::from_lines(base, new).ops() {
        let (tag, old, added) = op.as_tag_tuple();
        if tag == DiffTag::Equal {
            continue;
        }
        let pairs = pair(&base_lines[old.clone()], &new_lines[added.clone()]);
        // Added lines go after the line they followed, else before the first changed line of the block, else before the
        // line that followed the block, else where they were.
        let mut at = (old.start.checked_sub(1).and_then(|i| find(&out, base_lines[i], i)).map(|i| i + 1))
            .or_else(|| pairs.iter().flatten().find_map(|&j| find(&out, base_lines[old.start + j], old.start + j)))
            .or_else(|| base_lines.get(old.end).and_then(|next| find(&out, next, old.end)))
            .unwrap_or(old.start.min(out.len()));
        for (line, paired) in new_lines[added.clone()].iter().zip(&pairs) {
            match paired {
                Some(j) => match find(&out, base_lines[old.start + j], old.start + j) {
                    Some(found) => {
                        out[found] = line;
                        at = found + 1;
                    }
                    None => lost.push((*line).to_owned()),
                },
                None => {
                    out.insert(at, line);
                    at += 1;
                }
            }
        }
        for (j, original) in base_lines[old.clone()].iter().enumerate() {
            if !pairs.contains(&Some(j))
                && let Some(at) = find(&out, original, old.start + j)
            {
                out.remove(at);
            }
        }
    }
    let mut text = out.join("\n");
    let changed = base.ends_with('\n') != new.ends_with('\n');
    if if changed { new.ends_with('\n') } else { current.ends_with('\n') } {
        text.push('\n');
    }
    (text, lost)
}

/// Pairs each line of a changed block's new text with the old line it rewrites: the pairing, in order, of lines at least
/// half alike that is most alike in total. An unpaired new line was added; an unpaired old line was removed.
fn pair(old: &[&str], new: &[&str]) -> Vec<Option<usize>> {
    let alike = |i: usize, j: usize| Some(TextDiff::from_chars(new[i], old[j]).ratio()).filter(|r| *r >= 0.5);
    // best[i][j]: the most likeness pairing new[i..] with old[j..] can reach.
    let mut best = vec![vec![0.0f32; old.len() + 1]; new.len() + 1];
    for i in (0..new.len()).rev() {
        for j in (0..old.len()).rev() {
            let paired = alike(i, j).map_or(0.0, |r| r + best[i + 1][j + 1]);
            best[i][j] = paired.max(best[i + 1][j]).max(best[i][j + 1]);
        }
    }
    let mut pairs = vec![None; new.len()];
    let (mut i, mut j) = (0, 0);
    while i < new.len() && j < old.len() {
        if alike(i, j).is_some_and(|r| best[i][j] == r + best[i + 1][j + 1]) {
            pairs[i] = Some(j);
            (i, j) = (i + 1, j + 1);
        } else if best[i][j] == best[i + 1][j] {
            i += 1;
        } else {
            j += 1;
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n";

    #[test]
    fn a_change_follows_its_line_when_someone_moved_it() {
        let current = "- [ ] gamma\n- [ ] alpha\n- [ ] beta\n";
        let (text, lost) = rebase(BASE, "- [ ] alpha\n- [ ] beta\n- [x] gamma\n", current);
        assert_eq!((text.as_str(), lost.len()), ("- [x] gamma\n- [ ] alpha\n- [ ] beta\n", 0));
    }

    #[test]
    fn an_added_line_goes_after_the_line_it_followed() {
        let current = "- [ ] alpha\n- [x] beta\n- [ ] gamma\n- [ ] delta\n";
        let (text, _) = rebase(BASE, "- [ ] alpha\n- [ ] new\n- [ ] beta\n- [ ] gamma\n", current);
        assert_eq!(text, "- [ ] alpha\n- [ ] new\n- [x] beta\n- [ ] gamma\n- [ ] delta\n");
    }

    #[test]
    fn an_added_line_stays_in_place_when_the_line_it_followed_changed() {
        let current = "- [ ] alpha\n- [ ] beta\n- [ ] gamma (Tuesday)\n";
        let (text, _) = rebase(BASE, "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [ ] delta\n", current);
        assert_eq!(text, "- [ ] alpha\n- [ ] beta\n- [ ] gamma (Tuesday)\n- [ ] delta\n");
        let (text, _) = rebase(BASE, "- [ ] alpha\n- [ ] new\n- [ ] beta\n- [ ] gamma\n", "- [x] alpha\n- [ ] beta\n- [ ] gamma\n");
        assert_eq!(text, "- [x] alpha\n- [ ] new\n- [ ] beta\n- [ ] gamma\n");
    }

    #[test]
    fn a_changed_block_pairs_each_line_with_the_line_it_rewrites() {
        let current = "- [ ] alpha (call Ann)\n- [ ] beta\n- [ ] gamma\n";
        let (text, lost) = rebase(BASE, "- [ ] new\n- [x] alpha\n- [x] beta\n- [ ] gamma\n", current);
        assert_eq!((text.as_str(), lost), ("- [ ] alpha (call Ann)\n- [ ] new\n- [x] beta\n- [ ] gamma\n", vec!["- [x] alpha".to_owned()]));
        let (text, lost) = rebase(BASE, "- [x] beta\n- [ ] gamma\n", "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [ ] delta\n");
        assert_eq!((text.as_str(), lost.len()), ("- [x] beta\n- [ ] gamma\n- [ ] delta\n", 0));
    }

    #[test]
    fn a_change_to_a_line_someone_else_changed_is_lost() {
        let current = "- [ ] alpha\n- [ ] beta (asked Bob)\n- [ ] gamma\n";
        let (text, lost) = rebase(BASE, "- [ ] alpha\n- [x] beta\n- [ ] gamma\n", current);
        assert_eq!((text.as_str(), lost), (current, vec!["- [x] beta".to_owned()]));
    }

    #[test]
    fn edits_merge_with_concurrent_ones() {
        let state = new(BASE);
        let theirs = edit(&state, "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [ ] delta\n").unwrap();
        let ours = edit(&state, "- [x] alpha\n- [ ] beta\n- [ ] gamma\n").unwrap();
        let merged = apply(Some(&apply(Some(&state), &theirs).unwrap()), &ours).unwrap();
        assert_eq!(text(&merged).unwrap(), "- [x] alpha\n- [ ] beta\n- [ ] gamma\n- [ ] delta\n");
    }

    #[test]
    fn an_update_that_arrives_early_waits_for_the_one_it_builds_on() {
        let state = new(BASE);
        let first = edit(&state, "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [ ] delta\n").unwrap();
        let second = edit(&apply(Some(&state), &first).unwrap(), "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [x] delta\n").unwrap();
        let early = apply(Some(&state), &second).unwrap();
        assert_eq!(text(&early).unwrap(), BASE);
        assert_eq!(text(&apply(Some(&early), &first).unwrap()).unwrap(), "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [x] delta\n");
    }
}
