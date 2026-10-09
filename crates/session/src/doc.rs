//! A doc as an agent sees it: a file, kept in step with the doc's text (`lmk_node::doc`).
use anyhow::{Context, Result};
use similar::{ChangeTag, DiffTag, TextDiff};
use std::path::Path;
use std::time::Duration;
use tokio::time::Instant;

/// How many lines `new` changed from `old`, and the lines it added or changed.
pub fn changed(old: &str, new: &str) -> (usize, Vec<String>) {
    let diff = TextDiff::from_lines(old, new);
    let count = diff.ops().iter().map(|op| op.old_range().len().max(op.new_range().len()) * usize::from(op.tag() != DiffTag::Equal)).sum();
    let added = diff.iter_all_changes().filter(|c| c.tag() == ChangeTag::Insert).map(|c| c.value().trim_end_matches('\n').to_owned()).collect();
    (count, added)
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

/// Writes a doc's file whole, through a rename, so that its readers never see half of it. The file keeps its permissions.
/// Windows refuses to replace a file that another program has open; then the file is written in place.
pub fn write_file(path: &Path, text: &str) -> Result<()> {
    let temp = path.with_file_name(format!(".{}.letmeknow", path.file_name().context("not a file")?.to_string_lossy()));
    std::fs::create_dir_all(path.parent().context("not a file")?)?;
    std::fs::write(&temp, text)?;
    if let Ok(metadata) = std::fs::metadata(path) {
        std::fs::set_permissions(&temp, metadata.permissions())?;
    }
    if std::fs::rename(&temp, path).is_err() {
        std::fs::remove_file(&temp)?;
        std::fs::write(path, text)?;
    }
    Ok(())
}

/// A file is brought into step once it has been quiet for FILE_QUIET, or changing for FILE_MAX; the doc after DOC_QUIET
/// or DOC_MAX. Editors write a file in bursts; a person's typing reaches the doc about once a second.
const FILE_QUIET: Duration = Duration::from_secs(1);
const FILE_MAX: Duration = Duration::from_secs(5);
const DOC_QUIET: Duration = Duration::from_secs(2);
const DOC_MAX: Duration = Duration::from_secs(10);

/// When the file, and the doc, first and last changed since they were last in step, if they did.
#[derive(Default)]
pub struct Quiet {
    file: Option<(Instant, Instant)>,
    doc: Option<(Instant, Instant)>,
}

impl Quiet {
    pub fn file_changed(&mut self, now: Instant) {
        mark(&mut self.file, now);
    }

    pub fn doc_changed(&mut self, now: Instant) {
        mark(&mut self.doc, now);
    }

    pub fn due(&self) -> Option<Instant> {
        let file = self.file.map(|(first, last)| (last + FILE_QUIET).min(first + FILE_MAX));
        let doc = self.doc.map(|(first, last)| (last + DOC_QUIET).min(first + DOC_MAX));
        file.into_iter().chain(doc).min()
    }
}

fn mark(changed: &mut Option<(Instant, Instant)>, now: Instant) {
    *changed = Some((changed.map_or(now, |(first, _)| first), now));
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
    fn changed_counts_the_lines_a_text_changed_and_gives_the_new_ones() {
        let (count, added) = changed(BASE, "- [x] alpha\n- [ ] gamma\n- [ ] delta @Claude\n");
        assert_eq!((count, added), (3, vec!["- [x] alpha".to_owned(), "- [ ] delta @Claude".to_owned()]));
    }

    #[test]
    fn a_file_is_written_through_a_rename_and_keeps_its_permissions() {
        let dir = std::env::temp_dir().join(format!("lmk-doc-{}", std::process::id()));
        let path = dir.join("plan.md");
        write_file(&path, "one\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            write_file(&path, "two\n").unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_file_another_program_has_open_is_written_in_place() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!("lmk-doc-open-{}", std::process::id()));
        let path = dir.join("plan.md");
        write_file(&path, "one\n").unwrap();
        // As editors open a file: others may read and write it, but not delete or replace it.
        let open = std::fs::OpenOptions::new().read(true).share_mode(1 | 2).open(&path).unwrap();
        write_file(&path, "two\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two\n");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        drop(open);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_doc_is_due_once_quiet_or_after_the_longest_wait() {
        let start = Instant::now();
        let mut quiet = Quiet::default();
        assert_eq!(quiet.due(), None);
        quiet.file_changed(start);
        assert_eq!(quiet.due(), Some(start + FILE_QUIET));
        for ms in (500..=4500).step_by(500) {
            quiet.file_changed(start + Duration::from_millis(ms));
        }
        assert_eq!(quiet.due(), Some(start + FILE_MAX));
        let mut quiet = Quiet::default();
        quiet.doc_changed(start);
        quiet.doc_changed(start + Duration::from_secs(1));
        assert_eq!(quiet.due(), Some(start + Duration::from_secs(1) + DOC_QUIET));
    }
}
