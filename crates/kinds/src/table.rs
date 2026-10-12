//! A table: a Yjs document holding `columns`, an array of maps (`id`, `name`, `type`, and for a choice column
//! `choices`), and `rows`, an array of maps (`id`, and each cell's value by its column's id), in the order they were
//! added; so the browser's grid (Yjs) and the table plugin (yrs) edit the same document. A column's type is `text`,
//! `number`, `date` (`YYYY-MM-DD`), `checkbox` or `choice`. Agents read and write a table as CSV: `id`, then the columns
//! by name.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use yrs::{Any, Array, ArrayRef, Map, MapPrelim, MapRef, Out, ReadTxn, StateVector, Transact, TransactionMut};

use crate::ydoc;

/// The state of a new table: no columns, no rows.
pub fn new() -> Vec<u8> {
    yrs::Doc::new().transact().encode_state_as_update_v1(&StateVector::default())
}

/// The table as CSV: a header, `id` and the columns' names, then a line per row.
pub fn csv(state: &[u8]) -> Result<String> {
    let doc = ydoc::load(state)?;
    let (columns, rows) = (doc.get_or_insert_array("columns"), doc.get_or_insert_array("rows"));
    let txn = doc.transact();
    let columns = read_columns(&columns, &txn);
    let mut out = csv::WriterBuilder::new().terminator(csv::Terminator::Any(b'\n')).from_writer(Vec::new());
    out.write_record(std::iter::once("id").chain(columns.iter().map(|c| c.name.as_str())))?;
    for row in read_rows(&rows, &txn) {
        out.write_record(std::iter::once(row.id).chain(columns.iter().map(|c| show(row.map.get(&txn, &c.id), &c.kind))))?;
    }
    Ok(String::from_utf8(out.into_inner().map_err(|error| error.into_error())?)?)
}

/// Carries the changes an agent made to a table's CSV, from `base` to `file`, onto the table as it is now, cell by
/// cell: a cell it changed takes the new value, unless someone else changed that cell meanwhile; a line without an id is
/// a new row; a row it deleted goes, unless someone else changed it meanwhile; and a column it added to the header or
/// deleted from it is added, typed by its values, or deleted. Returns the update, if anything changed, and the changes
/// not kept, each with why.
pub fn merge(state: &[u8], base: &str, file: &str) -> Result<(Option<Vec<u8>>, Vec<String>)> {
    let (base, file) = (Csv::parse(base)?, Csv::parse(file)?);
    let doc = ydoc::load(state)?;
    let (columns, rows) = (doc.get_or_insert_array("columns"), doc.get_or_insert_array("rows"));
    let before = doc.transact().state_vector();
    let (mut changed, mut lost) = (false, Vec::new());
    {
        let mut txn = doc.transact_mut();
        for (at, name) in file.header.iter().enumerate() {
            let existing = read_columns(&columns, &txn);
            if name.is_empty() || base.header.contains(name) || existing.iter().any(|c| c.name == *name) {
                continue;
            }
            let kind = infer(file.rows.iter().map(|(_, cells)| cells[at].as_str()));
            let after = file.header[..at].iter().rev().find_map(|before| existing.iter().find(|c| c.name == *before)).map_or(0, |c| c.index + 1);
            columns.insert(&mut txn, after, MapPrelim::from([("id", Any::from(new_id())), ("name", Any::from(name.as_str())), ("type", Any::from(kind))]));
            changed = true;
        }
        for name in base.header.iter().filter(|name| !file.header.contains(name)) {
            if let Some(column) = read_columns(&columns, &txn).iter().find(|c| c.name == *name) {
                columns.remove_range(&mut txn, column.index, 1);
                changed = true;
            }
        }

        let columns = read_columns(&columns, &txn);
        let named: HashMap<&str, &Column> = columns.iter().map(|c| (c.name.as_str(), c)).collect();
        let current = read_rows(&rows, &txn);
        let current: HashMap<&str, &Row> = current.iter().map(|r| (r.id.as_str(), r)).collect();
        let was: HashMap<&str, &Vec<String>> = base.rows.iter().filter(|(id, _)| !id.is_empty()).map(|(id, cells)| (id.as_str(), cells)).collect();
        // A row's cell in the base, by the column's name.
        let old = |cells: &[String], name: &str| base.header.iter().position(|n| n == name).map_or(String::new(), |at| cells[at].clone());
        for (id, cells) in &file.rows {
            match (current.get(id.as_str()), was.get(id.as_str())) {
                (Some(row), was) => {
                    for (at, name) in file.header.iter().enumerate() {
                        let Some(column) = named.get(name.as_str()) else { continue };
                        let (new, now) = (cells[at].as_str(), show(row.map.get(&txn, &column.id), &column.kind));
                        let old = was.map_or(now.clone(), |cells| old(cells, name));
                        if new == old || new == now {
                            continue;
                        }
                        if now != old {
                            lost.push(format!("row {id} {name}: {new:?}, as someone changed it to {now:?} meanwhile"));
                            continue;
                        }
                        changed |= set(&mut txn, &row.map, column, id, new, &mut lost);
                    }
                }
                (None, Some(was)) => {
                    if file.header.iter().enumerate().any(|(at, name)| cells[at] != old(was, name)) {
                        lost.push(format!("row {id}: someone deleted it meanwhile"));
                    }
                }
                (None, None) => {
                    let id = if id.is_empty() { new_id() } else { id.clone() };
                    let row = rows.push_back(&mut txn, MapPrelim::from([("id", Any::from(id.as_str()))]));
                    for (at, name) in file.header.iter().enumerate() {
                        if let Some(column) = named.get(name.as_str()) {
                            set(&mut txn, &row, column, &id, &cells[at], &mut lost);
                        }
                    }
                    changed = true;
                }
            }
        }

        let kept: HashSet<&str> = file.rows.iter().map(|(id, _)| id.as_str()).collect();
        let mut gone = Vec::new();
        for (id, cells) in base.rows.iter().filter(|(id, _)| !id.is_empty() && !kept.contains(id.as_str())) {
            let Some(row) = current.get(id.as_str()) else { continue };
            let same = |(at, name): (usize, &String)| named.get(name.as_str()).is_none_or(|c| show(row.map.get(&txn, &c.id), &c.kind) == cells[at]);
            if base.header.iter().enumerate().all(same) {
                gone.push(row.index);
            } else {
                lost.push(format!("row {id}: kept, as someone changed it meanwhile"));
            }
        }
        gone.sort_unstable();
        for index in gone.into_iter().rev() {
            rows.remove_range(&mut txn, index, 1);
            changed = true;
        }
    }
    Ok((changed.then(|| doc.transact().encode_state_as_update_v1(&before)), lost))
}

struct Column {
    index: u32,
    id: String,
    /// Its name, unique in the table: one that came twice, as when two members added it at once, gets a number.
    name: String,
    kind: String,
    map: MapRef,
}

struct Row {
    index: u32,
    id: String,
    map: MapRef,
}

fn text(map: &MapRef, txn: &impl ReadTxn, key: &str) -> String {
    match map.get(txn, key) {
        Some(Out::Any(Any::String(text))) => text.to_string(),
        _ => String::new(),
    }
}

fn read_columns(columns: &ArrayRef, txn: &impl ReadTxn) -> Vec<Column> {
    let mut seen = HashSet::new();
    let maps = columns.iter(txn).zip(0..).filter_map(|(out, index)| match out {
        Out::YMap(map) => Some((index, map)),
        _ => None,
    });
    maps.map(|(index, map)| {
        let given = text(&map, txn, "name");
        let (mut name, mut n) = (given.clone(), 1);
        while !seen.insert(name.clone()) {
            n += 1;
            name = format!("{given} {n}");
        }
        Column { index, id: text(&map, txn, "id"), name, kind: text(&map, txn, "type"), map }
    })
    .collect()
}

fn read_rows(rows: &ArrayRef, txn: &impl ReadTxn) -> Vec<Row> {
    let maps = rows.iter(txn).zip(0..).filter_map(|(out, index)| match out {
        Out::YMap(map) => Some((index, map)),
        _ => None,
    });
    maps.map(|(index, map)| Row { index, id: text(&map, txn, "id"), map }).collect()
}

/// A cell's value as CSV text: a checkbox's `true` or `false`, a number as Rust writes it, and no value as nothing.
fn show(value: Option<Out>, kind: &str) -> String {
    match value {
        Some(Out::Any(Any::Bool(checked))) => checked.to_string(),
        None if kind == "checkbox" => "false".into(),
        Some(Out::Any(Any::String(text))) => text.to_string(),
        Some(Out::Any(Any::Number(number))) => number.to_string(),
        _ => String::new(),
    }
}

/// The value a cell's text gives in a column of type `kind`, None for an empty cell; or what the text should be.
fn parse(text: &str, kind: &str) -> Result<Option<Any>, &'static str> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match kind {
        "number" => trimmed.parse::<f64>().ok().filter(|n| n.is_finite()).map(|n| Some(Any::Number(n.into()))).ok_or("a number"),
        "date" => date(trimmed).then(|| Some(Any::from(trimmed))).ok_or("a date, YYYY-MM-DD"),
        "checkbox" => match trimmed.to_lowercase().as_str() {
            "true" | "yes" | "x" => Ok(Some(Any::Bool(true))),
            "false" | "no" => Ok(Some(Any::Bool(false))),
            _ => Err("true or false"),
        },
        "choice" => Ok(Some(Any::from(trimmed))),
        _ => Ok(Some(Any::from(text))),
    }
}

fn date(text: &str) -> bool {
    let b = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| b[range].iter().all(u8::is_ascii_digit);
    let number = |range: std::ops::Range<usize>| text[range].parse::<u8>().unwrap_or(0);
    b.len() == 10 && b[4] == b'-' && b[7] == b'-' && digits(0..4) && digits(5..7) && digits(8..10) && (1..=12).contains(&number(5..7)) && (1..=31).contains(&number(8..10))
}

/// The type a new column's values suggest: a number, date or checkbox if all of them read as one, else text.
fn infer<'a>(values: impl Iterator<Item = &'a str>) -> &'static str {
    let values: Vec<&str> = values.filter(|v| !v.trim().is_empty()).collect();
    let fits = |kind| values.iter().all(|v| parse(v, kind).is_ok());
    match ["number", "date", "checkbox"].into_iter().find(|kind| !values.is_empty() && fits(kind)) {
        Some(kind) => kind,
        None => "text",
    }
}

/// Sets a cell to the value its text gives, adding a choice that a choice column lacks; or, if the text does not fit the
/// column, keeps it in `lost`. Returns whether it set the cell.
fn set(txn: &mut TransactionMut, row: &MapRef, column: &Column, id: &str, text: &str, lost: &mut Vec<String>) -> bool {
    match parse(text, &column.kind) {
        Ok(Some(value)) => {
            if let (Any::String(choice), "choice") = (&value, column.kind.as_str()) {
                let mut choices: Vec<Any> = match column.map.get(txn, "choices") {
                    Some(Out::Any(Any::Array(choices))) => choices.to_vec(),
                    _ => Vec::new(),
                };
                if !choices.iter().any(|c| matches!(c, Any::String(c) if c == choice)) {
                    choices.push(value.clone());
                    column.map.insert(txn, "choices", Any::from(choices));
                }
            }
            row.insert(txn, column.id.as_str(), value);
        }
        Ok(None) => {
            row.remove(txn, &column.id);
        }
        Err(should) => {
            lost.push(format!("row {id} {}: {text:?}, which is not {should}", column.name));
            return false;
        }
    }
    true
}

/// A new row's or column's id: 8 lowercase letters and digits.
fn new_id() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    lmk_proto::random::random::<8>().iter().map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char).collect()
}

/// A table as CSV text: the column names in its header, but `id`; and its rows, each with its id (empty for a new
/// row) and its cells in the header's order.
#[derive(Default)]
struct Csv {
    header: Vec<String>,
    rows: Vec<(String, Vec<String>)>,
}

impl Csv {
    fn parse(text: &str) -> Result<Csv> {
        let mut reader = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(text.as_bytes());
        let mut records = reader.records();
        let Some(header) = records.next().transpose()? else { return Ok(Csv::default()) };
        let names: Vec<String> = header.iter().map(|name| name.trim().to_owned()).collect();
        let id = names.iter().position(|name| name == "id");
        let others: Vec<usize> = (0..names.len()).filter(|at| Some(*at) != id).collect();
        let mut rows = Vec::new();
        for record in records {
            let record = record?;
            let cell = |at: usize| record.get(at).unwrap_or_default().to_owned();
            let (row, cells) = (id.map_or(String::new(), |at| cell(at).trim().to_owned()), others.iter().map(|at| cell(*at)).collect::<Vec<_>>());
            if !row.is_empty() || cells.iter().any(|c| !c.trim().is_empty()) {
                rows.push((row, cells));
            }
        }
        Ok(Csv { header: others.iter().map(|at| names[*at].clone()).collect(), rows })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The state after an agent's file `file`, from `base`.
    fn write(state: &[u8], base: &str, file: &str) -> (Vec<u8>, Vec<String>) {
        let (update, lost) = merge(state, base, file).unwrap();
        (update.map_or(state.to_vec(), |update| ydoc::apply(state, &update).unwrap()), lost)
    }

    /// The table's CSV with its rows' ids as `#1`, `#2`... in order, and the ids.
    fn read(state: &[u8]) -> (String, Vec<String>) {
        let text = csv(state).unwrap();
        let ids: Vec<String> = text.lines().skip(1).map(|line| line.split(',').next().unwrap().to_owned()).collect();
        let shown = ids.iter().enumerate().fold(text.clone(), |text, (n, id)| text.replace(id.as_str(), &format!("#{}", n + 1)));
        (shown, ids)
    }

    const TASKS: &str = "Task,Due,Done,Points\nwrite,2026-10-12,false,3\nship,,true,\n";

    #[test]
    fn a_csv_starts_a_table_whose_columns_its_values_type() {
        let (state, lost) = write(&new(), "", TASKS);
        assert!(lost.is_empty());
        let (text, ids) = read(&state);
        assert_eq!(text, "id,Task,Due,Done,Points\n#1,write,2026-10-12,false,3\n#2,ship,,true,\n");
        assert!(ids.iter().all(|id| id.len() == 8));
        let (_, lost) = write(&state, &csv(&state).unwrap(), &csv(&state).unwrap().replace(",3\n", ",lots\n").replace("2026-10-12", "soon"));
        assert_eq!(lost.len(), 2, "{lost:?}");
        assert!(lost[0].ends_with("which is not a date, YYYY-MM-DD") && lost[1].ends_with("which is not a number"), "{lost:?}");
    }

    #[test]
    fn edits_to_different_cells_both_stand_and_of_two_to_one_cell_the_tables_stays() {
        let (state, _) = write(&new(), "", TASKS);
        let base = csv(&state).unwrap();
        let (_, ids) = read(&state);
        let (theirs, _) = write(&state, &base, &base.replace("write,", "draft,").replace(",true,", ",true,5"));
        let (state, lost) = write(&theirs, &base, &base.replace("write,", "rewrite,").replace("2026-10-12", "2026-10-13"));
        assert_eq!(lost, [format!("row {} Task: \"rewrite\", as someone changed it to \"draft\" meanwhile", ids[0])]);
        assert_eq!(read(&state).0, "id,Task,Due,Done,Points\n#1,draft,2026-10-13,false,3\n#2,ship,,true,5\n");
    }

    #[test]
    fn a_line_without_an_id_is_a_new_row_and_a_row_deleted_goes_unless_someone_changed_it() {
        let (state, _) = write(&new(), "", TASKS);
        let base = csv(&state).unwrap();
        let (_, ids) = read(&state);
        let second = base.lines().nth(2).unwrap();
        let (state, lost) = write(&state, &base, &format!("{}\n,review,,,1\n", base.replace(&format!("{second}\n"), "").trim_end()));
        assert!(lost.is_empty());
        assert_eq!(read(&state).0, "id,Task,Due,Done,Points\n#1,write,2026-10-12,false,3\n#2,review,,false,1\n");

        let base = csv(&state).unwrap();
        let (theirs, _) = write(&state, &base, &base.replace("write,", "draft,"));
        let first = base.lines().nth(1).unwrap();
        let (state, lost) = write(&theirs, &base, &base.replace(&format!("{first}\n"), ""));
        assert_eq!(lost, [format!("row {}: kept, as someone changed it meanwhile", ids[0])]);
        assert_eq!(read(&state).0.lines().count(), 3);
    }

    #[test]
    fn a_column_added_to_the_header_is_typed_by_its_values_and_one_deleted_goes() {
        let (state, _) = write(&new(), "", TASKS);
        let base = csv(&state).unwrap();
        let file: String = base.lines().enumerate().map(|(n, line)| {
            let (id, rest) = line.split_once(',').unwrap();
            let rest = rest.rsplit_once(',').unwrap().0;
            format!("{id},{},{rest}\n", ["Estimate", "2.5", "1"][n])
        }).collect();
        let (state, lost) = write(&state, &base, &file);
        assert!(lost.is_empty());
        assert_eq!(read(&state).0, "id,Estimate,Task,Due,Done\n#1,2.5,write,2026-10-12,false\n#2,1,ship,,true\n");
        let doc = ydoc::load(&state).unwrap();
        let columns = doc.get_or_insert_array("columns");
        let kinds: Vec<String> = read_columns(&columns, &doc.transact()).into_iter().map(|c| c.kind).collect();
        assert_eq!(kinds, ["number", "text", "date", "checkbox"]);
    }

    #[test]
    fn a_choice_a_column_lacks_joins_its_choices() {
        let doc = yrs::Doc::new();
        let columns = doc.get_or_insert_array("columns");
        let status = MapPrelim::from([("id", Any::from("s")), ("name", Any::from("Status")), ("type", Any::from("choice")), ("choices", Any::from(vec![Any::from("todo")]))]);
        columns.push_back(&mut doc.transact_mut(), status);
        let state = doc.transact().encode_state_as_update_v1(&StateVector::default());
        let (state, lost) = write(&state, "id,Status\n", "id,Status\n,todo\n,doing \n");
        assert!(lost.is_empty());
        let doc = ydoc::load(&state).unwrap();
        let columns = doc.get_or_insert_array("columns");
        let txn = doc.transact();
        let column = read_columns(&columns, &txn).remove(0);
        assert_eq!(column.map.get(&txn, "choices"), Some(Out::Any(Any::from(vec![Any::from("todo"), Any::from("doing")]))));
    }
}
