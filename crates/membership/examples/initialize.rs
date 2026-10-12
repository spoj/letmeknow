use anyhow::{Context, Result};
use lmk_membership::store::Store;

fn main() -> Result<()> {
    let state = std::env::args_os().nth(1).context("usage: initialize NEW_STATE_DIRECTORY")?;
    let store = Store::initialize(std::path::Path::new(&state))?;
    println!("{}", hex::encode(store.key().verifying_key().as_bytes()));
    Ok(())
}
