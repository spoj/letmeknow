//! The doc kind's plugin for the session process (`lmk_kinds::plugin`).

fn main() -> anyhow::Result<()> {
    lmk_kinds::plugin::run(lmk_kinds::Kind::Doc)
}
