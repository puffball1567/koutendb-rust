use koutendb::{KoutenDb, ReadRingOptions, RetrieveOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = KoutenDb::open_default()?;
    db.set_galaxy_description("Example knowledge base")?;
    db.set_ring_description("docs/rust", "Rust driver documents")?;

    let id = db.put_json_vec(
        "docs/rust",
        r#"{"title":"hello","lang":"rust"}"#,
        &[1.0, 0.0],
    )?;

    let selected = db.query_string(id, "{ title }")?;
    println!("id={id}");
    println!("selected={selected}");

    let page = db.read_ring_json(
        "docs/rust",
        &ReadRingOptions::new()
            .filter_json(r#"{"lang":"rust"}"#)
            .selection("{ title }")
            .limit(10),
    )?;
    println!("page={page}");

    let result = db.retrieve_with(
        &[1.0, 0.0],
        RetrieveOptions::new().ring("docs/rust").budget(8),
    )?;
    println!(
        "hits={} scanned={} estimated_tokens={}",
        result.len(),
        result.stats.scanned,
        result.stats.estimated_tokens
    );

    println!("{}", db.atlas(Some(&[1.0, 0.0]), 8)?);
    Ok(())
}
