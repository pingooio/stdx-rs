use std::collections::BTreeMap;

use maxminddb::{
    Reader, Value,
    writer::{Tree, TreeOptions},
};

fn main() -> Result<(), String> {
    let opts = TreeOptions {
        database_type: "My-Example-DB".to_string(),
        ip_version: 4,
        record_size: 24,
        description: {
            let mut m = BTreeMap::new();
            m.insert("en".to_string(), "Example database".to_string());
            m
        },
        ..Default::default()
    };

    let mut tree = Tree::new(opts).unwrap();

    // insert_value — accepts a raw Value<'_>, built with the map! macro
    tree.insert_value(
        "1.2.3.0/24".parse().unwrap(),
        maxminddb::map! {
            "code" => "US",
            "name" => "United States",
        },
    )?;

    // insert — accepts any Serialize, e.g. a BTreeMap<String, String>
    let mut m = BTreeMap::new();
    m.insert("code".to_string(), "GB".to_string());
    m.insert("name".to_string(), "United Kingdom".to_string());
    tree.insert("5.6.7.0/24".parse().unwrap(), m)?;

    let mut buf = Vec::new();
    tree.write_to(&mut buf)?;

    let reader = Reader::from_source(buf).unwrap();

    let us: Value<'_> = reader.lookup("1.2.3.4".parse().unwrap()).unwrap();
    println!("1.2.3.4 -> {us:?}");

    let gb: Value<'_> = reader.lookup("5.6.7.8".parse().unwrap()).unwrap();
    println!("5.6.7.8 -> {gb:?}");

    Ok(())
}
