use maxminddb::{
    Reader,
    encoder::Value,
    writer::{Tree, TreeOptions},
};

fn main() -> Result<(), String> {
    let opts = TreeOptions {
        database_type: "My-Example-DB".to_string(),
        ip_version: 4,
        record_size: 24,
        description: {
            let mut m = std::collections::BTreeMap::new();
            m.insert("en".to_string(), "Example database".to_string());
            m
        },
        ..Default::default()
    };

    let mut tree = Tree::new(opts).unwrap();

    tree.insert(
        "1.2.3.0/24".parse().unwrap(),
        maxminddb::map! {
            "code" => "US",
            "name" => "United States",
            "active" => true,
            "rank" => 1u32,
        },
    )
    .unwrap();

    tree.insert(
        "5.6.7.0/24".parse().unwrap(),
        maxminddb::map! {
            "code" => "GB",
            "name" => "United Kingdom",
            "active" => false,
            "rank" => 2u32,
        },
    )
    .unwrap();

    let mut buf = Vec::new();
    tree.write_to(&mut buf).unwrap();

    let reader = Reader::from_source(buf).unwrap();

    let us: Value = reader.lookup("1.2.3.4".parse().unwrap()).unwrap();
    println!("1.2.3.4 -> {us:?}");

    let gb: Value = reader.lookup("5.6.7.8".parse().unwrap()).unwrap();
    println!("5.6.7.8 -> {gb:?}");

    Ok(())
}
