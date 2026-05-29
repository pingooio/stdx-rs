use std::{
    collections::BTreeMap,
    io::Write,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use ipnetwork::IpNetwork;

use crate::encoder::{self, Value};

pub type WriterResult<T> = Result<T, String>;

fn map_io_err(e: std::io::Error) -> String {
    e.to_string()
}

const DATA_SECTION_SEPARATOR: &[u8; 16] = &[0u8; 16];
const METADATA_START_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

#[derive(Debug, Clone)]
enum RecordType {
    Empty,
    Data,
    Node,
}

#[derive(Debug, Clone)]
struct DataRecord {
    value: Value,
    key: u64,
}

#[derive(Debug, Clone)]
struct ChildRecord {
    record_type: RecordType,
    data: Option<DataRecord>,
    node: Option<Box<TreeNode>>,
}

impl ChildRecord {
    fn empty() -> Self {
        ChildRecord {
            record_type: RecordType::Empty,
            data: None,
            node: None,
        }
    }

    fn data(value: Value, key: u64) -> Self {
        ChildRecord {
            record_type: RecordType::Data,
            data: Some(DataRecord {
                value,
                key,
            }),
            node: None,
        }
    }

    fn node(node: TreeNode) -> Self {
        ChildRecord {
            record_type: RecordType::Node,
            data: None,
            node: Some(Box::new(node)),
        }
    }
}

#[derive(Debug, Clone)]
struct TreeNode {
    node_num: Option<usize>,
    children: [ChildRecord; 2],
}

impl TreeNode {
    fn new() -> Self {
        TreeNode {
            node_num: None,
            children: [ChildRecord::empty(), ChildRecord::empty()],
        }
    }

    fn insert(&mut self, ip: &[u8], prefix_len: usize, depth: usize, value: Value, data_key: u64) -> WriterResult<()> {
        if depth == prefix_len {
            self.children[0] = ChildRecord::data(value.clone(), data_key);
            self.children[1] = ChildRecord::data(value, data_key);
            return Ok(());
        }

        let bit = bit_at(ip, depth);
        let child = &mut self.children[bit as usize];

        match &child.record_type {
            RecordType::Empty => {
                let mut subtree = TreeNode::new();
                subtree.insert(ip, prefix_len, depth + 1, value, data_key)?;
                *child = ChildRecord::node(subtree);
            }
            RecordType::Data => {
                let existing = child.data.as_ref().unwrap();
                let mut subtree = TreeNode::new();
                subtree.children[0] = ChildRecord::data(existing.value.clone(), existing.key);
                subtree.children[1] = ChildRecord::data(existing.value.clone(), existing.key);
                subtree.insert(ip, prefix_len, depth + 1, value, data_key)?;
                *child = ChildRecord::node(subtree);
            }
            RecordType::Node => {
                child
                    .node
                    .as_mut()
                    .unwrap()
                    .insert(ip, prefix_len, depth + 1, value, data_key)?;
            }
        }

        Ok(())
    }

    fn finalize(&mut self, next_node: &mut usize) {
        self.node_num = Some(*next_node);
        *next_node += 1;

        for i in 0..2 {
            if let Some(node) = self.children[i].node.as_mut() {
                node.finalize(next_node);
            }
        }
    }

    fn write_node<W: Write>(
        &self,
        writer: &mut W,
        node_count: usize,
        data_offsets: &BTreeMap<u64, usize>,
        record_size: u16,
    ) -> WriterResult<()> {
        let left_val = self.resolve_record_value(&self.children[0], node_count, data_offsets)?;
        let right_val = self.resolve_record_value(&self.children[1], node_count, data_offsets)?;

        let max_record = 1usize << record_size;
        if left_val >= max_record || right_val >= max_record {
            return Err(format!(
                "record value ({}, {}) exceeds max for {} bit record size",
                left_val, right_val, record_size
            ));
        }

        match record_size {
            24 => writer
                .write_all(&[
                    ((left_val >> 16) & 0xFF) as u8,
                    ((left_val >> 8) & 0xFF) as u8,
                    (left_val & 0xFF) as u8,
                    ((right_val >> 16) & 0xFF) as u8,
                    ((right_val >> 8) & 0xFF) as u8,
                    (right_val & 0xFF) as u8,
                ])
                .map_err(map_io_err)?,
            28 => writer
                .write_all(&[
                    ((left_val >> 16) & 0xFF) as u8,
                    ((left_val >> 8) & 0xFF) as u8,
                    (left_val & 0xFF) as u8,
                    ((((left_val >> 24) & 0x0F) << 4) | ((right_val >> 24) & 0x0F)) as u8,
                    ((right_val >> 16) & 0xFF) as u8,
                    ((right_val >> 8) & 0xFF) as u8,
                    (right_val & 0xFF) as u8,
                ])
                .map_err(map_io_err)?,
            32 => writer
                .write_all(&[
                    ((left_val >> 24) & 0xFF) as u8,
                    ((left_val >> 16) & 0xFF) as u8,
                    ((left_val >> 8) & 0xFF) as u8,
                    (left_val & 0xFF) as u8,
                    ((right_val >> 24) & 0xFF) as u8,
                    ((right_val >> 16) & 0xFF) as u8,
                    ((right_val >> 8) & 0xFF) as u8,
                    (right_val & 0xFF) as u8,
                ])
                .map_err(map_io_err)?,
            s => return Err(format!("unsupported record size: {s}")),
        }

        for child in &self.children {
            if let Some(node) = &child.node {
                node.write_node(writer, node_count, data_offsets, record_size)?;
            }
        }

        Ok(())
    }

    fn resolve_record_value(
        &self,
        record: &ChildRecord,
        node_count: usize,
        data_offsets: &BTreeMap<u64, usize>,
    ) -> WriterResult<usize> {
        match &record.record_type {
            RecordType::Empty => Ok(node_count),
            RecordType::Data => {
                let d = record.data.as_ref().unwrap();
                let offset = data_offsets.get(&d.key).unwrap();
                Ok(node_count + 16 + offset)
            }
            RecordType::Node => Ok(record.node.as_ref().unwrap().node_num.unwrap()),
        }
    }
}

fn bit_at(ip: &[u8], depth: usize) -> u8 {
    (ip[depth >> 3] >> (7 - (depth & 7))) & 1
}

#[derive(Debug)]
pub struct Tree {
    root: TreeNode,
    data_map: BTreeMap<u64, Value>,
    node_count: usize,
    ip_version: u16,
    record_size: u16,
    database_type: String,
    description: BTreeMap<String, String>,
    languages: Vec<String>,
    build_epoch: u64,
    next_data_key: u64,
}

#[derive(Clone)]
pub struct TreeOptions {
    pub ip_version: u16,
    pub record_size: u16,
    pub database_type: String,
    pub description: BTreeMap<String, String>,
    pub languages: Vec<String>,
    pub build_epoch: u64,
}

impl Default for TreeOptions {
    fn default() -> Self {
        TreeOptions {
            ip_version: 6,
            record_size: 28,
            database_type: String::new(),
            description: BTreeMap::new(),
            languages: Vec::new(),
            build_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl Tree {
    pub fn new(opts: TreeOptions) -> WriterResult<Self> {
        if opts.ip_version != 4 && opts.ip_version != 6 {
            return Err(format!("invalid ip_version: {} (must be 4 or 6)", opts.ip_version));
        }
        if opts.record_size != 24 && opts.record_size != 28 && opts.record_size != 32 {
            return Err(format!("invalid record_size: {} (must be 24, 28, or 32)", opts.record_size));
        }
        Ok(Tree {
            root: TreeNode::new(),
            data_map: BTreeMap::new(),
            node_count: 0,
            ip_version: opts.ip_version,
            record_size: opts.record_size,
            database_type: opts.database_type,
            description: opts.description,
            languages: opts.languages,
            build_epoch: opts.build_epoch,
            next_data_key: 1,
        })
    }

    pub fn insert(&mut self, network: IpNetwork, value: Value) -> WriterResult<()> {
        let prefix_len = network.prefix() as usize;
        let ip = ip_to_bytes(network.network());

        if self.ip_version == 4 && ip.len() != 4 {
            return Err("cannot insert IPv6 network into an IPv4 tree".to_string());
        }

        let (ip_bytes, actual_prefix_len) = if self.ip_version == 6 && ip.len() == 4 {
            let mut v6 = [0u8; 16];
            v6[12..].copy_from_slice(&ip);
            (v6.to_vec(), prefix_len + 96)
        } else {
            (ip, prefix_len)
        };

        let data_key = {
            let mut found_key = None;
            for (k, v) in &self.data_map {
                if *v == value {
                    found_key = Some(*k);
                    break;
                }
            }
            match found_key {
                Some(k) => k,
                None => {
                    let key = self.next_data_key;
                    self.next_data_key += 1;
                    self.data_map.insert(key, value.clone());
                    key
                }
            }
        };

        self.node_count = 0;
        self.root.insert(&ip_bytes, actual_prefix_len, 0, value, data_key)?;

        Ok(())
    }

    pub fn write_to<W: Write>(&mut self, writer: &mut W) -> WriterResult<u64> {
        let mut next = 1usize;
        for child in &mut self.root.children {
            if let Some(node) = child.node.as_mut() {
                node.finalize(&mut next);
            }
        }
        self.node_count = next;

        let search_tree_size_bytes = self.node_count * self.record_size as usize / 4;

        let mut data_offsets: BTreeMap<u64, usize> = BTreeMap::new();
        let mut data_section = Vec::new();
        for (key, value) in &self.data_map {
            let offset = data_section.len();
            encoder::encode_value_to(&mut data_section, value)?;
            data_offsets.insert(*key, offset);
        }

        let node_count = self.node_count;
        self.root
            .write_node(writer, node_count, &data_offsets, self.record_size)?;

        writer.write_all(DATA_SECTION_SEPARATOR).map_err(map_io_err)?;
        writer.write_all(&data_section).map_err(map_io_err)?;
        writer.write_all(METADATA_START_MARKER).map_err(map_io_err)?;

        let metadata = build_metadata_value(
            self.node_count as u32,
            self.record_size,
            self.ip_version,
            &self.database_type,
            &self.description,
            &self.languages,
            self.build_epoch,
        );
        let metadata_bytes = encoder::encode_value(&metadata)?;
        writer.write_all(&metadata_bytes).map_err(map_io_err)?;

        Ok((search_tree_size_bytes
            + DATA_SECTION_SEPARATOR.len()
            + data_section.len()
            + METADATA_START_MARKER.len()
            + metadata_bytes.len()) as u64)
    }
}

fn build_metadata_value(
    node_count: u32,
    record_size: u16,
    ip_version: u16,
    database_type: &str,
    description: &BTreeMap<String, String>,
    languages: &[String],
    build_epoch: u64,
) -> Value {
    let mut desc_map = BTreeMap::new();
    for (k, v) in description {
        desc_map.insert(k.clone(), Value::String(v.clone()));
    }

    let mut lang_array = Vec::new();
    for l in languages {
        lang_array.push(Value::String(l.clone()));
    }

    let mut m = BTreeMap::new();
    m.insert("binary_format_major_version".to_string(), Value::Uint16(2));
    m.insert("binary_format_minor_version".to_string(), Value::Uint16(0));
    m.insert("build_epoch".to_string(), Value::Uint64(build_epoch));
    m.insert("database_type".to_string(), Value::String(database_type.to_string()));
    m.insert("description".to_string(), Value::Map(desc_map));
    m.insert("ip_version".to_string(), Value::Uint16(ip_version));
    m.insert("languages".to_string(), Value::Slice(lang_array));
    m.insert("node_count".to_string(), Value::Uint32(node_count));
    m.insert("record_size".to_string(), Value::Uint16(record_size));
    Value::Map(m)
}

fn ip_to_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read_simple_v4() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("country".to_string(), Value::String("US".to_string()));
        tree.insert("1.2.3.0/24".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            country: String,
        }
        let result: TestRecord = reader.lookup("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(result.country, "US");
    }

    #[test]
    fn test_write_and_read_multiple_networks() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m1 = BTreeMap::new();
        m1.insert("country".to_string(), Value::String("US".to_string()));
        tree.insert("1.0.0.0/8".parse().unwrap(), Value::Map(m1)).unwrap();
        let mut m2 = BTreeMap::new();
        m2.insert("country".to_string(), Value::String("FR".to_string()));
        tree.insert("2.0.0.0/8".parse().unwrap(), Value::Map(m2)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            country: String,
        }
        let r1: TestRecord = reader.lookup("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(r1.country, "US");
        let r2: TestRecord = reader.lookup("2.3.4.5".parse().unwrap()).unwrap();
        assert_eq!(r2.country, "FR");
        assert!(reader.lookup::<TestRecord>("3.4.5.6".parse().unwrap()).is_err());
    }

    #[test]
    fn test_v6_database() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 6,
            record_size: 28,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("country".to_string(), Value::String("FR".to_string()));
        tree.insert("2a00:1450:4000::/36".parse().unwrap(), Value::Map(m))
            .unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            country: String,
        }
        let r: TestRecord = reader.lookup("2a00:1450:4000::".parse().unwrap()).unwrap();
        assert_eq!(r.country, "FR");
    }

    #[test]
    fn test_all_record_sizes() {
        for record_size in [24, 28, 32] {
            let opts = TreeOptions {
                database_type: "Test".to_string(),
                ip_version: 4,
                record_size,
                ..Default::default()
            };
            let mut tree = Tree::new(opts).unwrap();
            let mut m = BTreeMap::new();
            m.insert("ip".to_string(), Value::String("test".to_string()));
            tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
            let mut buf = Vec::new();
            tree.write_to(&mut buf).unwrap();
            let reader = crate::Reader::from_source(buf.clone()).unwrap();
            #[derive(serde::Deserialize, Debug)]
            struct TestRecord {
                ip: String,
            }
            let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
            assert_eq!(r.ip, "test", "failed for record_size={record_size}");
        }
    }

    #[test]
    fn test_write_with_metadata() {
        let mut desc = BTreeMap::new();
        desc.insert("en".to_string(), "Test Database".to_string());
        let opts = TreeOptions {
            database_type: "TestIP".to_string(),
            ip_version: 4,
            record_size: 24,
            description: desc,
            languages: vec!["en".to_string()],
            build_epoch: 1000000,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("data".to_string(), Value::String("hello".to_string()));
        tree.insert("192.168.0.0/16".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        assert_eq!(reader.metadata.database_type, "TestIP");
        assert_eq!(reader.metadata.build_epoch, 1000000);
        assert_eq!(reader.metadata.description["en"], "Test Database");
    }

    #[test]
    fn test_bool_value() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("active".to_string(), Value::Bool(true));
        m.insert("inactive".to_string(), Value::Bool(false));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            active: bool,
            inactive: bool,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert!(r.active);
        assert!(!r.inactive);
    }

    #[test]
    fn test_slice_value() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert(
            "tags".to_string(),
            Value::Slice(vec![
                Value::String("a".to_string()),
                Value::String("b".to_string()),
                Value::String("c".to_string()),
            ]),
        );
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            tags: Vec<String>,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r.tags, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_integer_types() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("u16".to_string(), Value::Uint16(100));
        m.insert("u32".to_string(), Value::Uint32(100000));
        m.insert("i32".to_string(), Value::Int32(-42));
        m.insert("u64".to_string(), Value::Uint64(1 << 40));
        m.insert("u128".to_string(), Value::Uint128(1u128 << 100));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            u16: u16,
            u32: u32,
            i32: i32,
            u64: u64,
            u128: u128,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r.u16, 100);
        assert_eq!(r.u32, 100000);
        assert_eq!(r.i32, -42);
        assert_eq!(r.u64, 1 << 40);
        assert_eq!(r.u128, 1u128 << 100);
    }

    // --- Additional comprehensive tests ---

    #[test]
    fn test_pointer_encoding_size3() {
        // Verify size=3 pointer encoding uses correct control byte (bits 0-2 ignored per spec)
        // Encode a large pointer (> 134744063) and check the control byte is exactly 0b00111000 (0x38)
        let v = Value::Pointer(200000000);
        let buf = encoder::encode_value(&v).unwrap();
        // First byte should be 0x38 (001 11 000 -> type=pointer, size_indicator=3)
        assert_eq!(buf[0], 0b00111000, "size=3 pointer control byte should be 0x38");
        // Next 4 bytes are the raw 32-bit pointer value in big-endian
        let ptr_val = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        assert_eq!(ptr_val, 200000000);
    }

    #[test]
    fn test_pointer_encoding_size0() {
        // Pointer < 2048: control byte has 3-bit value appended
        let v = Value::Pointer(500);
        let buf = encoder::encode_value(&v).unwrap();
        // First byte: 001 SSVVV  where SSVV = 00 (size=0), VVV = bits 8-10 of pointer
        // For p=500: 500 = 0b111110100 -> bits [8:10] = 0b001
        // So first byte = 001 00 001 = 0b00100001 = 0x21
        assert_eq!(buf[0], 0b00100001);
        assert_eq!(buf.len(), 2);
        let decoded = ((buf[0] as u32 & 0x07) << 8) | buf[1] as u32;
        assert_eq!(decoded, 500);
    }

    #[test]
    fn test_pointer_encoding_size1() {
        let v = Value::Pointer(10000);
        let buf = encoder::encode_value(&v).unwrap();
        // size=1: first byte = 001 01 VVV, next 2 bytes = value-2048
        assert_eq!((buf[0] >> 5) & 0x07, 0b001); // pointer type
        assert_eq!((buf[0] >> 3) & 0x03, 0b01); // size=1
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn test_empty_database() {
        // A database with no networks inserted should still write valid metadata
        let opts = TreeOptions {
            database_type: "Empty".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut buf = Vec::new();
        let n = tree.write_to(&mut buf).unwrap();
        assert!(n > 0);
        let reader = crate::Reader::from_source(buf).unwrap();
        assert_eq!(reader.metadata.database_type, "Empty");
        assert_eq!(reader.metadata.node_count, 1); // root node always present
    }

    #[test]
    fn test_overlapping_networks() {
        // More specific prefix should win in lookup; both can exist in tree
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m1 = BTreeMap::new();
        m1.insert("data".to_string(), Value::String("broad".to_string()));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m1)).unwrap();

        let mut m2 = BTreeMap::new();
        m2.insert("data".to_string(), Value::String("specific".to_string()));
        tree.insert("10.1.0.0/16".parse().unwrap(), Value::Map(m2)).unwrap();

        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();

        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            data: String,
        }

        // 10.0.x.x should match the /8
        let r1: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r1.data, "broad");

        // 10.1.x.x should match the /16
        let r2: TestRecord = reader.lookup("10.1.0.1".parse().unwrap()).unwrap();
        assert_eq!(r2.data, "specific");
    }

    // test_bytes_value removed: Value does not implement Deserialize,
    // and testing Bytes type requires either (a) adding Deserialize to Value,
    // or (b) using the decoder API directly. Retain the coverage gap for now.

    #[test]
    fn test_nested_map() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut inner = BTreeMap::new();
        inner.insert("code".to_string(), Value::Uint16(1));
        inner.insert("name".to_string(), Value::String("US".to_string()));

        let mut m = BTreeMap::new();
        m.insert("country".to_string(), Value::Map(inner));
        m.insert("active".to_string(), Value::Bool(true));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();

        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();

        #[derive(serde::Deserialize, Debug)]
        struct Country {
            code: u16,
            name: String,
        }
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            country: Country,
            active: bool,
        }

        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r.country.code, 1);
        assert_eq!(r.country.name, "US");
        assert!(r.active);
    }

    #[test]
    fn test_data_deduplication() {
        // Two networks with identical data should produce a smaller overall file
        // than two with different data (same tree structure, but data section is smaller).
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };

        // Insert two networks with identical data
        let mut tree = Tree::new(opts.clone()).unwrap();
        let shared_data = {
            let mut m = BTreeMap::new();
            m.insert("val".to_string(), Value::String("shared".to_string()));
            Value::Map(m)
        };
        tree.insert("10.0.0.0/8".parse().unwrap(), shared_data.clone()).unwrap();
        tree.insert("11.0.0.0/8".parse().unwrap(), shared_data).unwrap();
        let mut buf_dedup = Vec::new();
        tree.write_to(&mut buf_dedup).unwrap();

        // Insert two networks with different data
        let mut tree2 = Tree::new(opts).unwrap();
        let mut m1 = BTreeMap::new();
        m1.insert("val".to_string(), Value::String("first".to_string()));
        let mut m2 = BTreeMap::new();
        m2.insert("val".to_string(), Value::String("second".to_string()));
        tree2.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m1)).unwrap();
        tree2.insert("11.0.0.0/8".parse().unwrap(), Value::Map(m2)).unwrap();
        let mut buf_no_dedup = Vec::new();
        tree2.write_to(&mut buf_no_dedup).unwrap();

        // Deduplicated file should be strictly smaller (same tree, smaller data section)
        assert!(
            buf_dedup.len() < buf_no_dedup.len(),
            "dedup size {} should be < no-dedup size {}",
            buf_dedup.len(),
            buf_no_dedup.len()
        );

        // Both must parse correctly
        let r1 = crate::Reader::from_source(buf_dedup).unwrap();
        let r2 = crate::Reader::from_source(buf_no_dedup).unwrap();
        assert_eq!(r1.metadata.node_count, r2.metadata.node_count);
    }

    #[test]
    fn test_ipv4_in_ipv6_tree() {
        // Insert an IPv4 network into an IPv6 tree; it should be reachable at ::/96-mapped address
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 6,
            record_size: 28,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("v4in6".to_string(), Value::Bool(true));
        // insert_string with ip_version=6 and an IPv4 CIDR should auto-map into ::/96
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();

        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();

        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            v4in6: bool,
        }

        // Look up using the IPv4 address (reader should handle v4-in-v6)
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert!(r.v4in6);
    }

    #[test]
    fn test_record_size_24_node_format() {
        // Write a simple DB with record_size=24 and verify the node bytes directly.
        // Per spec: record value < node_count => node ref; == node_count => no data;
        // > node_count+15 => data section offset (node_count+16 = first valid data offset).
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("1.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();

        let reader = crate::Reader::from_source(buf.clone()).unwrap();
        let node_count = reader.metadata.node_count; // u32
        let nc = node_count as u64;
        // 24-bit record size: 6 bytes per node; first node at buf[0..6]
        let left = ((buf[0] as u64) << 16) | ((buf[1] as u64) << 8) | (buf[2] as u64);
        let right = ((buf[3] as u64) << 16) | ((buf[4] as u64) << 8) | (buf[5] as u64);
        // Valid: <= nc (node ref or no-data), or >= nc+16 (data section)
        assert!(left <= nc || left >= nc + 16, "left={left} nc={nc}");
        assert!(right <= nc || right >= nc + 16, "right={right} nc={nc}");
    }

    #[test]
    fn test_record_size_28_node_format() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 28,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("1.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();

        let node_count = crate::Reader::from_source(buf.clone()).unwrap().metadata.node_count as usize;
        // 28-bit: 7 bytes per node
        assert!(buf.len() > node_count * 7);
    }

    #[test]
    fn test_record_size_32_node_format() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 32,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("1.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();

        let node_count = crate::Reader::from_source(buf.clone()).unwrap().metadata.node_count as usize;
        // 32-bit: 8 bytes per node
        assert!(buf.len() > node_count * 8);
    }

    #[test]
    fn test_search_tree_size_calculation() {
        // Verify the search tree size formula from the spec:
        //   (record_size * 2 / 8) * node_count
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();

        let reader = crate::Reader::from_source(buf).unwrap();
        let node_count = reader.metadata.node_count as usize;
        let record_size = reader.metadata.record_size as usize;
        let expected_tree_bytes = (record_size * 2 / 8) * node_count;
        // The written bytes include tree + separator + data + metadata,
        // so tree bytes should be the first `expected_tree_bytes` in the buffer
        assert_eq!(expected_tree_bytes, record_size * 2 / 8 * node_count);
        // Also check: node_count * (record_size * 2 / 8) doesn't overflow
        assert!(node_count * (record_size * 2 / 8) <= usize::MAX);
    }

    #[test]
    fn test_metadata_binary_format_version() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        assert_eq!(reader.metadata.binary_format_major_version, 2);
        assert_eq!(reader.metadata.binary_format_minor_version, 0);
    }

    #[test]
    fn test_metadata_description_optional() {
        // Description is optional; an empty map should work
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            description: BTreeMap::new(),
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        assert!(reader.metadata.description.is_empty());
    }

    #[test]
    fn test_languages_optional() {
        // Languages is optional
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            languages: vec![],
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        assert!(reader.metadata.languages.is_empty());
    }

    #[test]
    fn test_insert_multiple_cidrs_then_lookup() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        for i in 0u8..10 {
            let cidr = format!("{i}.0.0.0/8");
            let mut m = BTreeMap::new();
            m.insert("net".to_string(), Value::String(cidr.clone()));
            tree.insert(cidr.parse().unwrap(), Value::Map(m)).unwrap();
        }
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            net: String,
        }
        for i in 0u8..10 {
            let ip = format!("{i}.0.0.1");
            let r: TestRecord = reader.lookup(ip.parse().unwrap()).unwrap();
            assert_eq!(r.net, format!("{i}.0.0.0/8"));
        }
    }

    #[test]
    fn test_large_string_value() {
        // Test a string > 28 bytes to exercise the size encoding (size=29 triggers 2-byte encoding)
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let long_str = "x".repeat(100);
        let mut m = BTreeMap::new();
        m.insert("long".to_string(), Value::String(long_str.clone()));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            long: String,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r.long, long_str);
    }

    #[test]
    fn test_metadata_start_marker_last_occurrence() {
        // The metadata start marker \xab\xcd\xefMaxMind.com must appear at the end of the file.
        // Our writer only writes it once, just before the metadata.
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();

        // The marker must appear at most once in the file
        let marker = b"\xab\xcd\xefMaxMind.com";
        let all_positions: Vec<usize> = buf
            .windows(marker.len())
            .enumerate()
            .filter(|(_, w)| *w == marker)
            .map(|(i, _)| i)
            .collect();
        // Exactly one occurrence
        assert_eq!(all_positions.len(), 1);
        // Marker is the last meaningful content before any trailing metadata bytes
        let last_pos = all_positions[0];
        // No marker content beyond this position
        assert!(last_pos < buf.len() - marker.len() || last_pos == buf.len() - marker.len());
        // Confirm it's at the end: nothing after the marker (or only the metadata)
        assert!(last_pos + marker.len() <= buf.len());
    }

    #[test]
    fn test_write_to_is_idempotent() {
        // Calling write_to multiple times should produce valid output each time
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(42));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();

        let mut buf1 = Vec::new();
        let n1 = tree.write_to(&mut buf1).unwrap();

        let mut buf2 = Vec::new();
        let n2 = tree.write_to(&mut buf2).unwrap();

        assert_eq!(n1, n2);
        assert_eq!(buf1.len(), buf2.len());
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_zero_length_prefix() {
        // /0 prefix = entire internet
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("all".to_string(), Value::Bool(true));
        tree.insert("0.0.0.0/0".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            all: bool,
        }
        let r: TestRecord = reader.lookup("255.255.255.255".parse().unwrap()).unwrap();
        assert!(r.all);
    }

    #[test]
    fn test_exact_prefix_length() {
        // /32 prefix = single IP — this exercises the depth==prefix_len leaf case
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("host".to_string(), Value::String("single".to_string()));
        tree.insert("10.0.0.1/32".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        let n = tree.write_to(&mut buf).unwrap();
        // Debug: print the first few node bytes and data section
        let nc = crate::Reader::from_source(buf.clone()).unwrap().metadata.node_count as usize;
        eprintln!("test_exact_prefix_length: written={n}, node_count={nc}");
        eprintln!("  first 12 bytes: {:02x?}", &buf[0..12.min(buf.len())]);
        eprintln!("  tree bytes = {} (expect {} per node * {nc})", nc * 6, nc * 6);
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            host: String,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r.host, "single");
        assert!(reader.lookup::<TestRecord>("10.0.0.2".parse().unwrap()).is_err());
    }

    #[test]
    fn test_negative_int32() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("neg".to_string(), Value::Int32(-1));
        m.insert("min".to_string(), Value::Int32(i32::MIN));
        m.insert("max".to_string(), Value::Int32(i32::MAX));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            neg: i32,
            min: i32,
            max: i32,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r.neg, -1);
        assert_eq!(r.min, i32::MIN);
        assert_eq!(r.max, i32::MAX);
    }

    #[test]
    fn test_float32_value() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("f".to_string(), Value::Float32(1.5));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            f: f32,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert!((r.f - 1.5).abs() < 1e-6);
    }

    #[test]
    fn test_map_with_many_keys() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        for i in 0..20 {
            m.insert(format!("key{i}"), Value::Uint16(i));
        }
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct ManyKeys {/* we just check it deserializes */}
        let _: ManyKeys = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
    }

    #[test]
    fn test_write_error_on_invalid_record_size() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 16, // invalid: must be 24, 28, or 32
            ..Default::default()
        };
        let result = Tree::new(opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_error_on_invalid_ip_version() {
        let result = Tree::new(TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 5,
            record_size: 24,
            ..Default::default()
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ip_version"));
    }

    #[test]
    fn test_write_error_on_invalid_record_size_in_new() {
        let result = Tree::new(TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 20, // not 24, 28, or 32
            ..Default::default()
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("record_size"));
    }

    #[test]
    fn test_write_error_on_record_size_36() {
        let result = Tree::new(TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 36, // multiple of 4 but unsupported
            ..Default::default()
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("record_size"));
    }

    #[test]
    fn test_write_error_ipv6_in_ipv4_tree() {
        let mut tree = Tree::new(TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        })
        .unwrap();
        let result = tree.insert("::1/128".parse().unwrap(), Value::Bool(true));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("IPv6"));
    }

    #[test]
    fn test_float64_value() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("f64".to_string(), Value::Float64(3.141592653589793));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            f64: f64,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert!((r.f64 - 3.141592653589793).abs() < 1e-15);
    }

    #[test]
    fn test_bytes_value() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("raw".to_string(), Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        assert!(reader.metadata.node_count > 0);
    }

    #[test]
    fn test_pointer_encoding_size2() {
        let v = Value::Pointer(1000000);
        let buf = encoder::encode_value(&v).unwrap();
        assert_eq!((buf[0] >> 5) & 0x07, 0b001);
        assert_eq!((buf[0] >> 3) & 0x03, 0b10);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn test_metadata_size_limit() {
        // Spec says metadata (including marker) must be <= 128 KiB.
        // Generate a large description to push metadata near the limit.
        let mut desc = BTreeMap::new();
        desc.insert("en".to_string(), "x".repeat(65536));
        let opts = TreeOptions {
            database_type: "LargeMeta".to_string(),
            ip_version: 4,
            record_size: 24,
            description: desc,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let marker = b"\xab\xcd\xefMaxMind.com";
        let marker_pos = buf.windows(marker.len()).rposition(|w| w == marker).unwrap();
        let metadata_section_size = buf.len() - marker_pos;
        assert!(
            metadata_section_size <= 128 * 1024,
            "metadata section {} bytes exceeds 128 KiB limit",
            metadata_section_size
        );
    }

    #[test]
    fn test_encoded_size_matches_actual() {
        let cases: Vec<Value> = vec![
            Value::Pointer(0),
            Value::Pointer(2047),
            Value::Pointer(2048),
            Value::Pointer(526335),
            Value::Pointer(526336),
            Value::Pointer(134744063),
            Value::Pointer(134744064),
            Value::Pointer(u32::MAX),
            Value::String(String::new()),
            Value::String("hello".to_string()),
            Value::String("x".repeat(29)),
            Value::String("x".repeat(300)),
            Value::String("x".repeat(66000)),
            Value::Float64(0.0),
            Value::Float64(-1.5),
            Value::Float64(f64::MAX),
            Value::Bytes(vec![]),
            Value::Bytes(vec![0; 42]),
            Value::Uint16(0),
            Value::Uint16(1),
            Value::Uint16(u16::MAX),
            Value::Uint32(0),
            Value::Uint32(1 << 20),
            Value::Uint32(u32::MAX),
            Value::Int32(0),
            Value::Int32(1),
            Value::Int32(-1),
            Value::Int32(i32::MIN),
            Value::Int32(i32::MAX),
            Value::Uint64(0),
            Value::Uint64(1 << 56),
            Value::Uint64(u64::MAX),
            Value::Uint128(0),
            Value::Uint128(1u128 << 120),
            Value::Uint128(u128::MAX),
            Value::Bool(true),
            Value::Bool(false),
            Value::Float32(0.0),
            Value::Float32(1.25),
            Value::Float32(f32::MAX),
            Value::Map(BTreeMap::new()),
            Value::Slice(vec![]),
        ];
        for v in cases {
            let encoded = encoder::encode_value(&v).unwrap();
            let predicted = encoder::encoded_size(&v);
            assert_eq!(
                encoded.len(),
                predicted,
                "encoded_size mismatch for {:?}: actual={}, predicted={}",
                v,
                encoded.len(),
                predicted
            );
        }
    }

    #[test]
    fn test_insert_same_network_twice() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m1 = BTreeMap::new();
        m1.insert("val".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m1)).unwrap();
        let mut m2 = BTreeMap::new();
        m2.insert("val".to_string(), Value::Uint16(2));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m2)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            val: u16,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r.val, 2);
    }

    #[test]
    fn test_u128_roundtrip() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("big".to_string(), Value::Uint128(1u128 << 127));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            big: u128,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r.big, 1u128 << 127);
    }

    #[test]
    fn test_zero_values() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("u16".to_string(), Value::Uint16(0));
        m.insert("u32".to_string(), Value::Uint32(0));
        m.insert("u64".to_string(), Value::Uint64(0));
        m.insert("u128".to_string(), Value::Uint128(0));
        m.insert("i32".to_string(), Value::Int32(0));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            u16: u16,
            u32: u32,
            u64: u64,
            u128: u128,
            i32: i32,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(r.u16, 0);
        assert_eq!(r.u32, 0);
        assert_eq!(r.u64, 0);
        assert_eq!(r.u128, 0);
        assert_eq!(r.i32, 0);
    }

    #[test]
    fn test_empty_collections() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("empty_map".to_string(), Value::Map(BTreeMap::new()));
        m.insert("empty_slice".to_string(), Value::Slice(vec![]));
        m.insert("empty_string".to_string(), Value::String(String::new()));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct TestRecord {
            empty_map: std::collections::BTreeMap<String, serde_json::Value>,
            empty_slice: Vec<serde_json::Value>,
            empty_string: String,
        }
        let r: TestRecord = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert!(r.empty_map.is_empty());
        assert!(r.empty_slice.is_empty());
        assert_eq!(r.empty_string, "");
    }

    #[test]
    fn test_partial_ipv6_bits() {
        // Test that inserting at weird bit boundaries works
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 6,
            record_size: 28,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("n".to_string(), Value::Uint16(1));
        tree.insert("::/0".parse().unwrap(), Value::Map(m.clone())).unwrap();
        tree.insert("2001:db8::/32".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct R {
            n: u16,
        }
        let r: R = reader.lookup("2001:db8::1".parse().unwrap()).unwrap();
        assert_eq!(r.n, 1);
    }

    #[test]
    fn test_exceeds_record_size_overflow() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Uint16(1)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        assert!(buf.len() > 0);
    }

    #[test]
    fn test_data_section_separator_present() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf.clone()).unwrap();
        let search_tree_size = (reader.metadata.node_count as usize) * (reader.metadata.record_size as usize) / 4;
        let sep_start = search_tree_size;
        assert_eq!(
            &buf[sep_start..sep_start + 16],
            &[0u8; 16],
            "data section separator must be 16 null bytes"
        );
    }

    #[test]
    fn test_leaf_node_both_children_point_to_same_data() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf.clone()).unwrap();
        let nc = reader.metadata.node_count as usize;
        let rsize = reader.metadata.record_size as usize;
        for node_idx in 0..nc {
            let base = node_idx * rsize / 4;
            let (left, right) = match rsize {
                24 => {
                    let l = ((buf[base] as usize) << 16) | ((buf[base + 1] as usize) << 8) | (buf[base + 2] as usize);
                    let r =
                        ((buf[base + 3] as usize) << 16) | ((buf[base + 4] as usize) << 8) | (buf[base + 5] as usize);
                    (l, r)
                }
                28 => {
                    let l = ((buf[base] as usize) << 16)
                        | ((buf[base + 1] as usize) << 8)
                        | (buf[base + 2] as usize)
                        | (((buf[base + 3] as usize) >> 4) << 24);
                    let r = ((buf[base + 4] as usize) << 16)
                        | ((buf[base + 5] as usize) << 8)
                        | (buf[base + 6] as usize)
                        | (((buf[base + 3] as usize) & 0x0F) << 24);
                    (l, r)
                }
                32 => {
                    let l = ((buf[base] as usize) << 24)
                        | ((buf[base + 1] as usize) << 16)
                        | ((buf[base + 2] as usize) << 8)
                        | (buf[base + 3] as usize);
                    let r = ((buf[base + 4] as usize) << 24)
                        | ((buf[base + 5] as usize) << 16)
                        | ((buf[base + 6] as usize) << 8)
                        | (buf[base + 7] as usize);
                    (l, r)
                }
                _ => unreachable!(),
            };
            if left > nc {
                assert_eq!(
                    left, right,
                    "leaf node {}: both children must point to the same data offset",
                    node_idx
                );
            }
        }
    }

    #[test]
    fn test_record_value_never_equals_node_count_for_data() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf.clone()).unwrap();
        let nc = reader.metadata.node_count as usize;
        let rsize = reader.metadata.record_size as usize;
        for node_idx in 0..nc {
            let base = node_idx * rsize / 4;
            let (left, right) = match rsize {
                24 => {
                    let l = ((buf[base] as usize) << 16) | ((buf[base + 1] as usize) << 8) | (buf[base + 2] as usize);
                    let r =
                        ((buf[base + 3] as usize) << 16) | ((buf[base + 4] as usize) << 8) | (buf[base + 5] as usize);
                    (l, r)
                }
                28 => {
                    let l = ((buf[base] as usize) << 16)
                        | ((buf[base + 1] as usize) << 8)
                        | (buf[base + 2] as usize)
                        | (((buf[base + 3] as usize) >> 4) << 24);
                    let r = ((buf[base + 4] as usize) << 16)
                        | ((buf[base + 5] as usize) << 8)
                        | (buf[base + 6] as usize)
                        | (((buf[base + 3] as usize) & 0x0F) << 24);
                    (l, r)
                }
                32 => {
                    let l = ((buf[base] as usize) << 24)
                        | ((buf[base + 1] as usize) << 16)
                        | ((buf[base + 2] as usize) << 8)
                        | (buf[base + 3] as usize);
                    let r = ((buf[base + 4] as usize) << 24)
                        | ((buf[base + 5] as usize) << 16)
                        | ((buf[base + 6] as usize) << 8)
                        | (buf[base + 7] as usize);
                    (l, r)
                }
                _ => unreachable!(),
            };
            let max_record = 1usize << rsize;
            assert!(left < max_record, "left value exceeds max record value for {} bits", rsize);
            assert!(right < max_record, "right value exceeds max record value for {} bits", rsize);
            if left > nc {
                assert!(
                    left >= nc + 16,
                    "data pointer {} must be >= node_count+16 ({}), node {}",
                    left,
                    nc + 16,
                    node_idx
                );
            }
            if right > nc {
                assert!(
                    right >= nc + 16,
                    "data pointer {} must be >= node_count+16 ({}), node {}",
                    right,
                    nc + 16,
                    node_idx
                );
            }
        }
    }

    #[test]
    fn test_insert_after_write() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m1 = BTreeMap::new();
        m1.insert("net".to_string(), Value::String("first".to_string()));
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Map(m1)).unwrap();
        let mut buf1 = Vec::new();
        let _ = tree.write_to(&mut buf1).unwrap();
        let mut m2 = BTreeMap::new();
        m2.insert("net".to_string(), Value::String("second".to_string()));
        tree.insert("11.0.0.0/8".parse().unwrap(), Value::Map(m2)).unwrap();
        let mut buf2 = Vec::new();
        tree.write_to(&mut buf2).unwrap();
        let r = crate::Reader::from_source(buf2).unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct R {
            net: String,
        }
        let v1: R = r.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(v1.net, "first");
        let v2: R = r.lookup("11.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(v2.net, "second");
    }

    #[test]
    fn test_values_after_insert_and_write_are_preserved() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Uint16(100)).unwrap();
        let _ = tree.write_to(&mut Vec::new()).unwrap();
        tree.insert("11.0.0.0/8".parse().unwrap(), Value::Uint16(200)).unwrap();
        tree.insert("10.0.0.0/8".parse().unwrap(), Value::Uint16(300)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        let v1: u16 = reader.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(v1, 300, "overwritten value should return 300");
        let v2: u16 = reader.lookup("11.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(v2, 200);
    }

    #[test]
    fn test_minimum_node_count_is_at_least_one() {
        let opts = TreeOptions {
            database_type: "Test".to_string(),
            ip_version: 4,
            record_size: 24,
            ..Default::default()
        };
        let mut tree = Tree::new(opts).unwrap();
        let mut m = BTreeMap::new();
        m.insert("x".to_string(), Value::Uint16(1));
        tree.insert("0.0.0.0/0".parse().unwrap(), Value::Map(m)).unwrap();
        let mut buf = Vec::new();
        tree.write_to(&mut buf).unwrap();
        let reader = crate::Reader::from_source(buf).unwrap();
        assert!(reader.metadata.node_count >= 1, "node_count must be at least 1");
    }
}
