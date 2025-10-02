use std::{collections::HashMap, sync::LazyLock};

use serde::{Deserialize, Serialize};

pub const UNKNOWN_CODE: &str = "XX";
pub const UNKNOWN: &str = "Unknown";

const COUNTRIES_JSON: &[u8] = include_bytes!("./assets/countries.json");

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Country {
    pub code: String,
    pub name: String,
}

impl Default for Country {
    fn default() -> Self {
        Self {
            code: String::from(UNKNOWN_CODE),
            name: String::from(UNKNOWN),
        }
    }
}

static COUNTRIES: LazyLock<HashMap<String, Country>> = LazyLock::new(|| {
    let countries: Vec<Country> = serde_json::from_slice(COUNTRIES_JSON)
        .unwrap_or_else(|err| panic!("countries: error parsing countries JSON: {err}"));

    return countries
        .iter()
        .map(|country| (country.code.clone(), country.clone()))
        .collect();
});

pub fn countries() -> &'static HashMap<String, Country> {
    &COUNTRIES
}

pub fn name(code: &str) -> String {
    let countries = countries();
    return countries
        .get(code)
        .map(|country| country.clone())
        .unwrap_or_default()
        .name;
}
