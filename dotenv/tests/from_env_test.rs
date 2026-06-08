use dotenv::{FromEnv, FromEnvError, FromEnvValue};

#[derive(Debug, FromEnv)]
struct SimpleConfig {
    #[env(rename = "TEST_FE_HOST")]
    host: String,
    #[env(rename = "TEST_FE_PORT")]
    port: u16,
}

#[test]
fn from_env_simple() {
    unsafe { std::env::set_var("TEST_FE_HOST", "localhost") };
    unsafe { std::env::set_var("TEST_FE_PORT", "8080") };

    let cfg = SimpleConfig::from_env().unwrap();
    assert_eq!(cfg.host, "localhost");
    assert_eq!(cfg.port, 8080);

    unsafe { std::env::remove_var("TEST_FE_HOST") };
    unsafe { std::env::remove_var("TEST_FE_PORT") };
}

#[test]
fn from_env_missing_var() {
    unsafe { std::env::remove_var("TEST_FE_HOST") };
    unsafe { std::env::remove_var("TEST_FE_PORT") };

    let err = SimpleConfig::from_env().unwrap_err();
    match &err {
        FromEnvError::Missing(var) => assert_eq!(var, "TEST_FE_HOST"),
        _ => panic!("expected Missing, got {err:?}"),
    }
}

#[test]
fn from_env_invalid_value() {
    unsafe { std::env::set_var("TEST_FE_HOST", "localhost") };
    unsafe { std::env::set_var("TEST_FE_PORT", "not_a_number") };

    let err = SimpleConfig::from_env().unwrap_err();
    match &err {
        FromEnvError::Invalid {
            var, ..
        } => assert_eq!(var, "TEST_FE_PORT"),
        _ => panic!("expected Invalid, got {err:?}"),
    }

    unsafe { std::env::remove_var("TEST_FE_HOST") };
    unsafe { std::env::remove_var("TEST_FE_PORT") };
}

// ── default / default = expr ─────────────────────────────────────────────

#[derive(Debug, FromEnv)]
struct WithDefault {
    #[env(rename = "TEST_WD_HOST")]
    host: String,
    #[env(default)]
    port: Option<u16>,
}

#[test]
fn from_env_with_default() {
    unsafe { std::env::set_var("TEST_WD_HOST", "example.com") };
    unsafe { std::env::remove_var("TEST_WD_PORT") };

    let cfg = WithDefault::from_env().unwrap();
    assert_eq!(cfg.host, "example.com");
    assert_eq!(cfg.port, None);

    unsafe { std::env::remove_var("TEST_WD_HOST") };
}

#[derive(Debug, FromEnv)]
struct WithDefaultExpr {
    #[env(rename = "TEST_WDE_HOST")]
    host: String,
    #[env(default = 3000)]
    port: u16,
}

#[test]
fn from_env_with_default_expr() {
    unsafe { std::env::set_var("TEST_WDE_HOST", "example.com") };

    let cfg = WithDefaultExpr::from_env().unwrap();
    assert_eq!(cfg.host, "example.com");
    assert_eq!(cfg.port, 3000);

    unsafe { std::env::remove_var("TEST_WDE_HOST") };
}

// ── rename + default / rename + default = expr ───────────────────────────

#[derive(Debug, FromEnv)]
struct RenameDefaultStandard {
    #[env(rename = "TEST_RDS_PORT", default)]
    port: u16,
    #[env(rename = "TEST_RDS_HOST")]
    host: String,
}

#[test]
fn from_env_rename_default_standard() {
    unsafe { std::env::set_var("TEST_RDS_HOST", "example.com") };
    unsafe { std::env::remove_var("TEST_RDS_PORT") };

    let cfg = RenameDefaultStandard::from_env().unwrap();
    assert_eq!(cfg.host, "example.com");
    assert_eq!(cfg.port, 0);

    unsafe { std::env::set_var("TEST_RDS_PORT", "8080") };

    let cfg = RenameDefaultStandard::from_env().unwrap();
    assert_eq!(cfg.port, 8080);

    unsafe { std::env::remove_var("TEST_RDS_PORT") };
    unsafe { std::env::remove_var("TEST_RDS_HOST") };
}

#[derive(Debug, FromEnv)]
struct RenameDefaultExpr {
    #[env(rename = "TEST_RDE_PORT", default = 3000)]
    port: u16,
    #[env(rename = "TEST_RDE_HOST")]
    host: String,
}

#[test]
fn from_env_rename_default_expr() {
    unsafe { std::env::set_var("TEST_RDE_HOST", "example.com") };
    unsafe { std::env::remove_var("TEST_RDE_PORT") };

    let cfg = RenameDefaultExpr::from_env().unwrap();
    assert_eq!(cfg.port, 3000);
    assert_eq!(cfg.host, "example.com");

    unsafe { std::env::set_var("TEST_RDE_PORT", "9090") };

    let cfg = RenameDefaultExpr::from_env().unwrap();
    assert_eq!(cfg.port, 9090);

    unsafe { std::env::remove_var("TEST_RDE_PORT") };
    unsafe { std::env::remove_var("TEST_RDE_HOST") };
}

// ── all defaults (no env vars needed) ────────────────────────────────────

#[derive(Debug, FromEnv)]
struct AllDefaults {
    #[env(default)]
    flag: Option<bool>,
    #[env(default = 42)]
    answer: u32,
    #[env(default)]
    name: String,
}

#[test]
fn from_env_all_defaults() {
    let cfg = AllDefaults::from_env().unwrap();
    assert_eq!(cfg.flag, None);
    assert_eq!(cfg.answer, 42);
    assert_eq!(cfg.name, "");
}

// ── empty struct ─────────────────────────────────────────────────────────

#[derive(Debug, FromEnv)]
struct EmptyStruct {}

#[test]
fn from_env_empty_struct() {
    let cfg = EmptyStruct::from_env().unwrap();
    let _ = cfg;
}

// ── with (custom parser) ─────────────────────────────────────────────────

fn parse_u16_from_env(var: &str, val: &str) -> Result<u16, FromEnvError> {
    val.parse::<u16>()
        .map_err(|e| FromEnvError::invalid(var, val, e.to_string()))
}

#[derive(Debug, FromEnv)]
struct WithCustomParser {
    #[env(rename = "TEST_WCP_NUM", with = "parse_u16_from_env")]
    num: u16,
    #[env(rename = "TEST_WCP_OTHER")]
    other: String,
}

#[test]
fn from_env_with_custom_parser() {
    unsafe { std::env::set_var("TEST_WCP_NUM", "42") };
    unsafe { std::env::set_var("TEST_WCP_OTHER", "hello") };

    let cfg = WithCustomParser::from_env().unwrap();
    assert_eq!(cfg.num, 42);
    assert_eq!(cfg.other, "hello");

    unsafe { std::env::remove_var("TEST_WCP_NUM") };
    unsafe { std::env::remove_var("TEST_WCP_OTHER") };
}

// ── nested struct with #[env(nested)] ────────────────────────────────────

#[derive(Debug, FromEnv)]
struct Database {
    #[env(rename = "TEST_DB_URL")]
    url: String,
    #[env(default = 5)]
    pool_size: u32,
}

#[derive(Debug, FromEnv)]
struct NestedConfig {
    database: Database,
    #[env(rename = "TEST_APP_DEBUG")]
    debug: bool,
}

#[test]
fn from_env_nested() {
    unsafe { std::env::set_var("TEST_DB_URL", "postgres://localhost/mydb") };
    unsafe { std::env::set_var("TEST_APP_DEBUG", "true") };

    let cfg = NestedConfig::from_env().unwrap();
    assert_eq!(cfg.database.url, "postgres://localhost/mydb");
    assert_eq!(cfg.database.pool_size, 5);
    assert!(cfg.debug);

    unsafe { std::env::remove_var("TEST_DB_URL") };
    unsafe { std::env::remove_var("TEST_APP_DEBUG") };
}

// ── deeply nested with prefix propagation ────────────────────────────────

#[derive(Debug, FromEnv)]
struct DeepChild {
    key: String,
}

#[derive(Debug, FromEnv)]
struct Middle {
    child: DeepChild,
}

#[derive(Debug, FromEnv)]
struct Root {
    middle: Middle,
}

#[test]
fn from_env_deeply_nested() {
    unsafe { std::env::set_var("MIDDLE_CHILD_KEY", "deep-value") };

    let cfg = Root::from_env().unwrap();
    assert_eq!(cfg.middle.child.key, "deep-value");

    unsafe { std::env::remove_var("MIDDLE_CHILD_KEY") };
}

// ── with (custom parser) without rename → uses field-based prefix ────────

fn parse_debug_flag(var: &str, val: &str) -> Result<bool, FromEnvError> {
    match val {
        "1" | "yes" | "true" => Ok(true),
        "0" | "no" | "false" => Ok(false),
        _ => Err(FromEnvError::invalid(var, val, format!("unexpected value: {val}"))),
    }
}

#[derive(Debug, FromEnv)]
struct NestedWithPrefix {
    #[env(with = "parse_debug_flag")]
    debug_flag: bool,
}

#[derive(Debug, FromEnv)]
struct ParentOfWith {
    #[env(rename = "TEST_PARENT_DEBUG")]
    debug: bool,
    nested: NestedWithPrefix,
}

#[test]
fn from_env_with_without_rename_uses_prefix() {
    unsafe { std::env::set_var("TEST_PARENT_DEBUG", "true") };
    unsafe { std::env::set_var("NESTED_DEBUG_FLAG", "yes") };

    let cfg = ParentOfWith::from_env().unwrap();
    assert!(cfg.debug);
    assert!(cfg.nested.debug_flag);

    unsafe { std::env::remove_var("TEST_PARENT_DEBUG") };
    unsafe { std::env::remove_var("NESTED_DEBUG_FLAG") };
}

// ── custom parser with missing env var ──────────────────────────────────

#[derive(Debug, FromEnv)]
struct WithCustomParserMissing {
    #[env(rename = "TEST_WCP_MISSING", with = "parse_u16_from_env")]
    _num: u16,
}

#[test]
fn from_env_with_custom_parser_missing_var() {
    unsafe { std::env::remove_var("TEST_WCP_MISSING") };

    let err = WithCustomParserMissing::from_env().unwrap_err();
    match &err {
        FromEnvError::Missing(var) => assert_eq!(var, "TEST_WCP_MISSING"),
        _ => panic!("expected Missing, got {err:?}"),
    }
}

// ── FromEnvValue trait ───────────────────────────────────────────────────

#[test]
fn from_env_value_trait() {
    let s = <String as FromEnvValue>::from_env_value("hello".into()).unwrap();
    assert_eq!(s, "hello");

    let n = <u16 as FromEnvValue>::from_env_value("42".into()).unwrap();
    assert_eq!(n, 42);

    let b = <bool as FromEnvValue>::from_env_value("true".into()).unwrap();
    assert!(b);

    let err = <u16 as FromEnvValue>::from_env_value("not_a_number".into()).unwrap_err();
    assert!(!err.is_empty());
}

// ── FromEnvError Display ─────────────────────────────────────────────────

#[test]
fn from_env_error_display() {
    let e = FromEnvError::missing("MY_VAR");
    assert_eq!(e.to_string(), "environment variable `MY_VAR` is not set");

    let e = FromEnvError::invalid("PORT", "abc", "invalid digit");
    assert_eq!(
        e.to_string(),
        "environment variable `PORT` has invalid value `abc`: invalid digit"
    );
}

// ── dotenv::from_env free function ───────────────────────────────────────

#[test]
fn from_env_free_function() {
    unsafe { std::env::set_var("TEST_FE_HOST", "free-fn") };
    unsafe { std::env::set_var("TEST_FE_PORT", "9090") };

    let cfg: SimpleConfig = dotenv::from_env().unwrap();
    assert_eq!(cfg.host, "free-fn");
    assert_eq!(cfg.port, 9090);

    unsafe { std::env::remove_var("TEST_FE_HOST") };
    unsafe { std::env::remove_var("TEST_FE_PORT") };
}
