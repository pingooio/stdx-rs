# Better Expression Language (BEL)

BEL is a non-Turing complete language designed for simplicity, speed, and safety.

BEL is ideal for lightweight expression evaluation when a scripting language or a WASM module are too resource intensive.

```javascript
jwt.exp < now().unix()
```

```javascript
path.starts_with("/api") || path.matches(Regex("^/(admin|secret)"))
```

```javascript
headers.all(header, header.length() < 256)
```



## Usage

Add `bel` to your `Cargo.toml`:

```toml
[dependencies]
bel = { git = "https://github.com/bloom42/bel-rs", branch = "main" }
```

Create and execute a simple BEL expression:

```rust
use bel::{Context, Program};

fn main() {
    let program = Program::compile("add(40, 2) == 42").unwrap();
    let mut context = Context::default();
    context.add_function("add", |a: i64, b: i64| a + b);
    let value = program.execute(&context).unwrap();
    assert_eq!(value, true.into());
}
```

## Types

`String`

`Int`

`Float`

`Regex`

`Timestamp`

`Duration`


## Todo

Improve default functions in context.

## Resources

- https://medium.com/mixpaneleng/building-a-not-so-simple-expression-language-part-ii-scope-mixpanel-engineering-ba6a293786aa
- https://github.com/expr-lang/expr
- https://github.com/google/cel-spec/blob/master/doc/langdef.md
- https://github.com/google/cel-go
