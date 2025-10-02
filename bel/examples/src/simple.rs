use bel::{Context, Program};

fn main() {
    let program = Program::compile(
        r#"
    1 == 1 && "abc".matches(Regex("^[a-z]+$"))"#,
    )
    .unwrap();
    let context = Context::default();
    let result = program.execute(&context).unwrap();
    // assert_eq!(value, true.into());
    println!("{:?}", result);
}
