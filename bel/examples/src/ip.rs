use bel::{Context, Program};

fn main() {
    let program = Program::compile(r#"Ip("127.0.0.1") == Ip("127.0.0.1/32")"#).unwrap();
    let context = Context::default();
    let result = program.execute(&context).unwrap();
    // assert_eq!(value, true.into());
    println!("{:?}", result);
}
