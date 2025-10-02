#![no_main]

use std::hint::black_box;

use bel::Value;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    Cmp,
}

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    op: BinOp,
    lhs: Value,
    rhs: Value,
}

// Ensure that the binary operators on `Value` do not panic,
// c.f. https://github.com/bloom42/bel-rs/pull/145.
fuzz_target!(|input: Input| {
    match input.op {
        BinOp::Add => _ = black_box(input.lhs + input.rhs),
        BinOp::Sub => _ = black_box(input.lhs - input.rhs),
        BinOp::Mul => _ = black_box(input.lhs * input.rhs),
        BinOp::Div => _ = black_box(input.lhs / input.rhs),
        BinOp::Rem => _ = black_box(input.lhs % input.rhs),
        BinOp::Eq => _ = black_box(input.lhs == input.rhs),
        BinOp::Cmp => _ = black_box(input.lhs.partial_cmp(&input.rhs)),
    }
});
