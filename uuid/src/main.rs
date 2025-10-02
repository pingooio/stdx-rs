use std::env;

use uuid;

fn print_usage(program: &str) {
    println!("Usage: {program} --v4|--v7 (default: v4");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];

    if args.len() > 2 {
        print_usage(&args[0]);
        return;
    }

    let version = args.get(1).map(AsRef::as_ref).unwrap_or("--v4");
    if version != "--v4" && version != "--v7" {
        print_usage(program);
        return;
    }

    let uuid = match version {
        "--v4" => uuid::Uuid::new_v4(),
        "--v7" => uuid::Uuid::new_v7(),
        _ => {
            print_usage(program);
            return;
        }
    };
    println!("{uuid}");
}
