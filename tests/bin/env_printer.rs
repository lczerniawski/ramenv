use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("--exit-code") {
        let code = args
            .get(2)
            .expect("missing exit code")
            .parse()
            .expect("invalid exit code");
        std::process::exit(code);
    }
    if args.len() < 2 {
        eprintln!("No environment variables specified to check");
        std::process::exit(1);
    }

    for var_name in &args[1..] {
        match env::var(var_name) {
            Ok(val) => println!("{var_name}={val}"),
            Err(_) => println!("{var_name}=NOT_SET"),
        }
    }
}
