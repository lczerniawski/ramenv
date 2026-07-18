use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
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
