pub mod config;
pub mod routing;

use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args();
    let _program = args.next();
    if args.next().as_deref() != Some("config")
        || args.next().as_deref() != Some("check")
        || args.next().is_some()
    {
        eprintln!("usage: hat config check (JSON configuration on stdin)");
        return ExitCode::from(2);
    }

    let mut input = Vec::new();
    if io::stdin()
        .take((config::CONFIG_LIMIT + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > config::CONFIG_LIMIT
    {
        eprintln!("invalid configuration");
        return ExitCode::from(2);
    }
    let Ok(input) = String::from_utf8(input) else {
        eprintln!("invalid configuration");
        return ExitCode::from(2);
    };

    match config::Config::from_json(&input) {
        Ok(_) => {
            println!("configuration valid");
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("invalid configuration");
            ExitCode::from(2)
        }
    }
}
