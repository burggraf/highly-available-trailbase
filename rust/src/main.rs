pub mod config;
pub mod node;
pub mod proxy;
pub mod replication;
pub mod routing;

use std::io::{self, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args();
    let _program = args.next();
    match (args.next().as_deref(), args.next().as_deref()) {
        (Some("config"), Some("check")) if args.next().is_none() => config_check(),
        (Some("proxy"), Some("serve")) => proxy_serve(&mut args).await,
        (Some("node"), Some("status")) if args.next().is_none() => {
            println!("node status: admission closed");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: hat config check | proxy serve --listen HOST:PORT | node status");
            ExitCode::from(2)
        }
    }
}

fn config_check() -> ExitCode {
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

async fn proxy_serve(args: &mut impl Iterator<Item = String>) -> ExitCode {
    if args.next().as_deref() != Some("--listen") {
        eprintln!("usage: hat proxy serve --listen HOST:PORT");
        return ExitCode::from(2);
    }
    let Some(listen) = args.next() else {
        eprintln!("usage: hat proxy serve --listen HOST:PORT");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: hat proxy serve --listen HOST:PORT");
        return ExitCode::from(2);
    }
    let Ok(listen) = listen.parse::<SocketAddr>() else {
        eprintln!("invalid proxy listen address");
        return ExitCode::from(2);
    };
    let mut input = Vec::new();
    if io::stdin()
        .take((config::CONFIG_LIMIT + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > config::CONFIG_LIMIT
    {
        eprintln!("invalid proxy input");
        return ExitCode::from(2);
    }
    let Ok(input) = String::from_utf8(input) else {
        eprintln!("invalid proxy input");
        return ExitCode::from(2);
    };
    match proxy::serve(listen, &input).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
