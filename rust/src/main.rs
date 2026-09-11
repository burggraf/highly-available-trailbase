pub mod auth;
pub mod config;
pub mod controller;
pub mod journal;
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
        (Some("controller"), Some("status")) if args.next().is_none() => {
            println!("controller status: local journal required");
            ExitCode::SUCCESS
        }
        (Some("controller"), Some("serve")) => controller_serve(&mut args).await,
        (Some("controller"), Some("account")) => controller_account(&mut args),
        _ => {
            eprintln!("usage: hat config check | proxy serve --listen HOST:PORT | node status | controller status | controller serve --listen HOST:PORT --journal PATH --origin ORIGIN | controller account add --journal PATH --account NAME");
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

fn controller_account(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(action) = args.next() else {
        eprintln!("usage: hat controller account add|disable --journal PATH --account NAME");
        return ExitCode::from(2);
    };
    if !matches!(action.as_str(), "add" | "disable") {
        eprintln!("usage: hat controller account add|disable --journal PATH --account NAME");
        return ExitCode::from(2);
    }
    let mut journal = None;
    let mut account = None;
    while let Some(argument) = args.next() {
        let Some(value) = args.next() else {
            eprintln!("usage: hat controller account add --journal PATH --account NAME");
            return ExitCode::from(2);
        };
        match argument.as_str() {
            "--journal" => journal = Some(value),
            "--account" => account = Some(value),
            _ => {
                eprintln!("usage: hat controller account add --journal PATH --account NAME");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(journal), Some(account)) = (journal, account) else {
        eprintln!("usage: hat controller account add --journal PATH --account NAME");
        return ExitCode::from(2);
    };
    let mut controller = match controller::Controller::open(journal, "account-maintenance") {
        Ok(controller) => controller,
        Err(_) => {
            eprintln!("account refused");
            return ExitCode::from(2);
        }
    };
    if action == "disable" {
        return match controller.disable_account(&account) {
            Ok(()) => {
                println!("account disabled");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("account refused");
                ExitCode::from(2)
            }
        };
    }
    let mut password = Vec::new();
    if io::stdin()
        .take((config::CONFIG_LIMIT + 1) as u64)
        .read_to_end(&mut password)
        .is_err()
        || password.len() > config::CONFIG_LIMIT
    {
        eprintln!("account refused");
        return ExitCode::from(2);
    }
    let Ok(password) = String::from_utf8(password) else {
        eprintln!("account refused");
        return ExitCode::from(2);
    };
    let password = password.trim_end_matches(['\r', '\n']);
    match controller.create_account(&account, password) {
        Ok(()) => {
            println!("account created");
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("account refused");
            ExitCode::from(2)
        }
    }
}

async fn controller_serve(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let mut listen = None;
    let mut journal = None;
    let mut origin = None;
    while let Some(argument) = args.next() {
        let value = match args.next() {
            Some(value) => value,
            None => {
                eprintln!(
                    "usage: hat controller serve --listen HOST:PORT --journal PATH --origin ORIGIN"
                );
                return ExitCode::from(2);
            }
        };
        match argument.as_str() {
            "--listen" => listen = value.parse::<SocketAddr>().ok(),
            "--journal" => journal = Some(value),
            "--origin" => origin = Some(value),
            _ => {
                eprintln!(
                    "usage: hat controller serve --listen HOST:PORT --journal PATH --origin ORIGIN"
                );
                return ExitCode::from(2);
            }
        }
    }
    let (Some(listen), Some(journal), Some(origin)) = (listen, journal, origin) else {
        eprintln!("usage: hat controller serve --listen HOST:PORT --journal PATH --origin ORIGIN");
        return ExitCode::from(2);
    };
    let controller = match controller::Controller::open(journal, "controller-process") {
        Ok(controller) => controller,
        Err(_) => {
            eprintln!("controller journal unavailable");
            return ExitCode::from(2);
        }
    };
    match controller::serve_dashboard(listen, controller, &origin).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
