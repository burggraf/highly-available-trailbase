use hat::{config, controller, proxy};
use std::io::{self, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args();
    let _program = args.next();
    match (args.next().as_deref(), args.next().as_deref()) {
        (Some("config"), Some("check")) if args.next().is_none() => config_check(),
        (Some("doctor"), None) => doctor_check(),
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
            eprintln!("usage: hat config check | hat doctor | proxy serve --listen HOST:PORT | node status | controller status | controller serve --listen HOST:PORT --journal PATH --origin ORIGIN --config PATH --node-id NODE | controller account add --journal PATH --account NAME");
            ExitCode::from(2)
        }
    }
}

fn read_config() -> Result<config::Config, ()> {
    let mut input = Vec::new();
    if io::stdin()
        .take((config::CONFIG_LIMIT + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > config::CONFIG_LIMIT
    {
        return Err(());
    }
    let input = String::from_utf8(input).map_err(|_| ())?;
    config::Config::from_json(&input).map_err(|_| ())
}

fn config_check() -> ExitCode {
    match read_config() {
        Ok(_) => {
            println!("configuration valid");
            ExitCode::SUCCESS
        }
        Err(()) => {
            eprintln!("invalid configuration");
            ExitCode::from(2)
        }
    }
}

fn doctor_check() -> ExitCode {
    match read_config() {
        Ok(_) => {
            println!("doctor: configuration valid");
            ExitCode::SUCCESS
        }
        Err(()) => {
            eprintln!("doctor refused");
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
    let usage = "usage: hat controller serve --listen HOST:PORT --journal PATH --origin ORIGIN --config PATH --node-id NODE";
    let mut listen = None;
    let mut journal = None;
    let mut origin = None;
    let mut config_path = None;
    let mut node_id = None;
    while let Some(argument) = args.next() {
        let Some(value) = args.next() else {
            eprintln!("{usage}");
            return ExitCode::from(2);
        };
        match argument.as_str() {
            "--listen" => listen = value.parse::<SocketAddr>().ok(),
            "--journal" => journal = Some(value),
            "--origin" => origin = Some(value),
            "--config" => config_path = Some(value),
            "--node-id" => node_id = Some(value),
            _ => {
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(listen), Some(journal), Some(origin)) = (listen, journal, origin) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let (cluster, local_node_id) = match config_path {
        Some(path) => {
            let Some(node_id) = node_id else {
                eprintln!("{usage}");
                return ExitCode::from(2);
            };
            let config = match std::fs::read(&path)
                .ok()
                .filter(|bytes| bytes.len() <= config::CONFIG_LIMIT)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .and_then(|input| config::Config::from_json(&input).ok())
            {
                Some(config) => config,
                None => {
                    eprintln!("controller configuration unavailable");
                    return ExitCode::from(2);
                }
            };
            if config.node(&node_id).is_none() {
                eprintln!("controller node unavailable");
                return ExitCode::from(2);
            }
            (controller::ClusterView::from_config(&config), Some(node_id))
        }
        None => {
            if node_id.is_some() {
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
            (controller::ClusterView::empty(), None)
        }
    };
    let controller = match controller::Controller::open(journal, "controller-process") {
        Ok(controller) => controller,
        Err(_) => {
            eprintln!("controller journal unavailable");
            return ExitCode::from(2);
        }
    };
    match controller::serve_dashboard_with_cluster(
        listen,
        controller,
        &origin,
        cluster,
        local_node_id.as_deref(),
    )
    .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
