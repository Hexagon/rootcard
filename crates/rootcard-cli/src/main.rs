//! The `rootcard` key tool. Status: skeleton (phase 0); the commands arrive in phase 5 of the plan.

use std::process::ExitCode;

const USAGE: &str = "rootcard - the key tool for rootcard identities

USAGE:
    rootcard <COMMAND>

COMMANDS:
    version    Print the tool and format versions
    help       Print this help

The identity commands (new, card, add-password, revoke-password, restore, fresh,
rotate-recovery, retire, inspect, verify, prove) are not implemented yet.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("help" | "--help" | "-h") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("version" | "--version" | "-V") => {
            println!(
                "rootcard {} (format v{})",
                env!("CARGO_PKG_VERSION"),
                rootcard::FORMAT_VERSION
            );
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
