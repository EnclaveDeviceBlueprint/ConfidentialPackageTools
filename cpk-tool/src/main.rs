//! cpk-tool: a tool for building and installing confidential packages

use log::error;
use structopt::StructOpt;
use cpk_tool::cli;

fn main() {
    let mut env_log_builder = env_logger::Builder::new();
    // By default, only show the logs from this crate.
    env_log_builder.filter_level(log::LevelFilter::Info);
    env_log_builder.format_timestamp(None);
    env_log_builder.format_module_path(false);

    // Allows to still set configuration via the default environment variable
    env_log_builder.parse_default_env();
    env_log_builder.init();

    let matches = cli::CpkToolApp::from_args();

    if let Err(e) = matches.subcommand.run() {
        error!("Command failed: {} ({:?})", e, e);
        std::process::exit(1);
    }

    std::process::exit(0);
}
