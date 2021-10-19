// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Base CLI implementation.

use crate::common::{PROJECT_AUTHOR, PROJECT_DESC, PROJECT_NAME, PROJECT_VERSION};
use crate::subcommands::Subcommand;
use structopt::StructOpt;

/// Struct representing the command-line interface of cpk-tool
#[derive(Debug, StructOpt)]
#[structopt(name=PROJECT_NAME, about=PROJECT_DESC, author=PROJECT_AUTHOR, version=PROJECT_VERSION)]
pub struct CpkToolApp {
    /// The subcommand -- e.g., build or install
    #[structopt(subcommand)]
    pub subcommand: Subcommand,
}
