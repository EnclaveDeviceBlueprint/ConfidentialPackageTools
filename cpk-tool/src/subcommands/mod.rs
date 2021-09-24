// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Individual commands supported by cpk-tool.

//! Subcommand implementations.

mod build;
mod install;
mod sync;

use crate::error::Result;
use crate::subcommands::{build::Build, install::Install, sync::Sync};

use structopt::StructOpt;

/// Command-line interface to cpk-tool operations.
#[derive(Debug, StructOpt)]
pub enum Subcommand {
    /// Builds a confidential package from a compiled application and a given
    /// set of inputs to control encryption and signing.
    Build(Build),

    /// Installs a confidential package on the host system from a given input file.
    Install(Install),

    /// Synchronizes an application class key into the Confidential Package Manager
    Sync(Sync),
}

impl Subcommand {
    /// Runs the command.
    pub fn run(&self) -> Result<()> {
        match &self {
            Subcommand::Build(cmd) => cmd.run(),
            Subcommand::Install(cmd) => cmd.run(),
            Subcommand::Sync(cmd) => cmd.run(),
        }
    }
}
