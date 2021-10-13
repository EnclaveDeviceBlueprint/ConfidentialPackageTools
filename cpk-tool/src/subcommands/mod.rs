// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Individual commands supported by cpk-tool.

//! Subcommand implementations.

#[cfg(feature = "build")]
mod build;

#[cfg(feature = "install")]
mod install;

#[cfg(feature = "sync")]
mod sync;

use crate::error::Result;

#[cfg(feature = "build")]
use crate::subcommands::build::Build;

#[cfg(feature = "install")]
use crate::subcommands::install::Install;

#[cfg(feature = "sync")]
use crate::subcommands::sync::Sync;

use structopt::StructOpt;

/// Command-line interface to cpk-tool operations.
#[derive(Debug, StructOpt)]
pub enum Subcommand {
    /// Builds a confidential package from a compiled application and a given
    /// set of inputs to control encryption and signing.
    #[cfg(feature = "build")]
    Build(Build),

    /// Installs a confidential package on the host system from a given input file.
    #[cfg(feature = "install")]
    Install(Install),

    /// Synchronizes an application class key into the Confidential Package Manager
    #[cfg(feature = "sync")]
    Sync(Sync),
}

impl Subcommand {
    /// Runs the command.
    pub fn run(&self) -> Result<()> {
        match &self {
            #[cfg(feature = "build")]
            Subcommand::Build(cmd) => cmd.run(),
            #[cfg(feature = "install")]
            Subcommand::Install(cmd) => cmd.run(),
            #[cfg(feature = "sync")]
            Subcommand::Sync(cmd) => cmd.run(),
            #[cfg(not(any(feature = "build", feature = "install", feature = "sync")))]
            _ => Ok(())
        }
    }
}
