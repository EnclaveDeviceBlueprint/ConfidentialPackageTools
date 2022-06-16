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

#[cfg(feature = "sync")]
mod pubkey;

use crate::error::Result;

#[cfg(feature = "build")]
use crate::subcommands::build::Build;

#[cfg(feature = "install")]
use crate::subcommands::install::Install;

#[cfg(feature = "sync")]
use crate::subcommands::sync::Sync;

#[cfg(feature = "sync")]
use crate::subcommands::pubkey::PubKey;

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

    /// Obtains the public part of the device key pair from the Confidential Package Manager on
    /// the local host, and writes it to the console as a base64-encoded SubjectPublicKeyInfo
    /// structure, which is compatible with cloud-based key synchronization mechanisms.
    #[cfg(feature = "sync")]
    PubKey(PubKey),
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
            #[cfg(feature = "sync")]
            Subcommand::PubKey(cmd) => cmd.run(),
            #[cfg(not(any(feature = "build", feature = "install", feature = "sync")))]
            _ => Ok(()),
        }
    }
}
