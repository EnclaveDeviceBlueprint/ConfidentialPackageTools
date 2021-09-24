// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Synchronizes the class key from its cloud-based key source into the locally-running
//! Confidential Package Manager (CPM).

use crate::error::Result;
use structopt::StructOpt;

/// Models the options required by the sync command.
#[derive(Debug, StructOpt)]
pub struct Sync {
    /// The output file, which will contain the built package once the process
    /// completes.
    #[structopt(short = "s", long = "source")]
    source: String,
}

impl Sync {
    /// Synchronizes the class key for a given application identity from its cloud-based key source
    /// into the locally-running Confidential Package Manager (CPM).
    pub fn run(&self) -> Result<()> {
        println!("Congratulations! You have called the sync command!");

        Ok(())
    }
}
