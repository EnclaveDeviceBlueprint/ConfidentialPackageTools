//! Installs a confidential package on the host system from the given
//! input file.

use crate::error::Result;
use structopt::StructOpt;

/// Models the options required by the install command.
#[derive(Debug, StructOpt)]
pub struct Install {
    /// The input file, which must be a binary confidential package file.
    #[structopt(short = "p", long = "package")]
    output_file: String,
}

impl Install {
    /// Installs the confidential package on the host system from the given
    /// input file.
    pub fn run(&self) -> Result<()> {
        println!("Congratulations! You have called the install command!");

        Ok(())
    }
}
