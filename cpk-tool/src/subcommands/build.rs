//! Builds a confidential package from a compiled application binary and
//! a given set of inputs to control signing and encryption.

use crate::error::Result;
use structopt::StructOpt;

/// Models the options required by the build command.
#[derive(Debug, StructOpt)]
pub struct Build {
    /// The output file, which will contain the built package once the process
    /// completes.
    #[structopt(short = "o", long = "out-file")]
    output_file: String,
}

impl Build {
    /// Builds the confidential package from the given inputs.
    pub fn run(&self) -> Result<()> {
        println!("Congratulations! You have called the build command!");

        Ok(())
    }
}
