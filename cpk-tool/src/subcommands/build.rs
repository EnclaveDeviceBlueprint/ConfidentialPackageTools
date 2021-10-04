// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Builds a confidential package from a compiled application binary and
//! a given set of inputs to control signing and encryption.

use crate::error::{Error, Result, ToolErrorKind};
use crate::prototype::builder::simple_build_from_payload;
use crate::util::get_config_from_command_or_env;

use cpk::keys::file::FileKeySource;
use cpk::keys::http::WebContractKeySource;
use cpk::keys::local::LocalMemoryKeyPair;
use cpk::keys::parsec::ParsecKeyPair;
use cpk::keys::EncryptionKeySource;

use structopt::StructOpt;

/// Models the options required by the build command.
#[derive(Debug, StructOpt)]
pub struct Build {
    /// The primary input file, which contains the content that needs to be packaged
    /// by the build process.
    #[structopt(short = "i", long = "input-payload")]
    input_payload: String,

    /// The output file, which will contain the built package once the process
    /// completes.
    #[structopt(short = "o", long = "output-package")]
    output_package: String,

    /// The identity of the application whose class key will be used for encryption. This would
    /// typically be a UUID in string form, although it can be any suitable identifier provided that
    /// a class encryption key with this name is contained in the referenced key store.
    #[structopt(short = "a", long = "application-id")]
    application_id: String,

    /// The encryption key method to use, either "http" or "file".
    #[structopt(short = "e", long = "encryption-key-method")]
    encryption_key_method: String,

    /// The human-readable name of the application.
    #[structopt(short = "n", long = "application-name", default_value = "Unknown")]
    application_name: String,

    /// The vendor or service provider identifier string.
    #[structopt(short = "v", long = "vendor", default_value = "Unknown")]
    vendor: String,

    /// The address of the key store. This argument is optional, and it's interpretation depends
    /// on the encryption key method.
    ///
    /// When the encryption key method is `http`, this argument should be the URL
    /// of an API endpoint that implements the Confidential Package Key Wrapping protocol. If it is
    /// omitted from the command-line, then this URL will be read from the
    /// `CP_CLOUD_KEY_SOURCE` environment variable instead. If it is not specified there either, then the
    /// command will fail.
    ///
    /// When the encryption key method is `file`, this argument should be the path to an existing
    /// file on disk, containing the key data in JSON format. File-based key stores are intended for
    /// local test environments only. If this argument is omitted from the command-line, it will
    /// be resolved from the CP_FILE_KEY_SOURCE environment variable instead. If it is not specified
    /// there either, then the command will fail.
    #[structopt(short = "k", long = "key-store")]
    key_store: Option<String>,

    /// The wrapping key method to use: either "local" or "parsec".
    #[structopt(short = "w", long = "wrapping-key-method")]
    wrapping_key_method: String,
}

impl Build {
    /// Builds the package with the given encryption key source.
    fn build_with_encryption_key_source<S : EncryptionKeySource>(&self, eks: &S) -> Result<()> {
        match self.wrapping_key_method.as_str() {
            "local" => {
                println!("WARNING: Local memory RSA wrapping keys should only be used in dev/test environments.");
                println!("         Consider using Parsec to manage the wrapping key using the best-available security facilities of your platform.");
                let local_wrapping = LocalMemoryKeyPair::default();
                simple_build_from_payload(
                    &self.application_id,
                    &self.application_name,
                    &self.vendor,
                    &self.input_payload,
                    &self.output_package,
                    eks,
                    &local_wrapping,
                )
            },
            "parsec" => {
                let parsec_wrapping = ParsecKeyPair::default();
                simple_build_from_payload(
                    &self.application_id,
                    &self.application_name,
                    &self.vendor,
                    &self.input_payload,
                    &self.output_package,
                    eks,
                    &parsec_wrapping,
                )
            },
            _ => Err(Error::ToolError(ToolErrorKind::InvalidWrappingKeySource)),
        }
    }

    /// Builds the confidential package from the given inputs.
    pub fn run(&self) -> Result<()> {
        match self.encryption_key_method.as_str() {
            "http" => {
                let endpoint = get_config_from_command_or_env(
                    &self.key_store,
                    "CP_CLOUD_KEY_SOURCE",
                    "HTTP key store endpoint",
                )?;
                let wks = WebContractKeySource::from_endpoint_uri(&endpoint);
                self.build_with_encryption_key_source(&wks)
            },
            "file" => {
                let path = get_config_from_command_or_env(
                    &self.key_store,
                    "CP_FILE_KEY_SOURCE",
                    "key store file path",
                )?;
                let fks = FileKeySource::from_file_path(&path)?;
                self.build_with_encryption_key_source(&fks)
            },
            _ => Err(Error::ToolError(ToolErrorKind::InvalidEncryptionKeySource)),
        }
    }
}
