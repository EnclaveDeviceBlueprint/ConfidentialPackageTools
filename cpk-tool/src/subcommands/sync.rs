// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Synchronizes the class key from its cloud-based key source into the locally-running
//! Confidential Package Manager (CPM).

use crate::error::{Error, Result, ToolErrorKind};

use crate::util::get_config_from_command_or_env;

use cpk::cpm::ConfidentialPackageManager;
use cpk::keys::file::FileKeySource;
use cpk::keys::http::WebContractKeySource;
use cpk::keys::EncryptionKeySource;

use structopt::StructOpt;

/// Models the options required by the sync command.
#[derive(Debug, StructOpt)]
pub struct Sync {
    /// The synchronization method to use, either "http", "file", "commandline" or "azuretwin".
    ///
    /// (Status note: the "azuretwin" option is defined but not yet implemented in the tool).
    #[structopt(short = "m", long = "key-method")]
    method: String,

    /// The identity of the application whose class key needs to be synchronized. This would
    /// typically be a UUID in string form.
    #[structopt(short = "a", long = "application-id")]
    application_id: String,

    /// The address of the key store. This argument is optional, and it's interpretation depends
    /// on the synchronization method.
    ///
    /// When the synchronization method is `http`, this argument should be the URL
    /// of an API endpoint that implements the Confidential Package Key Wrapping protocol. If it is
    /// omitted from the command-line, then this URL will be read from the
    /// `CP_CLOUD_KEY_SOURCE` environment variable instead. If it is not specified there either, then the
    /// command will fail.
    ///
    /// When the synchronization method is `file`, this argument should be the path to an existing
    /// file on disk, containing the key data in JSON format. File-based key stores are intended for
    /// local test environments only. If this argument is omitted from the command-line, it will
    /// be resolved from the CP_FILE_KEY_SOURCE environment variable instead. If it is not specified
    /// there either, then the command will fail.
    ///
    /// When the synchronization method is `commandline`, this argument should directly contain the
    /// wrapped key data as base64 encoding of the wrapped encryption key. When using this mechanism,
    /// the caller is assumed to have already obtained the wrapped key from a suitable source, and
    /// the wrapping is assumed to have been performed using the public part of the device key. In
    /// this situation, the tool is not responsible for reading the wrapped key from any other source.
    /// It will simply take the data from the command-line and pass it directly into the
    /// Confidential Package Manager, with no other processing other than base64 decoding.
    ///
    /// When the synchronization method is `azuretwin`, this argument is currently unused, because all
    /// configuration is read from environment variables. (Note: the `azuretwin` mechanism is
    /// not implemented yet).
    #[structopt(short = "k", long = "key-store")]
    key_store: Option<String>,
}

impl Sync {
    /// Synchronizes the key into the CPM from any given key source.
    fn sync_using_key_source<K: EncryptionKeySource>(
        &self,
        keysource: &K,
        cpm: &ConfidentialPackageManager,
    ) -> Result<()> {
        println!("Getting the device public key...");
        let device_public = cpm.get_device_public_key()?;
        println!("Getting the wrapped key from the key store...");
        let wrapped = keysource.wrap(&self.application_id, &device_public)?;
        println!("Unwrapping...");
        cpm.install_application_key(&self.application_id, &wrapped)?;
        println!("Done.");
        Ok(())
    }

    /// Implements the command for the HTTP (WebContract) sync method.
    fn sync_using_http(&self, cpm: &ConfidentialPackageManager) -> Result<()> {
        let endpoint = get_config_from_command_or_env(
            &self.key_store,
            "CP_CLOUD_KEY_SOURCE",
            "HTTP key store endpoint",
        )?;

        let keysource = WebContractKeySource::from_endpoint_uri(&endpoint);

        self.sync_using_key_source(&keysource, cpm)
    }

    /// Implements the command for the Azure device twin sync method (not supported yet).
    fn sync_using_azure_twin(&self, _cpm: &ConfidentialPackageManager) -> Result<()> {
        println!("Key synchronization via Azure device twin not yet supported. Please use `http` or `file`.");
        Err(Error::ToolError(ToolErrorKind::NotSupported))
    }

    /// Implements the command for a key store based in a file on the local file system.
    fn sync_using_file(&self, cpm: &ConfidentialPackageManager) -> Result<()> {
        // Echo a warning so that users are clear that this is only for local test environments.
        println!("WARNING: File-based key stores should only be used in local test environments.");
        let filepath = get_config_from_command_or_env(
            &self.key_store,
            "CP_FILE_KEY_SOURCE",
            "key store file path",
        )?;

        let keysource = FileKeySource::from_file_path(&filepath)?;

        self.sync_using_key_source(&keysource, cpm)
    }

    /// Implements the command for a degenerate key store where the wrapped data is passed directly on the
    /// command line as base64.
    fn sync_using_command_line(&self, cpm: &ConfidentialPackageManager) -> Result<()> {
        println!("Decoding base64 key data from command-line parameter...");
        if let Some(key_data) = &self.key_store {
            let wrapped = base64::decode(&key_data)?;
            println!("Unwrapping...");
            cpm.install_application_key(&self.application_id, &wrapped)?;
            println!("Done.");
            Ok(())
        }
        else {
            println!("Error: No key data supplied for commandline sync method. Please supply -k argument with base64-encoded key data.");
            Err(Error::ToolError(ToolErrorKind::MissingConfiguration))
        }
    }

    /// Synchronizes the class key for a given application identity from its cloud-based key source
    /// into the locally-running Confidential Package Manager (CPM).
    pub fn run(&self) -> Result<()> {
        println!("Connecting with Confidential Package Manager on the host system...");
        let cpm = ConfidentialPackageManager::new();
        let _pingres = cpm.ping()?;
        match self.method.as_str() {
            "http" => self.sync_using_http(&cpm),
            "file" => self.sync_using_file(&cpm),
            "azuretwin" => self.sync_using_azure_twin(&cpm),
            "commandline" => self.sync_using_command_line(&cpm),
            _ => {
                println!(
                    "Invalid synchronization method. Please specify either `http`, `file` or `commandline`."
                );
                Err(Error::ToolError(ToolErrorKind::InvalidSyncMethod))
            }
        }
    }
}
