// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! Synchronizes the class key from its cloud-based key source into the locally-running
//! Confidential Package Manager (CPM).

use crate::error::{Error, Result, ToolErrorKind};

use cpk::cpm::ConfidentialPackageManager;
use cpk::keys::http::WebContractKeySource;
use cpk::keys::EncryptionKeySource;

use structopt::StructOpt;

/// Models the options required by the sync command.
#[derive(Debug, StructOpt)]
pub struct Sync {
    /// The synchronization method to use, either "http" or "azuretwin" (although only "http"
    /// is implemented currently).
    #[structopt(short = "m", long = "method")]
    method: String,

    /// The identity of the application whose class key needs to be synchronized. This would
    /// typically be a UUID in string form.
    #[structopt(short = "a", long = "application-id")]
    application_id: String,

    /// The key wrapping endpoint to use when synchronizing with the "http" method. This must
    /// be a pre-authenticated HTTP URL. If this option is not specified, then it will be obtained
    /// from the `CP_CLOUD_KEY_SOURCE` environment variable instead.
    #[structopt(short = "e", long = "http-endpoint")]
    http_endpoint: Option<String>,
}

impl Sync {
    /// Implements the command for the HTTP (WebContract) sync method.
    fn sync_using_http(&self, cpm: &ConfidentialPackageManager) -> Result<()> {
        let endpoint = match &self.http_endpoint {
            Some(e) => e.clone(),
            None => {
                // The endpoint isn't on the command-line, so examine the environment variable instead
                let env = std::env::var("CP_CLOUD_KEY_SOURCE");
                if env.is_err() {
                    // The endpoint hasn't been specified on the command-line or in the environment variable.
                    println!("No HTTP endpoint found for sync. Please specify by setting the `CP_CLOUD_KEY_SOURCE` environment variable.");
                    return Err(Error::ToolError(ToolErrorKind::MissingConfiguration));
                }
                env.unwrap()
            }
        };

        let keysource = WebContractKeySource::from_endpoint_uri(&endpoint);

        println!("Getting the device public key...");
        let device_public = cpm.get_device_public_key()?;
        println!("Getting the wrapped key from the endpoint...");
        let wrapped = keysource.wrap(&self.application_id, &device_public)?;
        println!("Unwrapping...");
        cpm.install_application_key(&self.application_id, &wrapped)?;

        Ok(())
    }

    /// Implements the command for the Azure device twin sync method (not supported yet).
    fn sync_using_azure_twin(&self, _cpm: &ConfidentialPackageManager) -> Result<()> {
        println!("Key synchronization via Azure device twin not yet supported. Please use `http`.");
        Err(Error::ToolError(ToolErrorKind::NotSupported))
    }

    /// Synchronizes the class key for a given application identity from its cloud-based key source
    /// into the locally-running Confidential Package Manager (CPM).
    pub fn run(&self) -> Result<()> {
        println!("Connecting with Confidential Package Manager on the host system...");
        let cpm = ConfidentialPackageManager::new();
        let _pingres = cpm.ping()?;
        match self.method.as_str() {
            "http" => self.sync_using_http(&cpm),
            "azuretwin" => self.sync_using_azure_twin(&cpm),
            _ => {
                println!(
                    "Invalid synchronization method. Please specify either `http` or `azuretwin`."
                );
                Err(Error::ToolError(ToolErrorKind::InvalidSyncMethod))
            }
        }
    }
}
