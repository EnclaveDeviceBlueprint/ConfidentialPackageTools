// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! General-purpose utilities used throughout the cpk-tool crate.

use crate::error::{Error, Result, ToolErrorKind};

/// Utility to get a string value either from a command-line option or a named environment variable.
pub fn get_config_from_command_or_env(
    config_option: &Option<String>,
    env_var_name: &str,
    purpose: &str,
) -> Result<String> {
    let opt = match config_option {
        Some(o) => o.clone(),
        None => {
            // The option isn't on the command-line, so examine the environment variable instead
            let env = std::env::var(env_var_name);
            if env.is_err() {
                // The option hasn't been specified on the command-line or in the environment variable.
                println!("No {} specified. Please specify on the command-line or by setting the `{}` environment variable.", purpose, env_var_name);
                return Err(Error::ToolError(ToolErrorKind::MissingConfiguration));
            }
            env.unwrap()
        }
    };

    Ok(opt)
}
