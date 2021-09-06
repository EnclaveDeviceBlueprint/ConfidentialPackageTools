// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements the manifest for confidential packages. The manifest is a JSON document, and exactly one
//! manifest must be embedded as one of the streams in a confidential package (.cpk) file. The frame format allows
//! one stream to be identified as the manifest, so that the consumer is able to discover the manifest within the
//! file to enable further processing.

pub mod v1;
