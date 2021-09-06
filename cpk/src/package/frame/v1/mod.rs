// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements version 1 of the package frame format. The frame format is not intended to change, and
//! version 1 is quite possibly the only version that will ever exist, but the versioning is designed as a
//! future-proofing mechanism

use serde::{Deserialize, Serialize};

/// The fixed header makes up the first 16 bytes of a confidential package (.cpk) file. The fixed header is
/// made up of a single 4-byte integer value (the magic number), followed by a sequence of 6 2-byte integer values,
/// all in little-endian order.
/// 
/// This structure can be serialized and deserialized using [bincode](https://crates.io/crates/bincode).
#[derive(Debug, Serialize, Deserialize)]
pub struct FixedHeader {
    /// The magic number, which must have the value `0x0ECCF00D` in all confidential package (.cpk) files.
    pub magic: u32,

    /// The version of the package frame. The only supported value is 1. This is a future-proofing mechanism.
    pub frame_version: u16,

    /// A flag field. Currently no flags are defined. The only supported value is 0.
    pub flag: u16,

    /// The number of data streams within the package.
    pub num_streams: u16,

    /// The zero-based index of the stream that contains the package manifest. It is an error for
    /// this number to be >= the `num_streams` field.
    pub manifest_stream: u16,

    /// The data type of the manifest stream. The only supported value is 1. This is a future-proofing or
    /// extensibility mechanism. This crate will not process or produce other maninfest types.
    pub manifest_type: u16,

    /// The version of the manifest. The only supported value is 1. This is a future-proofing mechanism.
    pub manifest_version: u16,

    // Within the confidential package file, there would now follow a sequence of 8-byte integer pairs,
    // with one pair for each stream, where the first value in the pair is the file offset where the
    // stream is located, and the second value is its size (in bytes). This part of the file is variably-sized
    // because it depends on the number of streams, but you could conceptualise it as follows:
    //
    // pub stream_table: [(u64, u64); num_streams]
    //
    // If there were 5 data streams in the package, the size of the stream table would be
    // 5 * 2 * 8 = 80 bytes.
    //
    // Immediately following the stream table, the next byte offset in the file is referred to as the
    // "origin". It is the byte at which the first data stream begins.
    //
    // In a file with 5 data streams, the origin will be the 97th byte of the file, because the first
    // 16 bytes are the fixed header, and the next 80 would be the stream table. The consumer would therefore
    // seek to position 97 relative to the beginning of the file in order to read the first data stream
    // (whose stream index would be zero).
    //
    // In the stream table, all file offets are expressed relative to the origin, NOT relative to the
    // beginning of the file. The reason for this is that it allows all offsets to be precomputed
    // based purely on their size, without factoring in the variable-length part of the header. Adding
    // a new stream to a package would not affect the offsets of existing streams.
};

/// This structure represents a single entry in the stream table. It is a pair of 64-bit unsigned
/// values, where the first value is the offset of the stream data relative to the file origin,
/// and the second value is the size of the stream in bytes.
/// 
/// This structure can be serialized and deserialized using [bincode](https://crates.io/crates/bincode).
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamTableEntry {
    /// The offset of the data for this stream, relative to the origin of the file.
    /// 
    /// NOTE: The "origin" of the file is not the same as the beginning of the file. The file origin
    /// refers to the first post-header byte of the file, not the first overall byte. The header size
    /// is 16 bytes plus the size of the stream table, which is 16 bytes multiplied by the number
    /// of streams. If there are 5 streams in the package, then the stream table will be 80 bytes in
    /// size, making a total header size of 96 bytes. The file origin is then the 97th byte. An offset
    /// of 0u64 in this field would refer to the 97th byte relative to the beginning of the file.
    pub offset: u64,

    /// The size of the data stream, in bytes.
    pub size: u64
}
