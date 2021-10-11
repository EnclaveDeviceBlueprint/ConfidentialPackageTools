// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module implements version 1 of the package frame format. The frame format is not intended to change, and
//! version 1 is quite possibly the only version that will ever exist, but the versioning is designed as a
//! future-proofing mechanism

use super::MAGIC;
use crate::package::error::{Error, PackageErrorKind};
use crate::package::Result;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::{Read, Seek, SeekFrom};

/// The fixed header makes up the first 16 bytes of a confidential package (.cpk) file. The fixed header is
/// made up of a single 4-byte integer value (the magic number), followed by a sequence of 6 2-byte integer values,
/// all in little-endian order.
///
/// This structure can be serialized and deserialized using [bincode](https://crates.io/crates/bincode).
#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

/// This structure represents a single entry in the stream table. It is a pair of 64-bit unsigned
/// values, where the first value is the offset of the stream data relative to the file origin,
/// and the second value is the size of the stream in bytes.
///
/// This structure can be serialized and deserialized using [bincode](https://crates.io/crates/bincode).
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub size: u64,
}

/// This structure models a v1 package frame, including the fixed header and the stream table.
#[derive(Debug)]
pub struct Frame {
    /// The fixed header of the frame, precisely as it was deserialized from the beginning of the
    /// input file stream.
    pub header: FixedHeader,
    stream_table: Vec<StreamTableEntry>,
}

impl Frame {
    /// Constructs a frame by reading it from the given input stream.
    ///
    /// The input stream can be any read stream, but typically it would be a stream on a newly-opened
    /// confidential package (.cpk) file, with the seek position at zero. This function will not
    /// perform a seek. It will assume that the stream will yield the magic number at its current
    /// read position, followed by the rest of the fixed header and then the stream table.
    pub fn read_from_stream<R: Read>(stream: &mut R) -> Result<Frame> {
        let mut hdr_bytes = [0_u8; std::mem::size_of::<FixedHeader>()];
        stream.read_exact(&mut hdr_bytes)?;

        // TODO: Okay to unwrap here? Can this realistically fail given that we are just decoding
        // integers, and we definitely have the exact number of bytes of input.
        let fhdr: FixedHeader = bincode::deserialize(&hdr_bytes).unwrap();

        // A series of checks for correctness and consistency of the header fields.

        if fhdr.magic != MAGIC {
            return Err(Error::PackageError(PackageErrorKind::MagicNumberMissing));
        }

        if fhdr.frame_version < 1 {
            return Err(Error::PackageError(PackageErrorKind::PackageVersionMissing));
        }

        if fhdr.frame_version > 1 {
            return Err(Error::PackageError(
                PackageErrorKind::PackageVersionNotSupported,
            ));
        }

        if fhdr.flag != 0 {
            return Err(Error::PackageError(PackageErrorKind::InvalidFlag));
        }

        if fhdr.num_streams == 0 {
            return Err(Error::PackageError(PackageErrorKind::StreamCountZero));
        }

        if fhdr.manifest_stream >= fhdr.num_streams {
            return Err(Error::PackageError(
                PackageErrorKind::ManifestStreamOutOfRange,
            ));
        }

        if fhdr.manifest_type != 1 {
            return Err(Error::PackageError(PackageErrorKind::InvalidManifestType));
        }

        if fhdr.manifest_version != 1 {
            return Err(Error::PackageError(
                PackageErrorKind::InvalidManifestVersion,
            ));
        }

        let mut frame = Frame {
            header: fhdr.clone(),
            stream_table: Vec::with_capacity(fhdr.num_streams as usize),
        };

        // Read the stream table
        for _i in 0..fhdr.num_streams {
            let mut entry_bytes = [0_u8; std::mem::size_of::<StreamTableEntry>()];
            stream.read_exact(&mut entry_bytes)?;

            // TODO: Okay to unwrap here? Can this realistically fail given that we are just decoding
            // integers, and we definitely have the exact number of bytes of input.
            let entry: StreamTableEntry = bincode::deserialize(&entry_bytes).unwrap();
            frame.stream_table.push(entry.clone());
        }

        Ok(frame)
    }

    /// Gets the offset of the origin byte in the input source. This is the offset at which the first byte
    /// of the first stream can be found.
    pub fn get_origin(&self) -> u64 {
        let hdr_size = std::mem::size_of::<FixedHeader>()
            + (self.header.num_streams as usize) * std::mem::size_of::<StreamTableEntry>();
        hdr_size as u64
    }

    /// Gets the offset, relative to the origin, of the stream with the given index.
    pub fn get_stream_offset(&self, stream_index: u16) -> Result<u64> {
        if stream_index < self.header.num_streams {
            Ok(self.stream_table[stream_index as usize].offset)
        } else {
            Err(Error::PackageError(PackageErrorKind::StreamIndexOutOfRange))
        }
    }

    /// Gets the size, in bytes, of the stream with the given index.
    pub fn get_stream_size(&self, stream_index: u16) -> Result<u64> {
        if stream_index < self.header.num_streams {
            Ok(self.stream_table[stream_index as usize].size)
        } else {
            Err(Error::PackageError(PackageErrorKind::StreamIndexOutOfRange))
        }
    }

    /// Reads the entire contents of the stream with the given index from the given readable/seekable source,
    /// and places the bytes into the given pre-allocated buffer, which must be of exactly the correct size
    /// to accommodate the data.
    ///
    /// This method is convenient to use for small streams, such as those that contain the manifest or small
    /// data items such as digests, signatures and certificates.
    pub fn read_whole_stream_into_buffer<R: Read + Seek>(
        &self,
        stream_index: u16,
        source: &mut R,
        buffer: &mut [u8],
    ) -> Result<()> {
        if stream_index < self.header.num_streams {
            let origin = self.get_origin();
            let offset = self.get_stream_offset(stream_index)?;
            let sz = self.get_stream_size(stream_index)?;
            if sz == buffer.len() as u64 {
                // We were given the correct size of buffer, so seek to the offset relative to the origin,
                // and read from the data source into the buffer.
                let _pos = source.seek(SeekFrom::Start(origin + offset))?;
                source.read_exact(buffer)?;
                Ok(())
            } else {
                Err(Error::PackageError(PackageErrorKind::BufferSizeIncorrect))
            }
        } else {
            Err(Error::PackageError(PackageErrorKind::StreamIndexOutOfRange))
        }
    }

    /// Reads the entire contents of the stream with the given index from the given readable/seekable source,
    /// and places the bytes into the given vector (resizing the vector as needed).
    ///
    /// This method is convenient to use for small streams, such as those that contain the manifest or small
    /// data items such as digests, signatures and certificates.
    pub fn read_whole_stream_into_vec<R: Read + Seek>(
        &self,
        stream_index: u16,
        source: &mut R,
        destination: &mut Vec<u8>,
    ) -> Result<()> {
        if stream_index < self.header.num_streams {
            let sz = self.get_stream_size(stream_index)?;
            let sz_usize = usize::try_from(sz)
                .map_err(|_e| Error::PackageError(PackageErrorKind::StreamTooLarge))?;
            destination.resize(sz_usize, 0); // TODO: Sanity check, maximum size?
            self.read_whole_stream_into_buffer(stream_index, source, destination.as_mut_slice())?;
            Ok(())
        } else {
            Err(Error::PackageError(PackageErrorKind::StreamIndexOutOfRange))
        }
    }

    /// Special case of [read_whole_stream_into_buffer] that specifically reads the manifest stream, and therefore does
    /// not require a stream index to be passed in.
    pub fn read_whole_manifest_stream_into_buffer<R: Read + Seek>(
        &self,
        source: &mut R,
        buffer: &mut [u8],
    ) -> Result<()> {
        self.read_whole_stream_into_buffer(self.header.manifest_stream, source, buffer)
    }

    /// Special case of [read_whole_stream_into_vec] that specifically reads the manifest stream, and therefore does
    /// not require a stream index to be passed in.
    pub fn read_whole_manifest_stream_into_vec<R: Read + Seek>(
        &self,
        source: &mut R,
        destination: &mut Vec<u8>,
    ) -> Result<()> {
        self.read_whole_stream_into_vec(self.header.manifest_stream, source, destination)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::Frame;
    use crate::package::error::{Error, PackageErrorKind};
    use crate::package::frame::MAGIC;
    use crate::package::Result;

    const STREAM_0: &[u8] = b"Is this a dagger I see before me?";
    const STREAM_1: &[u8] = b"The handle toward my hand?";
    const STREAM_2: &[u8] = b"Come, let me clutch thee!";
    const STREAM_3: &[u8] = b"I have thee not, yet I see thee still.";
    const STREAM_4: &[u8] = b"{}";

    fn populate_valid_test_frame(frame: &mut Vec<u8>) -> Result<()> {
        // Write the fixed header
        frame.write_all(&MAGIC.to_le_bytes())?; // Magic number
        frame.write_all(&1u16.to_le_bytes())?; // Version
        frame.write_all(&0u16.to_le_bytes())?; // Flag (unused)
        frame.write_all(&5u16.to_le_bytes())?; // Number of streams
        frame.write_all(&4u16.to_le_bytes())?; // 0-based index of the manifest stream - the final stream
        frame.write_all(&1u16.to_le_bytes())?; // Manifest "type" (currently not used, but designed for flexibility)
        frame.write_all(&1u16.to_le_bytes())?; // Manifest version

        // Write the stream table
        let mut cursor: u64 = 0;
        frame.write_all(&cursor.to_le_bytes())?;
        frame.write_all(&(STREAM_0.len() as u64).to_le_bytes())?;
        cursor += STREAM_0.len() as u64;
        frame.write_all(&cursor.to_le_bytes())?;
        frame.write_all(&(STREAM_1.len() as u64).to_le_bytes())?;
        cursor += STREAM_1.len() as u64;
        frame.write_all(&cursor.to_le_bytes())?;
        frame.write_all(&(STREAM_2.len() as u64).to_le_bytes())?;
        cursor += STREAM_2.len() as u64;
        frame.write_all(&cursor.to_le_bytes())?;
        frame.write_all(&(STREAM_3.len() as u64).to_le_bytes())?;
        cursor += STREAM_3.len() as u64;
        frame.write_all(&cursor.to_le_bytes())?;
        frame.write_all(&(STREAM_4.len() as u64).to_le_bytes())?;

        // Write the streams
        frame.write_all(&STREAM_0)?;
        frame.write_all(&STREAM_1)?;
        frame.write_all(&STREAM_2)?;
        frame.write_all(&STREAM_3)?;
        frame.write_all(&STREAM_4)?;

        Ok(())
    }

    #[test]
    fn test_read_header_fields() {
        let mut stream: Vec<u8> = Vec::new();
        populate_valid_test_frame(&mut stream).unwrap();
        let frame = Frame::read_from_stream(&mut stream.as_slice()).unwrap();

        assert_eq!(frame.header.magic, MAGIC);
        assert_eq!(frame.header.frame_version, 1);
        assert_eq!(frame.header.flag, 0);
        assert_eq!(frame.header.num_streams, 5);
        assert_eq!(frame.header.manifest_stream, 4);
        assert_eq!(frame.header.manifest_type, 1);
        assert_eq!(frame.header.manifest_version, 1);
    }

    #[test]
    fn test_read_stream_sizes() {
        let mut stream: Vec<u8> = Vec::new();
        populate_valid_test_frame(&mut stream).unwrap();
        let frame = Frame::read_from_stream(&mut stream.as_slice()).unwrap();

        assert_eq!(frame.get_stream_size(0).unwrap(), STREAM_0.len() as u64);
        assert_eq!(frame.get_stream_size(1).unwrap(), STREAM_1.len() as u64);
        assert_eq!(frame.get_stream_size(2).unwrap(), STREAM_2.len() as u64);
        assert_eq!(frame.get_stream_size(3).unwrap(), STREAM_3.len() as u64);
        assert_eq!(frame.get_stream_size(4).unwrap(), STREAM_4.len() as u64);
    }

    #[test]
    fn test_read_stream_offsets() {
        let mut stream: Vec<u8> = Vec::new();
        populate_valid_test_frame(&mut stream).unwrap();
        let frame = Frame::read_from_stream(&mut stream.as_slice()).unwrap();

        let mut expected: u64 = 0;
        assert_eq!(frame.get_stream_offset(0).unwrap(), expected);
        expected += STREAM_0.len() as u64;
        assert_eq!(frame.get_stream_offset(1).unwrap(), expected);
        expected += STREAM_1.len() as u64;
        assert_eq!(frame.get_stream_offset(2).unwrap(), expected);
        expected += STREAM_2.len() as u64;
        assert_eq!(frame.get_stream_offset(3).unwrap(), expected);
        expected += STREAM_3.len() as u64;
        assert_eq!(frame.get_stream_offset(4).unwrap(), expected);
    }

    #[test]
    fn test_read_stream_contents() {
        let mut stream: Vec<u8> = Vec::new();
        populate_valid_test_frame(&mut stream).unwrap();
        let frame = Frame::read_from_stream(&mut stream.as_slice()).unwrap();

        let mut cursor = Cursor::new(stream);

        let mut str0: Vec<u8> = Vec::new();
        frame
            .read_whole_stream_into_vec(0, &mut cursor, &mut str0)
            .unwrap();
        assert_eq!(str0.len(), STREAM_0.len());
        assert_eq!(str0.as_slice(), STREAM_0);

        let mut str1: Vec<u8> = Vec::new();
        frame
            .read_whole_stream_into_vec(1, &mut cursor, &mut str1)
            .unwrap();
        assert_eq!(str1.len(), STREAM_1.len());
        assert_eq!(str1.as_slice(), STREAM_1);

        let mut str2: Vec<u8> = Vec::new();
        frame
            .read_whole_stream_into_vec(2, &mut cursor, &mut str2)
            .unwrap();
        assert_eq!(str2.len(), STREAM_2.len());
        assert_eq!(str2.as_slice(), STREAM_2);

        let mut str3: Vec<u8> = Vec::new();
        frame
            .read_whole_stream_into_vec(3, &mut cursor, &mut str3)
            .unwrap();
        assert_eq!(str3.len(), STREAM_3.len());
        assert_eq!(str3.as_slice(), STREAM_3);

        let mut str4: Vec<u8> = Vec::new();
        frame
            .read_whole_stream_into_vec(4, &mut cursor, &mut str4)
            .unwrap();
        assert_eq!(str4.len(), STREAM_4.len());
        assert_eq!(str4.as_slice(), STREAM_4);
    }

    #[test]
    fn test_read_manifest_stream_contents() {
        let mut stream: Vec<u8> = Vec::new();
        populate_valid_test_frame(&mut stream).unwrap();
        let frame = Frame::read_from_stream(&mut stream.as_slice()).unwrap();

        let mut cursor = Cursor::new(stream);

        let mut manifest: Vec<u8> = Vec::new();
        frame
            .read_whole_manifest_stream_into_vec(&mut cursor, &mut manifest)
            .unwrap();
        assert_eq!(manifest.len(), STREAM_4.len());
        assert_eq!(manifest.as_slice(), STREAM_4);
    }

    #[test]
    fn test_stream_size_index_out_of_range() {
        let mut stream: Vec<u8> = Vec::new();
        populate_valid_test_frame(&mut stream).unwrap();
        let frame = Frame::read_from_stream(&mut stream.as_slice()).unwrap();
        let err = frame.get_stream_size(5).unwrap_err();
        match err {
            Error::PackageError(kind) => assert_eq!(PackageErrorKind::StreamIndexOutOfRange, kind),
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_stream_offset_index_out_of_range() {
        let mut stream: Vec<u8> = Vec::new();
        populate_valid_test_frame(&mut stream).unwrap();
        let frame = Frame::read_from_stream(&mut stream.as_slice()).unwrap();
        let err = frame.get_stream_offset(5).unwrap_err();
        match err {
            Error::PackageError(kind) => assert_eq!(PackageErrorKind::StreamIndexOutOfRange, kind),
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_stream_contents_index_out_of_range() {
        let mut stream: Vec<u8> = Vec::new();
        populate_valid_test_frame(&mut stream).unwrap();
        let frame = Frame::read_from_stream(&mut stream.as_slice()).unwrap();
        let mut cursor = Cursor::new(stream);

        let mut str5: Vec<u8> = Vec::new();
        let err = frame
            .read_whole_stream_into_vec(5, &mut cursor, &mut str5)
            .unwrap_err();
        match err {
            Error::PackageError(kind) => assert_eq!(PackageErrorKind::StreamIndexOutOfRange, kind),
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_origin() {
        let mut stream: Vec<u8> = Vec::new();
        populate_valid_test_frame(&mut stream).unwrap();
        let frame = Frame::read_from_stream(&mut stream.as_slice()).unwrap();
        assert_eq!(96, frame.get_origin());
    }

    #[test]
    fn test_invalid_header_magic() {
        // Write the fixed header
        let mut frame: Vec<u8> = Vec::new();
        frame.write_all(&0u32.to_le_bytes()).unwrap(); // Magic number
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Version
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Flag (unused)
        frame.write_all(&5u16.to_le_bytes()).unwrap(); // Number of streams
        frame.write_all(&4u16.to_le_bytes()).unwrap(); // 0-based index of the manifest stream - the final stream
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest "type" (currently not used, but designed for flexibility)
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest version

        let err = Frame::read_from_stream(&mut frame.as_slice()).unwrap_err();

        match err {
            Error::PackageError(kind) => assert_eq!(PackageErrorKind::MagicNumberMissing, kind),
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_invalid_header_version_zero() {
        // Write the fixed header
        let mut frame: Vec<u8> = Vec::new();
        frame.write_all(&MAGIC.to_le_bytes()).unwrap(); // Magic number
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Version
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Flag (unused)
        frame.write_all(&5u16.to_le_bytes()).unwrap(); // Number of streams
        frame.write_all(&4u16.to_le_bytes()).unwrap(); // 0-based index of the manifest stream - the final stream
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest "type" (currently not used, but designed for flexibility)
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest version

        let err = Frame::read_from_stream(&mut frame.as_slice()).unwrap_err();

        match err {
            Error::PackageError(kind) => assert_eq!(PackageErrorKind::PackageVersionMissing, kind),
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_invalid_header_version_unsupported() {
        // Write the fixed header
        let mut frame: Vec<u8> = Vec::new();
        frame.write_all(&MAGIC.to_le_bytes()).unwrap(); // Magic number
        frame.write_all(&2u16.to_le_bytes()).unwrap(); // Version
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Flag (unused)
        frame.write_all(&5u16.to_le_bytes()).unwrap(); // Number of streams
        frame.write_all(&4u16.to_le_bytes()).unwrap(); // 0-based index of the manifest stream - the final stream
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest "type" (currently not used, but designed for flexibility)
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest version

        let err = Frame::read_from_stream(&mut frame.as_slice()).unwrap_err();

        match err {
            Error::PackageError(kind) => {
                assert_eq!(PackageErrorKind::PackageVersionNotSupported, kind)
            }
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_invalid_header_flag() {
        // Write the fixed header
        let mut frame: Vec<u8> = Vec::new();
        frame.write_all(&MAGIC.to_le_bytes()).unwrap(); // Magic number
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Version
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Flag (unused)
        frame.write_all(&5u16.to_le_bytes()).unwrap(); // Number of streams
        frame.write_all(&4u16.to_le_bytes()).unwrap(); // 0-based index of the manifest stream - the final stream
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest "type" (currently not used, but designed for flexibility)
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest version

        let err = Frame::read_from_stream(&mut frame.as_slice()).unwrap_err();

        match err {
            Error::PackageError(kind) => assert_eq!(PackageErrorKind::InvalidFlag, kind),
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_invalid_header_stream_count_zero() {
        // Write the fixed header
        let mut frame: Vec<u8> = Vec::new();
        frame.write_all(&MAGIC.to_le_bytes()).unwrap(); // Magic number
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Version
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Flag (unused)
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Number of streams
        frame.write_all(&4u16.to_le_bytes()).unwrap(); // 0-based index of the manifest stream - the final stream
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest "type" (currently not used, but designed for flexibility)
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest version

        let err = Frame::read_from_stream(&mut frame.as_slice()).unwrap_err();

        match err {
            Error::PackageError(kind) => assert_eq!(PackageErrorKind::StreamCountZero, kind),
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_invalid_header_manifest_stream_out_of_range() {
        // Write the fixed header
        let mut frame: Vec<u8> = Vec::new();
        frame.write_all(&MAGIC.to_le_bytes()).unwrap(); // Magic number
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Version
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Flag (unused)
        frame.write_all(&5u16.to_le_bytes()).unwrap(); // Number of streams
        frame.write_all(&5u16.to_le_bytes()).unwrap(); // 0-based index of the manifest stream - the final stream
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest "type" (currently not used, but designed for flexibility)
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest version

        let err = Frame::read_from_stream(&mut frame.as_slice()).unwrap_err();

        match err {
            Error::PackageError(kind) => {
                assert_eq!(PackageErrorKind::ManifestStreamOutOfRange, kind)
            }
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_invalid_header_manifest_type_unsupported() {
        // Write the fixed header
        let mut frame: Vec<u8> = Vec::new();
        frame.write_all(&MAGIC.to_le_bytes()).unwrap(); // Magic number
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Version
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Flag (unused)
        frame.write_all(&5u16.to_le_bytes()).unwrap(); // Number of streams
        frame.write_all(&4u16.to_le_bytes()).unwrap(); // 0-based index of the manifest stream - the final stream
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Manifest "type" (currently not used, but designed for flexibility)
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest version

        let err = Frame::read_from_stream(&mut frame.as_slice()).unwrap_err();

        match err {
            Error::PackageError(kind) => assert_eq!(PackageErrorKind::InvalidManifestType, kind),
            _ => panic!("Unexpected error type."),
        }
    }

    #[test]
    fn test_invalid_header_manifest_version_unsupported() {
        // Write the fixed header
        let mut frame: Vec<u8> = Vec::new();
        frame.write_all(&MAGIC.to_le_bytes()).unwrap(); // Magic number
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Version
        frame.write_all(&0u16.to_le_bytes()).unwrap(); // Flag (unused)
        frame.write_all(&5u16.to_le_bytes()).unwrap(); // Number of streams
        frame.write_all(&4u16.to_le_bytes()).unwrap(); // 0-based index of the manifest stream - the final stream
        frame.write_all(&1u16.to_le_bytes()).unwrap(); // Manifest "type" (currently not used, but designed for flexibility)
        frame.write_all(&2u16.to_le_bytes()).unwrap(); // Manifest version

        let err = Frame::read_from_stream(&mut frame.as_slice()).unwrap_err();

        match err {
            Error::PackageError(kind) => assert_eq!(PackageErrorKind::InvalidManifestVersion, kind),
            _ => panic!("Unexpected error type."),
        }
    }
}
