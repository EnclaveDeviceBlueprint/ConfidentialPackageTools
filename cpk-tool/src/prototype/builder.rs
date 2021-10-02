// SPDX-License-Identifier: MIT
// Copyright 2021 Contributors to the Confidential Packaging project.

//! Prototype (proof-of-concept) implementation of the confidential package build
//! process.

use crate::error::Result;
use crate::prototype::package::ConfidentialPackage;

use cpk::keys::{EncryptionKeyExposure, EncryptionKeySource, WrappingKeySource};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};

use pkcs8::FromPrivateKey;

use rsa::hash::Hash;
use rsa::{PaddingScheme, RsaPrivateKey as RsaPriv};

use std::fs::File;

// Non-confidential RSA private signing key to demonstrate payload signing
// without requiring dependencies on OpenSSL or existing keys/certs.
const SERVICE_PROVIDER_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1oNfjoIDKvyTk
IFWqmumaw6e9gwPHsSd7YZpoPG3OgbXo8IJxuCelKm4lHcVKZnXFatyO/ffx+OwJ
iT9k5wySU5C+JxRNJnbjeiYNfuiF5mqaW0+mPrN/Z7+FAPdNF14OpV/PoYpnkKJu
BxkvEVxYqqRGE4Bh3Oe3XDLtOY8keGksweobsWjZz2v5zVZkUhaKw999BDzbEnwC
m5q7768dw1faKwI8eVAGZg9dPgCGIf1f2SEJA/DYEUVFJs2cLIe/Tnt7kjUl77EI
dyW/IGhcsios4HjTmD1fwM7MNaDTn3iveyqfCzYJ4chpcYqBSQ7W157CQ+rg/Q+l
YexxhETjAgMBAAECggEACVnEg5WJy+ZXUd9QSb479JnKEvmhwjAepj16I4+o347R
/LIVJSGj+N7cWNDVjWUE/yrnO/1bPHviOwNz3g//F7FxrDh61RX73O42807rTal1
J4k36okj2JVQyNop4TAoyXw+GIRqibZqhlubMk8kf/QZDPqIC4HB9DCs9oWWFvx9
xcgs/7JTYNqARz/cZaMX8rRXGPniUxrs3kB6vznxgRcCwOLSdVsCLCCLHpbAhm7R
0lXawG2Jkk2RucCtMl+EmpJAt2by/sjg7raiXdpBiHPh1nu+OVUo55hMtzGPbPtF
0izm9sUKQB5q5nihYsOwhxKyuv159QNzpKC3+SrBYQKBgQDf3deq0CEMmS+Y2QcC
bBwfS7OHaDKxVdM/F/3LlLT+FrnMVMuzmvsbRp9417XGNxVucuTdWU5USguQXs+T
vhXIsAsKm5RmHrJpeDKR/j48jgminxf/2ldIJn3n9CYBBdjO8pTo6PqUeFVuVJKj
F8jIVNjoMZw7YwhnCuukmEaEywKBgQDPsuvbdEinR092u2VjLrornW387qe3JihT
cA2SeeFBkMk3KBQ9xfP/s+KRH97KrwEBj1mMzsvEUzWBW071pxoCu5W+JCbnBlak
nc5vS/1hePb2JqA0mumvNdTcQpFShctObVQJSRvvU+M5/sBC9mTc1TZEoB4hHVYu
5RhNeNNVSQKBgG/GQjJlLLsvmRZF9jv9YqU1lPPc0MK+SXVNM0j8fMoI6sfc5sBM
d2gNAP7DJV1Mj4TQFPl356YqOk/hJt9rn1DOpRSszZGXbhk/DHDccpKlkKYDrWXv
zHiXz3GK85a7Jp9de4A3IzYSRwWJcJXCAFwWER8N9iWosr9QMovCBCO1AoGAexAJ
XaM9tRe0hqYsQaMbHeKOm9IQP511QVLgR8y9YerWvj6aF6vlkblU4iYfDLq6fuEf
7yVMaMvgpP+j/jt/VuUsqVekUThZN/pkqV8+B3Xz5g8m12R+V5kuwT8T+fBacOKo
a0QNMDXlKaS+6C4zvwD5wZmZoIdQXELTrnuLxDkCgYEAlaqt4CDhn5Z780SQgQ9G
/Y6RYu/YXDS080lfU9/MOVJ50x9LfuVPrkACsvLanyiNjBKiWH4AZ47q12a7valn
FWVI+FuReQOpbMwH3vYodP4EYwwlO7aRu4+Ql1nflxrqXhrbeLT3VUNSZvTfu623
hQhrUEkvvzSRSxwVsIzC0FE=
-----END PRIVATE KEY-----
";

// Self-signed cert corresponding to above private key.
const SERVICE_PROVIDER_CERTIFICATE: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDkDCCAngCCQDSFo2Y5B37/zANBgkqhkiG9w0BAQsFADCBiTELMAkGA1UEBhMC
VUsxFzAVBgNVBAgMDkNhbWJyaWRnZXNoaXJlMRIwEAYDVQQHDAlDYW1icmlkZ2Ux
DTALBgNVBAoMBERlbW8xDTALBgNVBAsMBERlbW8xEDAOBgNVBAMMB2RlbW8udWsx
HTAbBgkqhkiG9w0BCQEWDm5vYm9keUBkZW1vLnVrMB4XDTIxMDczMTE2NTAwNVoX
DTIyMDczMTE2NTAwNVowgYkxCzAJBgNVBAYTAlVLMRcwFQYDVQQIDA5DYW1icmlk
Z2VzaGlyZTESMBAGA1UEBwwJQ2FtYnJpZGdlMQ0wCwYDVQQKDAREZW1vMQ0wCwYD
VQQLDAREZW1vMRAwDgYDVQQDDAdkZW1vLnVrMR0wGwYJKoZIhvcNAQkBFg5ub2Jv
ZHlAZGVtby51azCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALWg1+Og
gMq/JOQgVaqa6ZrDp72DA8exJ3thmmg8bc6BtejwgnG4J6UqbiUdxUpmdcVq3I79
9/H47AmJP2TnDJJTkL4nFE0mduN6Jg1+6IXmappbT6Y+s39nv4UA900XXg6lX8+h
imeQom4HGS8RXFiqpEYTgGHc57dcMu05jyR4aSzB6huxaNnPa/nNVmRSForD330E
PNsSfAKbmrvvrx3DV9orAjx5UAZmD10+AIYh/V/ZIQkD8NgRRUUmzZwsh79Oe3uS
NSXvsQh3Jb8gaFyyKizgeNOYPV/Azsw1oNOfeK97Kp8LNgnhyGlxioFJDtbXnsJD
6uD9D6Vh7HGEROMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAKVbaCzw2gwsyQ2dw
X/za7fepQSRvBdpMx0gdy6mpatwyVQIn1ZAO+dL0fJhn8IzH6Z+uczOpi0Ei99Ra
I3istwXn8ZFSod84/V5e3z7Xm6bdiCL5L/3QllqjuD9nWwghsFQI9Wfn4XXer2AV
Y+1z/FtCfCfISViMUu8On9tfCLp0QZO7OYpF4bEeHVpdE2MhcgbGujfBLW9ADdvt
UlEq+XfQmeE9d3SD2+T/I1g28eQWq4kxWCSmFEVOhwy2A4vNIIB2yC1vVirexfNM
k8WxYOhavpe8kqDixSdm1hMaUSoLKkF72nMmDrKZCQM2CknF0qUBwnz3koYvjm1y
kq7Y+A==
-----END CERTIFICATE-----
";

/// A minimal, restricted prototype implementation of the package build process.
/// 
/// This function is designed to demonstrate how a confidential package file can be formed from an
/// input payload and written to disk. This code is for proof-of-concept purposes only.
/// 
/// In time, the package build process will be fully implemented within the `cpk` crate, and will be
/// able to handle large input files, varied hashing and signing schemes, certificate handling, and
/// a greater flexibility of symmetric encryption schemes,
/// 
/// This prototype has a number of assumptions, restrictions and simplifications:
/// 
/// - The input file (and hence the resulting confidential package) is assumed to be "small", meaning that
/// its entire contents can sensibly be loaded into memory during the build process.
/// - The encryption scheme is AES in GCM mode with a 256-bit key.
/// - The hashing scheme is SHA-256.
/// - The signing scheme is RSA with a 2048-bit private key and using the PKCS1 v1.5 padding scheme.
/// - A self-signed demo private key and certificate is used. The caller cannot provide their own
/// key or certificate. The demo certificate will be embedded in the confidential package.
/// - Logging is with `println!()` statements to the console.
/// - The caller is not able to provide any versioning or build information, nor any target details
/// for the payload. The prototype package model hard-codes these to version 1.0.0 (with a
/// current timestamp) with a target architecture of aarch64 and a target OS of OP-TEE.
pub fn simple_build_from_payload<
    S: EncryptionKeySource,
    W: WrappingKeySource + EncryptionKeyExposure,
>(
    application_id: &String,
    application_name: &String,
    vendor: &String,
    path_to_payload: &String,
    path_to_package: &String,
    encryption_key_source: &S,
    wrapping_key_source: &W,
) -> Result<()> {
    // Read the payload from the input - this will error if the file does not exist or can't be opened.
    println!("Reading input file...");
    let mut in_out = std::fs::read(&path_to_payload)?;

    // Hash and sign - hard-code the cryptoscheme to SHA-256 and PKCS1 v1.5
    println!("Signing...");
    let signing_key = RsaPriv::from_pkcs8_pem(SERVICE_PROVIDER_PRIVATE_KEY).unwrap();
    let digest = digest(&SHA256, &in_out);
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
    let mut signature = signing_key.sign(padding, &digest.as_ref())?;

    // Get the wrapped encryption key from its source and unwrap
    println!("Fetching encryption key from source...");
    let wrapping_key = wrapping_key_source.get_public()?;
    let wrapped_key = encryption_key_source.wrap(application_id, &wrapping_key)?;
    let unwrapped_key = wrapping_key_source.expose(&wrapped_key)?;

    // Convert the key into a RING AES GCM key
    let unbound_key = UnboundKey::new(&AES_256_GCM, &unwrapped_key).unwrap();
    let sealing_key = LessSafeKey::new(unbound_key);

    // Generate a nonce
    let mut nonce_bytes: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let rand = SystemRandom::new();
    rand.fill(&mut nonce_bytes).unwrap();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Encrypt the payload and receive the tag
    println!("Encrypting payload...");
    let tag = sealing_key
        .seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
        .unwrap();
    let tag_bytes = tag.as_ref();

    // Put all components into the confidential package data model, including the demo self-signed cert.
    println!("Creating confidential package...");
    let package = ConfidentialPackage::build_from_encrypted_input(
        application_id,
        application_name,
        vendor,
        &mut in_out,
        &nonce_bytes,
        &tag_bytes,
        &digest.as_ref(),
        &mut signature,
        &SERVICE_PROVIDER_CERTIFICATE,
    );

    // Create and write the output file.
    println!("Writing output...");
    let mut outfile = File::create(&path_to_package)?;
    package.write_to_stream(&mut outfile)?;

    println!("Done.");
    Ok(())
}
