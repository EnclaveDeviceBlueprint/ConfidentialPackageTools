// Copyright 2021 Contributors to the Confidential Packaging project.
// SPDX-License-Identifier: MIT

//! This module defines key sharing protocols that are needed for the production and consumption
//! of confidential packages. The top-level module defines the protocols as traits, and the various
//! sub-modules implement these traits in some useful ways.
//! 
//! There are two relevant types of key: _encryption keys_ and _wrapping keys_.
//! 
//! Encryption keys are the symmetric keys (such as AES-256) that are used to encrypt the confidential
//! payload in the package. Encryption keys need to be shared between the environment where the package
//! is built (such as a developement machine or a build server), and the environment where it is
//! installed (the target computing device that supports confidential execution). Encryption keys are
//! expected to be provisioned and stored securely, such as in a managed HSM or cloud key vault. These
//! tools are not concerned with the specifics of provisioning and storage. These tools are concerned
//! only with _retrieval_ of encryption keys from their source.
//! 
//! Unlike encryption keys, wrapping keys are asymmetric keys (such as RSA-2048), with a public part and
//! a private part. Wrapping keys are used to encrypt ("wrap") the encryption keys. This allows them
//! to be retrieved securely from their source. Encryption keys are only decrypted once they are inside
//! some suitable secure boundary, such as on the build agent, or within the Trusted Execution Environment
//! (TEE) on the target device. While encryption keys are typically provisioned and stored in a cloud
//! or online service, wrapping keys are more typically provisioned and stored on a local device, with
//! the private part either secured within a TEE, or within some secure hardware like a local HSM.
//! 
//! The traits in this module all model the process of key sharing between sources and destinations,
//! both for encryption keys and for wrapping keys. Different key flows are made possible by combining
//! or pipelining these traits, and making use of their various implementations (or providing new
//! implementations).

pub mod cpm;
pub mod error;
pub mod file;
pub mod http;
pub mod local;
pub mod parsec;

/// Convenient result alias for this module, where errors are of type [KeyError].
pub type Result<T> = std::result::Result<T, error::KeyError>;

/// This trait models the behaviour of an encryption key source, such as a cloud key vault or online
/// HSM.
/// 
/// There are no functions for creating, deleting or enumerating keys. While the underlying key source
/// might well have all of these facilities available, they are not relevant from the perspective of
/// this tool.
/// 
/// The only available function is [wrap], which can be used to encrypt ("wrap") a key with a given
/// identity, and return the encrypted/wrapped key as a result.
pub trait EncryptionKeySource {
    /// Obtains a named key from the key store, encrypts ("wraps") it with the given public key,
    /// and returns the encrypted bytes.
    /// 
    /// The caller is assumed to have access to the corresponding private key for unwrapping,
    /// or at least is able to pass the wrapped key onto a component that can do so.
    /// 
    /// The public key is currently required to be an RSA public key in PKCS#1 DER format,
    /// defined as per [RFC3279](https://datatracker.ietf.org/doc/html/rfc3279):
    /// 
    /// `````
    /// RSAPublicKey ::= SEQUENCE {
    ///           modulus        INTEGER,
    ///           publicExponent INTEGER }
    /// `````
    /// 
    /// The public key would normally have been obtained from a suitable [WrappingKeySource],
    /// which will return a key in the correct format.
    /// 
    /// The resulting byte vector is the direct output of the encryption process, and will be
    /// suitable for passing onto an [EncryptionKeyDestination] or [EncryptionKeyExposure]
    /// object.
    fn wrap(&self, key_id: &String, public_key: &Vec<u8>) -> Result<Vec<u8>>;
}

/// This trait models the behavious of the encyption key destination, which is normally the Confidential
/// Package Manager (CPM) within the TEE of a target device, where a confidential package is being
/// installed.
/// 
/// Encryption keys are _injected_ into a destination using the [unwrap] function. This function does
/// not return the unwrapped/decrypted key to the caller. Instead, the destination will unwrap the key
/// and store it internally within its own secure boundary.
/// 
/// The keys that are injected via this trait will already have been wrapped from an [EncryptionKeySource]
/// using the public part of a wrapping key pair. The private part of the same key pair will be held
/// inside the secure boundary, where it can be used to decrypt ("unwrap") the encryption key. Once
/// unwrapped, the key can be used within that same secure boundary to decrypt and execute the payloads
/// of confidential packages.
pub trait EncryptionKeyDestination {
    /// Injects the given encrypted ("wrapped") key into the destination, which is assumed to have the
    /// required private key for decryption ("unwrapping").
    /// 
    /// The wrapped byte vector is the output from an earlier call to [EncryptionKeySource::wrap].
    fn unwrap(&self, key_id: &String, wrapped: &Vec<u8>) -> Result<()>;
}

/// This trait is implemented by objects that are able to directly expose the contents of a wrapped
/// encryption key.
/// 
/// No objects implementing this trait would exist on a target computing device, because encryption
/// keys can only be unwrapped within the Confidential Package Manager running inside the TEE. On a
/// target device, the only relevant trait is [EncryptionKeyDestination], which can receive the wrapped
/// key in order to be unwrapped within the TEE.
/// 
/// This trait is designed for use on build agents, where there is a need to encrypt the confidential
/// payload and create a confidential package file. Build agents need the plain encryption key in its
/// unwrapped form, in order to execute the encryption process correctly.
pub trait EncryptionKeyExposure {
    /// Decrypts ("unwraps") the given encryption key and returns its raw bytes.
    /// 
    /// The wrapped byte vector is the output from an earlier call to [EncryptionKeySource::wrap].
    fn expose(&self, wrapped: &Vec<u8>) -> Result<Vec<u8>>;
}

/// This trait is implemented by objects that own and manage an asymmetric key pair for key wrapping
/// purposes, and are able to export the public part of the key.
/// 
/// On a target device, the Confidential Package Manager is a wrapping key source, because it owns
/// a key pair whose private part is contained within the secure boundary of its TEE. It is able to
/// yield the public key in order to wrap encryption keys.
/// 
/// On a build agent, wrapping keys can be managed in a variety of ways, such as by using a
/// locally-available [Parsec](https://parsec.community) service to keep the private key safe in
/// a hardware-protected secure boundary.
pub trait WrappingKeySource {
    /// Gets the public part of the wrapping key pair.
    /// 
    /// The public key is currently required to be an RSA public key in PKCS#1 DER format,
    /// defined as per [RFC3279](https://datatracker.ietf.org/doc/html/rfc3279):
    /// 
    /// `````
    /// RSAPublicKey ::= SEQUENCE {
    ///           modulus        INTEGER,
    ///           publicExponent INTEGER }
    /// `````
    /// 
    /// The public key returned by this function can be passed directly to [EncryptionKeySource::wrap].
    fn get_public(&self) -> Result<Vec<u8>>;
}

/// This trait allows the public part of a wrapping key to be published to an external destination
/// as part of a key-sharing flow.
/// 
/// While wrapped encryption keys can sometimes be retrieved directly from an [EncryptionKeySource],
/// there are other situations where the wrapped encryption key needs to be transferred in a two-step
/// process, with the public key first being "published" to some intermediate destination before the
/// wrapped encryption key can be received. An example of this situation is when a digital twin is
/// being used to synchronize the wrapped key between a cloud service and an edge computing device. The
/// public key would be published to the digital twin as a reported property, similar to the way that
/// an IoT thermostat device might publish the current detected temperature. The cloud service would use
/// this public key to wrap any encryption keys that are intended to be shared with the target device,
/// and publish those wrapped keys to the digital twin in the same way (as intended properties).
pub trait WrappingKeyDestination {
    /// Synchronously writes the given public key to the destination, such as by patching a reported
    /// property in a digital twin document.
    /// 
    /// The public key is currently required to be an RSA public key in PKCS#1 DER format,
    /// defined as per [RFC3279](https://datatracker.ietf.org/doc/html/rfc3279):
    /// 
    /// `````
    /// RSAPublicKey ::= SEQUENCE {
    ///           modulus        INTEGER,
    ///           publicExponent INTEGER }
    /// `````
    fn publish_public(&self, wrapping_key: &Vec<u8>) -> Result<()>;
}
