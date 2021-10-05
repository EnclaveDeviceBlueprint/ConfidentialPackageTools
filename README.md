# Confidential Package Tools

## Welcome

Welcome to the source code repository for Confidential Package Tools.

## What Is A Confidential Package?

A confidential package is a binary file that is designed to embed a signed and encrypted
confidential payload. Although a confidential payload could be any kind of data, confidential
packages have been designed to embed compiled applications that are intended for execution within a
secure boundary, such as a Trusted Execution Environment (TEE) or similar confidential enclave.

When building confidential applications, it is desirable to protect them with encryption, so that
their confidentiality is maintained while they are in transit or at rest. Once they are installed on
their target computing device, they can be decrypted within the confidential enclave or TEE, which
ensures that confidentiality is also maintained while they are in use.

The confidential package format has been designed to be a convenient way to store and manage
confidential applications from their point of origin on a build agent, right through to their point
of execution within their target secure enclave.

Confidential packages are single, self-contained files that can be stored on disk or easily embedded
in a container for storage in a cloud-based container registry. They are designed to be simple and
to accommodate any workflow.

## How Is This Different From Trusted Applications?

TEE operating systems such as [OP-TEE](https://www.op-tee.org) already provide packaging formats
that allow trusted applications to be signed and encrypted. In OP-TEE the
[sign_encrypt.py](https://github.com/OP-TEE/optee_os/blob/master/scripts/sign_encrypt.py) tool is
used for this purpose, and the OP-TEE operating system has built-in functionality for installing and
decrypting these files.

Confidential packages have a similar purpose, but there are some important differences:

- Confidential packages are **agnostic and portable** with respect to the confidential execution
   environments of the target device. They are designed for use with different processor
   architectures, operating systems and confidential computing technologies.
- Confidential packages are not directly understood by the TEE or similar operating system. In order
   to achieve portability, they are processed by a separate software component that is provisioned
   within the TEE or similar enclave. This component is called the **Confidential Package Manager**
   (CPM). The CPM decrypts the embedded confidential payloads and prepares them for execution.
- Confidential packages are **flexible** with respect to signing workflows, trust chains and key
   management systems. They do not make any assumptions about the source of the encryption key, or
   about the certificate chains that should be used to validate the payload. In this respect, they
   are designed to be used in workflows where the confidential applications are being distributed by
   vendors in a way that is not directly coupled with the device hardware or firmware.
- Confidential packages are **integrated** with key repositories and key sharing mechanisms, using
   the tools in this repository. Encryption keys can be obtained from a variety of sources, and
   exported using secure wrapping protocols, allowing packages to be both built and installed in a
   way that is decoupled from any specific platform or TEE/enclave technology.

## What Do These Tools Do?

The tools in this repository can be used to build and install confidential packages.

The build process is intended for execution on build agents such as development machines, build
servers or agents in a CI pipeline. The build process takes a compiled application as its main
input, and produces a confidential package file. The confidential package file can then be stored or
embedded in an OCI container for onward deployment.

The installation process is intended for execution on a target device such as an edge computing
device. The target device must have a confidential computing environment available to it, such as a
TEE or other hardware-isolated enclave technology. The installer takes a confidential package file
as its main input, and communicates with the Confidential Package Manager (CPM) to decrypt and
deploy the confidential application.

Both processes can be initiated from the same command-line tool, called `cpk-tool`. This tool has
different commands. Use the `cpk-tool build` command to build a confidential package, and the
`cpk-tool install` command to install it onto its target device. Although a common tool is used,
these two steps would normally be executed on different machines as described above. Confidential
packages are completely portable, so it does not matter if they are built on a different platform or
architecture relative to where they are installed.

In addition to understanding the confidential package file format, these tools also integrate with
some documented key-sharing protocols in order to manage the encryption process in a seamless and
secure way. Encryption keys never need to be supplied in clear text on the command line.

## What Are The Dependencies?

For development and experimentation, there are ways to use these tools on a single machine with no
special hardware or firmware requirements and no outside dependencies.

In a real-world scenario, these tools are not entirely stand-alone.

The `cpk-tool install` command has a dependency on the Confidential Package Manager (CPM), which
must be provisioned and running within a TEE or similar secure enclave on the device where the
command is invoked. The tool communicates with the CPM using a set of API contracts that are
expressed in the Enclave Definition Language (EDL), which is part of the
[OpenEnclave](https://openenclave.io/sdk/) project. The use of OpenEnclave and EDL is central to the
way that these tools maintain portability across different TEE or enclave technologies. You can
learn more about the EDL contract in the [Confidential Package
Specification](https://github.com/Scalys/ConfidentialPackageSpecification) repository.

The tools also expect to interact with a **key store**, which provides the encryption keys that are
used to protect the confidential payloads within the package. For development and experimentation,
it is possible to use a simple file on disk as the key store. In real-world deployments, however, it
is expected that the key store would be a service such as a managed HSM or cloud key vault. Since
such services are highly variable in terms of their behaviour and their APIs, the tools use a simple
HTTP web contract that can easily be implemented by a serverless function. Learn more about this in
the [Confidential Package Specification](https://github.com/Scalys/ConfidentialPackageSpecification)
repository.

## What Is The File Format?

The file format for confidential packages is documented in the [Confidential Package
Specification](https://github.com/Scalys/ConfidentialPackageSpecification) repository.

## Can The Tools Be Installed?

Not yet. These tools are still in active development. At the moment, they need to be built from the
source code in this repository. Installation packages and recipes will be made available in the
future.

## How Are The Tools Built?

These tools are written mostly in the [Rust](https://www.rust-lang.org) programming language. To
build the tools from their source code, it is first necessary to install the Rust compiler and its
integrated build system (called "cargo"). Use [this link](https://www.rust-lang.org/tools/install)
to get Rust installed.

Once Rust is installed, clone the repository and change directory to the `cpk-tool` folder before
issuing the command:

`````
cargo build
`````

For testing and experimentation on platforms that do not support confidential computing enclaves,
build the tool in simulation mode as follows:

`````
cargo build --features cpm-simulator
`````

In simulation mode, the `cpk-tool build` and `cpk-tool install` commands can both be used on the
same machine and without any specific hardware or firmware requirements. Use this mode when doing
development on the tools themselves, or in order to easily gain familiarity.

Once the tool has built, try accessing the help functionality with:

`````
./target/debug/cpk-tool build --help
`````

or:

`````
./target/debug/cpk-tool install --help
`````

**Status note**: It is currently necessary to build the whole tool in simulation mode in order to
access just the `cpk-tool build` functionality by itself. In the future, more
conditional-compilation features will be added so that support for individual tool commands can be
either included or excluded.

## Is There A Quick Test?

Yes! It is easy to quickly test the build and installation process for a confidential package
without needing any specialized hardware, and without needing any cloud key management services.
This test can be run on any machine that supports running Rust code.

The following procedure will build a confidential package containing this README file, and perform a
simulated installation of it.

First, build the tool in simulation mode using the instructions above.

Next, from within the `cpk-tool` directory, give the following command. Just copy and paste this -
there is no need to substitute or change anything:

`````
./target/debug/cpk-tool build -i ../README.md -a test -w local -e file -k ./test.json -o ./my_first_confidential_package.cpk
`````

This command will display a warning about the RSA wrapping key, but this is benign for a quick test
- just ignore it!

The output file `my_first_confidential_package.cpk` should have been created in the working
directory. The `cpk` file extension is conventionally used to denote a confidential package file.
This is a binary file, which embeds an encrypted version of the `README.md` file (the file you are
reading now), using an encryption key that was obtained from the `test.json` file. (The `test.json`
file contains a demo AES key that allows the tools to be tested locally without requiring any online
HSM or cloud key vault service).

Now, issue the following command, which prepares for the installation by sharing the encryption key
with the simulated version of the Confidential Package Manager (CPM). In real-world scenarios, the
`sync` command would not be needed, because wrapped encryption keys would be shared with all target
devices by a cloud-managed service.

`````
./target/debug/cpk-tool sync -a test -m file -k ./test.json
`````

Finally, install the package as follows:

`````
./target/debug/cpk-tool install -p ./my_first_confidential_package.cpk
`````

This part of the process is only simulated, so nothing is really getting installed anywhere.
However, the command should produce some output that looks similar to the following:

`````
Opening package...
Reading package manifest (stream 6)...
Package identity: test
Package name: Unknown
Package vendor: Unknown
    Target architecture: aarch64
    Target operating system: OP-TEE
    Version 1.0.0 (2021-10-05 12:52:37.489525 UTC)
Processing package contents...
Connecting with Confidential Package Manager on the host system...
Installing...
Verifying...
    Digest check PASSED.
    Signature check PASSED.
Finished.
`````

This completes the quick test.

## Is It Possible To Contribute?

Yes, absolutely! These tools are being developed as public open source. Look out for a contribution
guide, which should be published quite soon.

## What Is The Licence?

These tools and their source code are being made available under the
[MIT](https://opensource.org/licenses/MIT) license.

## What Is The Current Status Of The Tools?

These tools are currently at the demo/proof-of-concept stage. There is enough functionality
available to build and install confidential packages on real devices and to integrate with real key
stores, but the tools are not yet intended for production use.
