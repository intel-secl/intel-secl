# Intel<sup>®</sup> Security Libraries for Data Center  - Key Broker Service
#### The Intel<sup>®</sup> SecL - DC Key Broker Service(KBS) component performs key distribution using platform trust to authorize key transfers. The KBS verifies the host's attestation from the Verification Service, verifies all digital signatures, and retains final control over whether the decryption key is issued. If the server's attestation meets the policy requirements, the KBS issues a decryption key itself wrapped using the AIK-derived binding key from the host that was attested, cryptographically ensuring that only the attested host can decrypt the requested image

## Key features
- Provides and retains encryption/decryption keys for virtual machine images / docker images
- The Key Broker Service connects to a back-end 3rd Party KMIP-compliant key management service for key creation and vaulting services
- Provides and Retains Encryption keys for Secure Key Caching Usecase
- Acts as relying party to facilitate attestation of SGX ECDSA Quote (Secure Key Caching Usecase)
- Provides Key Transfer Policy validation engine to ensure keys are released to trusted clients

## Build Key Broker Service

- Git clone the `Key Broker Service`
- Run scripts to build the `Key Broker Service`

```shell
$ git clone https://github.com/intel-secl/intel-secl.git
$ cd intel-secl
$ make kbs-installer
```

# Links
 - Use [Automated Build Steps](https://01.org/intel-secl/documentation/build-installation-scripts) to build all repositories in one go, this will also provide provision to install prerequisites and would handle order and version of dependent repositories.

***Note:** Automated script would install a specific version of the build tools, which might be different than the one you are currently using*
 - [Product Documentation](https://01.org/intel-secl/documentation/intel%C2%AE-secl-dc-product-guide)
