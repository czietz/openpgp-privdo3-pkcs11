OpenPGP-PrivDO3-PKCS11
===========
**PKCS#11 library exposing Private Data Object 3 on OpenPGP cards**

## Purpose

OpenPGP-PrivDO3-PKCS11 is a library with the sole function to give PKCS#11-aware applications – in particular [VeraCrypt](https://veracrypt.io/) – access to the _Private Data Object 3_ (PrivDO3) on OpenPGP smart cards. It has been tested with [Nitrokey 3](https://www.nitrokey.com/) and YubiKey 5, and might also work with other OpenPGP cards.

The [OpenSC](https://github.com/OpenSC/OpenSC) middleware offers very limited support for Private Data Objects on OpenPGP cards, [fully supporting only _Private Data Object 1_](https://github.com/OpenSC/OpenSC/blob/7f2e1062785d1442bab6f7378823c35ece5a91e8/src/pkcs15init/pkcs15-openpgp.c#L562-L569) (PrivDO1). Reading PrivDO1 is *not protected* by any PIN, making it unsuitable for, e.g., securely storing VeraCrypt key files. PrivDO3, on the other hand, can only be read or written after authentication with the user PIN:

| Data object                  | READ access   | WRITE access |
| ---------------------------- | ------------- | ------------ |
| Private use (0101) (PrivDO1) | Always ⚠      | Verify PIN1  |
| Private use (0103) (PrivDO3) | Verify PIN1 ✔ | Verify PIN1  |

(Excerpt from the [*Functional Specification of the OpenPGP application on ISO Smart Card Operating Systems*, Version 3.4](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf).)

## Usage with VeraCrypt

Automatically built binaries are available in the [Releases](https://github.com/czietz/openpgp-privdo3-pkcs11/releases) section.

Configure the `openpgp-privdo3-pkcs11*.dll/.so` matching your operating system as PKCS#11 library under _Settings → Security tokens_. See the [VeraCrypt documentation](https://veracrypt.io/en/Keyfiles%20in%20VeraCrypt.html) for a description of how to use security tokens for key file storage.

Each OpenPGP card can only store _one_ PrivDO3. To prevent accidental overwriting, OpenPGP-PrivDO3-PKCS11 refuses to store a new file when PrivDO3 already exists on the card. You have to delete the existing PrivDO3 before importing a new key file.

❗ **ATTENTION:** If you delete a key file without having a backup, you lose access to all VeraCrypt volumes protected by this key file.

## Limitations

* By design, this library does not implement any cryptographic operations (such as signing or encrypting). Use OpenSC’s PKCS#11 library for cryptography.
* OpenPGP cards are detected when the library is initialized, i.e., when VeraCrypt is started. Therefore, the token or card must be present when VeraCrypt is started.
* The maximum size of PrivDO3 depends on the token. For example, Nitrokey 3 supports up to 4 KiB, whereas YubiKey 5 only supports 255 bytes. PrivDO3 is therefore best used to store very small files. A typical VeraCrypt-generated key file is 64 bytes.
* Each OpenPGP card can only store _one_ PrivDO3. To prevent accidental overwriting, OpenPGP-PrivDO3-PKCS11 refuses to store a new file when PrivDO3 already exists on the card. You have to delete the existing PrivDO3 before importing a new file.
* As stated in the license, this library is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.

## License

OpenPGP-PrivDO3-PKCS11 is available under the terms of the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0). [A human friendly license summary](https://www.tldrlegal.com/license/apache-license-2-0-apache-2-0) is available at tldrlegal.com but the [full license text](LICENSE.md) always prevails.

## Notice

This product includes software developed at The Pkcs11Interop Project (http://www.pkcs11interop.net).
