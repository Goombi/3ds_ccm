# 3ds_ccm

> Simple binary made from the 3DS AES-CCM reimplementation from the wonderful folks making [Citra](https://github.com/citra-emu/citra). Used to [Wrap](https://www.3dbrew.org/wiki/APT:Wrap) and [Unwrap](https://www.3dbrew.org/wiki/APT:Unwrap) data.

## Usage

`./3ds_ccm <action> <nonce_offset> <nonce_size>`

* `<action>` : Either `wrap` to encrypt or `unwrap` to decrypt.
* `<nonce_offset>` : Where in the decrypted data is the nonce located (Always at the begginning of encrypted). Same value that would be given to the 3DS [APT:Wrap](https://www.3dbrew.org/wiki/APT:Wrap) and [APT:Unwrap](https://www.3dbrew.org/wiki/APT:Unwrap).
* `<nonce_size>` : Size of the nonce.

Additionnaly, the key and the actual data have to be provided as hex strings on the standard input, separated by a line break.

### Output and return value

On a return value of 0, the output will be the data in hex form in stdout.

On a return value of 1, the error will be written to stdout (as wrong as it might be to some).

### Exemple

`echo -e "0123456789ABCDEF0123456789ABCDEF\nDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF" | ./3ds_ccm wrap 12 10`

`echo -e "0123456789ABCDEF0123456789ABCDEF\nDEADBEEFDEADBEEFC106D40E5EC92D612B958B7ADBF4D32000493FD1C06F66C22EC36638ADB5BBA4DFDBA343D79DA4D70B2E3F668491365F6A4B69D3A0A04FAF3FDD13FC2CB1C5371C656CB2B858F6FF7427D94ADB81A96B1F2A1DF663445AF0586482EF00E5117461A6EA7C85E478E7" | ./3ds_ccm unwrap 12 10`

## Building

Simple install CryptoPP (`apt-get install libcrypto++ libcrypto++-dev` for Debian) and run `make`.

## License

> See LICENSE file.

Under GPLv2 from Citra. Here is a brief summary of the changes made to the code :

* Cut through 99% of the code to only keep the 3DS "custom" (read broken) AES-CCM implementation.
* Added a CLI interface around.