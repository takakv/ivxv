# IVXV

Common data types and cryptographic primitives used by IVXV.

> **NB!** This is not an official IVXV library and is not affiliated with or endorsed by the Estonian State Electoral
> Office or the IVXV project maintainers.
> The official repository for IVXV is [valimised/ivxv](https://github.com/valimised/ivxv).

## Features

- Elliptic-curve ElGamal over P-384
- Non-interactive zero-knowledge proofs of correct decryption
- ASN.1 structures and object identifiers used by IVXV

## Security notes

This library has not been independently audited.

The library relies on RustCrypto for its arithmetic, which uses the `subtle` crate and constant-time formulas so that
secret-dependent operations run in constant time.
However, neither RustCrypto nor this library have been thoroughly assessed to ensure that the generated assembly is
constant time on common CPU architectures.

Use at your own risk!

## Example use

Verify a zero-knowledge proof that a ciphertext decrypts to a claimed plaintext,
given the election public key:

```rust
use ivxv::election::ElectionPublicKey;
use ivxv::proofs::decryption::DecryptionContext;

let pk = ElectionPublicKey::from_pem(pem)?;

let ctx = DecryptionContext::new(&pk);
ctx.verify_der(ciphertext, message, proof)?;
```

See
[ivxv-decproof-verifier](https://github.com/takakv/ivxv-decproof-verifier)
for a real use case.

## License

Licensed under [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
