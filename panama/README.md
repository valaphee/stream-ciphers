# PANAMA Stream Cipher Algorithm

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![HAZMAT][hazmat-image]][hazmat-link]

Implementation of the [PANAMA] stream cipher by Joan Daemen and Craig Clapp.

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

This crate does not ensure ciphertexts are authentic (i.e. by using a MAC to
verify ciphertext integrity), which can lead to serious vulnerabilities
if used incorrectly!

No security audits of this crate have ever been performed, and it has not been
thoroughly assessed to ensure its operation is constant-time on common CPU
architectures.

**USE AT YOUR OWN RISK!**


## Examples

```rust
use panama::Panama;
use panama::cipher::{KeyIvInit, StreamCipher};
use hex_literal::hex;

let key = hex!("21d2674aa5855e278988a6b430061efdbf0a6ccb77cb96cd3071075d181ea880");
let nonce = hex!("9a26b80afd983cff419e1a96db6e29436e898ec42ab1a512899e2e69cbc98134");
let plaintext = *b"My Plaintext!! My Dear plaintext!!";
let ciphertext = hex!("526dda62e54800d32ec745df4e6dcc5b6087b97eb5eb0e792e780e7a9730d71b269c");

// Key and IV must be references to the `Array` type.
// Here we use the `Into` trait to convert arrays into it.
let mut cipher = Panama::new(&key.into(), &nonce.into());

let mut buffer = plaintext;

// apply keystream (encrypt)
cipher.apply_keystream(&mut buffer);
assert_eq!(buffer, ciphertext);

let ciphertext = buffer;

// decrypt ciphertext by applying keystream again
let mut cipher = Panama::new(&key.into(), &nonce.into());
cipher.apply_keystream(&mut buffer);
assert_eq!(buffer, plaintext);

// stream ciphers can be used with streaming messages
let mut cipher = Panama::new(&key.into(), &nonce.into());
for chunk in buffer.chunks_mut(3) {
    cipher.apply_keystream(chunk);
}
assert_eq!(buffer, ciphertext);
```

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/panama.svg
[crate-link]: https://crates.io/crates/panama
[docs-image]: https://docs.rs/panama/badge.svg
[docs-link]: https://docs.rs/panama/
[build-image]: https://github.com/valaphee/stream-ciphers/actions/workflows/panama.yml/badge.svg
[build-link]: https://github.com/valaphee/stream-ciphers/actions/workflows/panama.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[//]: # (footnotes)

[PANAMA]: https://en.wikipedia.org/wiki/Panama_(cryptography)
