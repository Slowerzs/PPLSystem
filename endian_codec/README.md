[![crates.io](https://img.shields.io/crates/v/endian_codec.svg)](https://crates.io/crates/endian_codec)
[![Documentation](https://docs.rs/endian_codec/badge.svg)](https://docs.rs/endian_codec/)
![CI master](https://github.com/xoac/endian_codec/workflows/Continuous%20integration/badge.svg?branch=master)
derive: [![crates.io](https://img.shields.io/crates/v/endian_codec_derive.svg)](https://crates.io/crates/endian_codec_derive)

# endian_codec

This crate helps serialize types as bytes and deserialize from bytes with a special
byte order. This crate can be used in [no_std] environment and has no external dependencies.

If you are looking for a small universal binary (de)serializer that works with
[serde], look at [bincode].

Main features:
* A clean way to convert structures to bytes( with bytes order) and back
* Derive
* `no_std`
* no external dependencies

### Examples
```rust
use endian_codec::{PackedSize, EncodeLE, DecodeLE};
// If you look at this structure without checking the documentation, you know it works with
// little-endian notation
#[derive(Debug, PartialEq, Eq, PackedSize, EncodeLE, DecodeLE)]
struct Version {
  major: u16,
  minor: u16,
  patch: u16
}

let mut buf = [0; Version::PACKED_LEN]; // From PackedSize
let test = Version { major: 0, minor: 21, patch: 37 };
// if you work with big- and little-endians, you will not mix them accidentally
test.encode_as_le_bytes(&mut buf);
let test_from_b = Version::decode_from_le_bytes(&buf);
assert_eq!(test, test_from_b);
```

There can be also a situation when you are forced to work with mixed-endians in one struct.
```rust
use endian_codec::{PackedSize, EncodeME};
// even if you only use derive EncodeME, you also need to have required traits in the scope.
use endian_codec::{EncodeLE, EncodeBE}; // for #[endian = "le/be"]

#[derive(PackedSize, EncodeME)]
// You work with a very old system and there are mixed-endians
// There will be only one format "le" or "little" in the next minor version.
struct Request {
  #[endian = "le"]
  cmd: u16,
  #[endian = "little"] // or #[endian = "le"]
  value: i64,
  #[endian = "big"] // or #[endian = "be"]
  timestamp: i128,
}

let mut buf = [0; Request::PACKED_LEN];
let req = Request {
  cmd: 0x44,
  value: 74,
  timestamp: 0xFFFF_FFFF_0000_0000,
};
// here we see me (mixed-endian), just look at the struct definition for details
req.encode_as_me_bytes(&mut buf);

```

#### Why another crate to handle endianess?
* Easy byteorder-encoding structs with multiple fields and consistent encoding
* Learning how to create custom derives
* Making a clean API and auto document code.

#### There are a few other crates that do a similar things:
* [byteorder] -  Library for reading/writing numbers in big-endian and little-endian.
* [bytes] - Buf and BufMut traits that have methods to put and get primitives in the desired endian format.
* [packed_struct] - Safe struct (un-) packing with bit-level control.
* [simple_endian] - Instead of providing functions that convert - create types that store.
variables in the desired endian format.
* [struct_deser] - Inspiration for this crate.



[bincode]:https://crates.io/crates/bincode
[byteorder]:https://crates.io/crates/byteorder
[bytes]:https://crates.io/crates/bytes
[packed_struct]:https://crates.io/crates/packed_struct
[simple_endian]:https://crates.io/crates/simple_endian
[struct_deser]:https://crates.io/crates/struct_deser
[no_std]:https://rust-embedded.github.io/book/intro/no-std.html
[serde]:https://crates.io/crates/serde

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

This project try follow rules:
* [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
* [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

_This README was generated with [cargo-readme](https://github.com/livioribeiro/cargo-readme) from [template](https://github.com/xoac/crates-io-lib-template)_
