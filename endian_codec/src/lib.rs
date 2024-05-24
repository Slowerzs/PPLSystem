//! This crate helps serialize types as bytes and deserialize from bytes with a special
//! byte order. This crate can be used in [no_std] environment and has no external dependencies.
//!
//! If you are looking for a small universal binary (de)serializer that works with
//! [serde], look at [bincode].
//!
//! Main features:
//! * A clean way to convert structures to bytes( with bytes order) and back
//! * Derive
//! * `no_std`
//! * no external dependencies
//!
//! ## Examples
//! ```rust
//! use endian_codec::{PackedSize, EncodeLE, DecodeLE};
//! // If you look at this structure without checking the documentation, you know it works with
//! // little-endian notation
//! #[derive(Debug, PartialEq, Eq, PackedSize, EncodeLE, DecodeLE)]
//! struct Version {
//!   major: u16,
//!   minor: u16,
//!   patch: u16
//! }
//!
//! let mut buf = [0; Version::PACKED_LEN]; // From PackedSize
//! let test = Version { major: 0, minor: 21, patch: 37 };
//! // if you work with big- and little-endians, you will not mix them accidentally
//! test.encode_as_le_bytes(&mut buf);
//! let test_from_b = Version::decode_from_le_bytes(&buf);
//! assert_eq!(test, test_from_b);
//! ```
//!
//! There can be also a situation when you are forced to work with mixed-endians in one struct.
//! ```rust
//! use endian_codec::{PackedSize, EncodeME};
//! // even if you only use derive EncodeME, you also need to have required traits in the scope.
//! use endian_codec::{EncodeLE, EncodeBE}; // for #[endian = "le/be"]
//!
//! #[derive(PackedSize, EncodeME)]
//! // You work with a very old system and there are mixed-endians
//! // There will be only one format "le" or "little" in the next minor version.
//! struct Request {
//!   #[endian = "le"]
//!   cmd: u16,
//!   #[endian = "little"] // or #[endian = "le"]
//!   value: i64,
//!   #[endian = "big"] // or #[endian = "be"]
//!   timestamp: i128,
//! }
//!
//! let mut buf = [0; Request::PACKED_LEN];
//! let req = Request {
//!   cmd: 0x44,
//!   value: 74,
//!   timestamp: 0xFFFF_FFFF_0000_0000,
//! };
//! // here we see me (mixed-endian), just look at the struct definition for details
//! req.encode_as_me_bytes(&mut buf);
//!
//! ```
//!
//! ### Why another crate to handle endianess?
//! * Easy byteorder-encoding structs with multiple fields and consistent encoding
//! * Learning how to create custom derives
//! * Making a clean API and auto document code.
//!
//! ### There are a few other crates that do a similar things:
//! * [byteorder] -  Library for reading/writing numbers in big-endian and little-endian.
//! * [bytes] - Buf and BufMut traits that have methods to put and get primitives in the desired endian format.
//! * [packed_struct] - Safe struct (un-) packing with bit-level control.
//! * [simple_endian] - Instead of providing functions that convert - create types that store.
//! variables in the desired endian format.
//! * [struct_deser] - Inspiration for this crate.
//!
//!
//!
//! [bincode]:https://crates.io/crates/bincode
//! [byteorder]:https://crates.io/crates/byteorder
//! [bytes]:https://crates.io/crates/bytes
//! [packed_struct]:https://crates.io/crates/packed_struct
//! [simple_endian]:https://crates.io/crates/simple_endian
//! [struct_deser]:https://crates.io/crates/struct_deser
//! [no_std]:https://rust-embedded.github.io/book/intro/no-std.html
//! [serde]:https://crates.io/crates/serde

#![no_std]
use core::mem::size_of;

#[cfg(feature = "endian_codec_derive")]
pub use endian_codec_derive::*;

/// Encoded as little-endian bytes.
pub trait EncodeLE: PackedSize {
    /// Borrow `self` and pack into `bytes` using little-endian representation. Return the packed size in bytes.
    ///
    /// # Panics
    /// Panic if [PackedSize](PackedSize) represents a different size than `bytes` slice.
    ///
    fn encode_as_le_bytes(&self, bytes: &mut [u8]) -> usize;
}

/// Encoded as big-endian bytes.
pub trait EncodeBE: PackedSize {
    /// Borrow `self` and pack into `bytes` using big-endian representation. Return the packed size in bytes.
    ///
    /// # Panics
    ///
    /// Panic if [PackedSize](PackedSize) represents a different size than `bytes` slice.
    fn encode_as_be_bytes(&self, bytes: &mut [u8]) -> usize;
}

/// Encode using mixed-endian bytes.
///
/// # Note
/// If you only use big-/little-endians, consider using [EncodeBE](EncodeBE) / [EncodeLE](EncodeLE) traits instead.
pub trait EncodeME: PackedSize {
    /// Borrow `self` and pack into `bytes` using mixed(custom)-endian representation. Return the packed size in bytes.
    ///
    /// # Panics
    ///
    /// Panic if [PackedSize](PackedSize) represents a different size than `bytes` slice.
    fn encode_as_me_bytes(&self, bytes: &mut [u8]) -> usize;
}

/// Decode from bytes stored as a little-endian.
pub trait DecodeLE: PackedSize {
    /// Read `bytes` slice packed as little-endian bytes and create `Self` from them
    ///
    /// # Panics
    ///
    /// Panic if [PackedSize](PackedSize) represents a different size than `bytes` slice.
    fn decode_from_le_bytes(bytes: &[u8]) -> Self;
}

/// Decode from bytes stored as a big-endian.
pub trait DecodeBE: PackedSize {
    /// Read `bytes` slice packed as big-endian bytes and create `Self` from them
    ///
    /// # Panics
    ///
    /// Panic if [PackedSize](PackedSize) represents a different size than `bytes` slice.
    fn decode_from_be_bytes(bytes: &[u8]) -> Self;
}

/// Decode from bytes stored as a mixed-endian.
///
/// # Note
/// If you only use big-/little-endians, consider using [DecodeBE](DecodeBE) / [DecodeLE](DecodeLE) traits instead.
pub trait DecodeME: PackedSize {
    /// Read `bytes` slice packed as mixed(custom)-endian bytes and create `Self` from them
    ///
    /// # Panics
    ///
    /// Panic if [PackedSize](PackedSize) represents a different size than `bytes` slice.
    fn decode_from_me_bytes(bytes: &[u8]) -> Self;
}

/// Represents size of a struct as packed bytes.
///
/// At this moment all settings with [repr](https://doc.rust-lang.org/nomicon/other-reprs.html)
/// attribute are ignored.
///
/// In other words if struct is marked as `repr(packed)` attribute, `std::mem::sizeof<T>()` should return the
/// same value as <T as PackedSize>::PACKED_LEN.
///
/// ```
/// // On a 64-bit machine, the size of struct A can be 16 bytes to make it more optimized for speed.
/// // but `PACKED_LEN` must be set to 12 bytes.
/// struct A {
///   p: i32,
///   v: i64,
/// }
/// ```
///
pub trait PackedSize {
    const PACKED_LEN: usize;
}

macro_rules! impl_codec_for_primitives {
    ($type:ty, $byte_len:expr) => {
        impl PackedSize for $type {
            const PACKED_LEN: usize = $byte_len;
        }

        impl EncodeLE for $type {
            #[inline]
            fn encode_as_le_bytes(&self, bytes: &mut [u8]) -> usize {
                bytes.copy_from_slice(&(self.to_le_bytes()));
                $byte_len
            }
        }

        impl EncodeBE for $type {
            #[inline]
            fn encode_as_be_bytes(&self, bytes: &mut [u8]) -> usize {
                bytes.copy_from_slice(&(self.to_be_bytes()));
                $byte_len
            }
        }

        impl DecodeLE for $type {
            #[inline]
            fn decode_from_le_bytes(bytes: &[u8]) -> Self {
                let mut arr = [0; $byte_len];
                arr.copy_from_slice(&bytes);
                Self::from_le_bytes(arr)
            }
        }

        impl DecodeBE for $type {
            #[inline]
            fn decode_from_be_bytes(bytes: &[u8]) -> Self {
                let mut arr = [0; $byte_len];
                arr.copy_from_slice(&bytes);
                Self::from_be_bytes(arr)
            }
        }
    };
}

impl_codec_for_primitives!(u8, 1);
impl_codec_for_primitives!(i8, 1);

impl EncodeME for u8 {
    #[inline]
    fn encode_as_me_bytes(&self, bytes: &mut [u8]) -> usize {
        bytes.copy_from_slice(&(self.to_be_bytes()));
        1
    }
}

impl DecodeME for u8 {
    #[inline]
    fn decode_from_me_bytes(bytes: &[u8]) -> Self {
        let mut arr = [0; 1];
        arr.copy_from_slice(bytes);
        Self::from_le_bytes(arr)
    }
}

impl_codec_for_primitives!(u16, 2);
impl_codec_for_primitives!(i16, 2);
impl_codec_for_primitives!(u32, 4);
impl_codec_for_primitives!(i32, 4);
impl_codec_for_primitives!(u64, 8);
impl_codec_for_primitives!(i64, 8);
impl_codec_for_primitives!(u128, 16);
impl_codec_for_primitives!(i128, 16);
impl_codec_for_primitives!(usize, size_of::<usize>());
impl_codec_for_primitives!(isize, size_of::<isize>());

impl<T: PackedSize, const S: usize> PackedSize for [T; S] {
    const PACKED_LEN: usize = T::PACKED_LEN * S;
}

impl<T: EncodeBE, const S: usize> EncodeBE for [T; S] {
    fn encode_as_be_bytes(&self, bytes: &mut [u8]) -> usize {
        let size = T::PACKED_LEN;

        for (i, value) in self.iter().enumerate() {
            value.encode_as_be_bytes(&mut bytes[i * size..(i + 1) * size]);
        }

        size * self.len()
    }
}

impl<T: EncodeLE, const S: usize> EncodeLE for [T; S] {
    fn encode_as_le_bytes(&self, bytes: &mut [u8]) -> usize {
        let size = T::PACKED_LEN;

        for (i, value) in self.iter().enumerate() {
            value.encode_as_le_bytes(&mut bytes[i * size..(i + 1) * size]);
        }

        size * self.len()
    }
}

impl<T: EncodeME, const S: usize> EncodeME for [T; S] {
    fn encode_as_me_bytes(&self, bytes: &mut [u8]) -> usize {
        let size = T::PACKED_LEN;

        for (i, value) in self.iter().enumerate() {
            value.encode_as_me_bytes(&mut bytes[i * size..(i + 1) * size]);
        }

        size * self.len()
    }
}

impl<T: DecodeBE, const S: usize> DecodeBE for [T; S] {
    fn decode_from_be_bytes(bytes: &[u8]) -> Self {
        let size = T::PACKED_LEN;
        let mut i: usize = 0;

        [(); S].map(|_| {
            let res = T::decode_from_be_bytes(&bytes[i * size..(i + 1) * size]);
            i += 1;
            res
        })
    }
}

impl<T> PackedSize for *mut T {
    const PACKED_LEN: usize = size_of::<*mut T>();
}

impl<T> PackedSize for *const T {
    const PACKED_LEN: usize = size_of::<*const T>();
}

impl<T: DecodeLE, const S: usize> DecodeLE for [T; S] {
    fn decode_from_le_bytes(bytes: &[u8]) -> Self {
        let size = T::PACKED_LEN;
        let mut i: usize = 0;

        [(); S].map(|_| {
            let res = T::decode_from_le_bytes(&bytes[i * size..(i + 1) * size]);
            i += 1;
            res
        })
    }
}

impl<T: DecodeME, const S: usize> DecodeME for [T; S] {
    fn decode_from_me_bytes(bytes: &[u8]) -> Self {
        let size = T::PACKED_LEN;
        let mut i: usize = 0;

        [(); S].map(|_| {
            let res = T::decode_from_me_bytes(&bytes[i * size..(i + 1) * size]);
            i += 1;
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_endian_size() {
        #[derive(PackedSize)]
        struct A {};
        assert_eq!(A::PACKED_LEN, 0);

        #[derive(PackedSize)]
        struct B {
            _a: u16,
        }
        assert_eq!(B::PACKED_LEN, 2);

        #[derive(PackedSize)]
        struct C {
            _a: u16,
            _b: u16,
        }
        assert_eq!(C::PACKED_LEN, 2 + 2);
    }

    #[test]
    fn derive_littlendian_serialize() {
        #[derive(PackedSize, EncodeLE)]
        struct Example {
            a: u16,
        }

        let t = Example { a: 5 };
        let mut b = [0; 2];
        t.encode_as_le_bytes(&mut b);
    }

    #[test]
    fn derive_bigendian_serialize() {
        #[derive(PackedSize, EncodeBE)]
        struct Example {
            a: u16,
        }

        let t = Example { a: 5 };
        let mut b = [0; 2];
        t.encode_as_be_bytes(&mut b);
    }

    #[test]
    fn derive_mixed_endian_serialize() {
        #[derive(PackedSize, EncodeME, Default)]
        struct Example {
            #[endian = "le"]
            a: u16,
            #[endian = "be"]
            b: u16,
            #[endian = "little"]
            aa: i16,
            #[endian = "big"]
            bb: i16,
        }

        let t = Example::default();
        let mut b = [0; 8];
        t.encode_as_me_bytes(&mut b);
    }

    #[test]
    fn derive_all_serialize() {
        #[derive(Default, PackedSize, EncodeLE, EncodeBE, EncodeME)]
        struct Example {
            #[endian = "be"]
            a: u16,
            b: [u8; 32],
        }

        let t = Example::default();
        let mut b = [0; 34];
        t.encode_as_me_bytes(&mut b);
        t.encode_as_be_bytes(&mut b);
        t.encode_as_le_bytes(&mut b);
    }

    #[test]
    fn derive_all() {
        #[derive(
            Default, PackedSize, EncodeLE, EncodeBE, EncodeME, DecodeLE, DecodeBE, DecodeME,
        )]
        struct Example {
            #[endian = "be"]
            a: u16,
        }

        let t = Example::default();
        let mut b = [0; 2];
        t.encode_as_me_bytes(&mut b);
        t.encode_as_be_bytes(&mut b);
        t.encode_as_le_bytes(&mut b);
    }

    #[test]
    fn test_codec_2bytes_primitives() {
        #[derive(Debug, PartialEq, Eq, PackedSize, EncodeLE, DecodeLE, EncodeBE, DecodeBE)]
        struct A {
            a: u16,
            b: i16,
        }

        let test = A { a: 0x2F, b: 0x2F00 };
        assert_eq!(A::PACKED_LEN, 4);
        let mut bytes = [0; A::PACKED_LEN];

        // LE
        let size = test.encode_as_le_bytes(&mut bytes);
        assert_eq!([47, 0, 0, 47], bytes);
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_le_bytes(&bytes);
        assert_eq!(test, test_back);

        //BE
        let size = test.encode_as_be_bytes(&mut bytes);
        assert_eq!([0, 47, 47, 0], bytes);
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_be_bytes(&bytes);
        assert_eq!(test, test_back);
    }

    #[test]
    fn test_codec_4bytes_primitives() {
        #[derive(Debug, PartialEq, Eq, PackedSize, EncodeLE, DecodeLE, EncodeBE, DecodeBE)]
        struct A {
            a: u32,
            b: i32,
        }

        let test = A {
            a: 0x2F,
            b: 0x2F000000,
        };
        assert_eq!(A::PACKED_LEN, 8);
        let mut bytes = [0; A::PACKED_LEN];

        // LE
        let size = test.encode_as_le_bytes(&mut bytes);
        assert_eq!([47, 0, 0, 0, 0, 0, 0, 47], bytes);
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_le_bytes(&bytes);
        assert_eq!(test, test_back);

        //BE
        let size = test.encode_as_be_bytes(&mut bytes);
        assert_eq!([0, 0, 0, 47, 47, 0, 0, 0], bytes);
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_be_bytes(&bytes);
        assert_eq!(test, test_back);
    }

    #[test]
    fn test_codec_8bytes_primitives() {
        #[derive(Debug, PartialEq, Eq, PackedSize, EncodeLE, DecodeLE, EncodeBE, DecodeBE)]
        struct A {
            a: u64,
            b: i64,
        }

        let test = A {
            a: 0x2F,
            b: 0x2F000000_00000000,
        };
        assert_eq!(A::PACKED_LEN, 16);
        let mut bytes = [0; A::PACKED_LEN];

        // LE
        let size = test.encode_as_le_bytes(&mut bytes);
        assert_eq!([47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47], bytes);
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_le_bytes(&bytes);
        assert_eq!(test, test_back);

        //BE
        let size = test.encode_as_be_bytes(&mut bytes);
        assert_eq!([0, 0, 0, 0, 0, 0, 0, 47, 47, 0, 0, 0, 0, 0, 0, 0,], bytes);
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_be_bytes(&bytes);
        assert_eq!(test, test_back);
    }

    #[test]
    fn test_codec_16bytes_primitives() {
        #[derive(Debug, PartialEq, Eq, PackedSize, EncodeLE, DecodeLE, EncodeBE, DecodeBE)]
        struct A {
            a: u128,
            b: i128,
        }

        let test = A {
            a: 0x2F,
            b: 0x2F000000_00000000_00000000_00000000,
        };
        assert_eq!(A::PACKED_LEN, 32);
        let mut bytes = [0; A::PACKED_LEN];

        // LE
        let size = test.encode_as_le_bytes(&mut bytes);
        assert_eq!(
            [
                47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 47
            ],
            bytes
        );
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_le_bytes(&bytes);
        assert_eq!(test, test_back);

        //BE
        let size = test.encode_as_be_bytes(&mut bytes);
        assert_eq!(
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            bytes
        );
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_be_bytes(&bytes);
        assert_eq!(test, test_back);
    }

    #[test]
    fn test_codec_nested() {
        #[derive(Debug, PartialEq, Eq, PackedSize, EncodeLE, DecodeLE, EncodeBE, DecodeBE)]
        struct A {
            a: u32,
            b: u8,
        }

        #[derive(Debug, PartialEq, Eq, PackedSize, EncodeLE, DecodeLE, EncodeBE, DecodeBE)]
        struct B {
            a: A,
            b: u16,
        }

        let test = B {
            a: A { a: 0x2F, b: 0x88 },
            b: 0x55,
        };

        assert_eq!(B::PACKED_LEN, 7);
        let mut bytes = [0; B::PACKED_LEN];

        // LE
        let size = test.encode_as_le_bytes(&mut bytes);
        assert_eq!([0x2f, 0, 0, 0, 0x88, 0x55, 0], bytes);
        assert_eq!(B::PACKED_LEN, size);

        let test_back = B::decode_from_le_bytes(&bytes);
        assert_eq!(test, test_back);

        //BE
        let size = test.encode_as_be_bytes(&mut bytes);
        assert_eq!([0, 0, 0, 0x2f, 0x88, 0, 0x55], bytes);
        assert_eq!(B::PACKED_LEN, size);

        let test_back = B::decode_from_be_bytes(&bytes);
        assert_eq!(test, test_back);
    }

    #[test]
    fn test_codec_array() {
        type A = [u16; 8];

        let mut i = 0;
        let test: A = [(); 8].map(|_| {
            let ret = i as u16;
            i += 1;
            ret
        });

        assert_eq!(A::PACKED_LEN, 16);
        let mut bytes = [0; A::PACKED_LEN];

        //LE
        let size = test.encode_as_le_bytes(&mut bytes);
        assert_eq!([0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0], bytes);
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_le_bytes(&bytes);
        assert_eq!(test, test_back);

        //BE
        let size = test.encode_as_be_bytes(&mut bytes);
        assert_eq!([0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7], bytes);
        assert_eq!(A::PACKED_LEN, size);

        let test_back = A::decode_from_be_bytes(&bytes);
        assert_eq!(test, test_back);
    }

    /*
     This will not compile because EncodeME derive require A to implement EncodeME.
    #[test]
    fn derive_parameters() {
        #[derive(PackedSize, EncodeME)]
        struct Example<A> {
            #[endian = "big"]
            a: A,
            #[endian = "little"]
            be: u16,
        }
    }
    */
}
