//! [![Crate](https://img.shields.io/crates/v/h2transformer.svg)](https://crates.io/crates/h2transformer)
//!
//! H2Transformer is a library for transforming raw data between encodings.
//!
//! As part of [h2gb](https://github.com/h2gb), it's common to extract a buffer
//! from a binary that's encoded in some format - Base64, hex string, etc.
//!
//! This library can detect and transform common formats. It can also
//! transform back to the original data with a constant length and without
//! saving any context (while the length is constant, the data isn't always
//! identical - like the case of Base32 and hex strings). If proper undo/redo
//! is needed, this won't fit the bill.
//!
//! Check out the definition of the `H2Transformation` enum for full details on
//! everything it can do!
//!
//! # Usage
//!
//! The public API is pretty straight forward. Here's an example that transforms
//! then untransforms some hex data:
//!
//!
//! ```
//! use h2transformer::H2Transformation;
//!
//! // Input (note that some are uppercase and some are lower - that's allowed)
//! let i: Vec<u8> = b"48656c6C6F2c20776f726c64".to_vec();
//!
//! // Output
//! let o = H2Transformation::FromHex.transform(&i).unwrap();
//!
//! // It's "Hello, world"
//! assert_eq!(b"Hello, world".to_vec(), o);
//!
//! // Transform back to the original
//! let i = H2Transformation::FromHex.untransform(&o).unwrap();
//!
//! // Get the original back - note that it's the same length, but the case has
//! // been normalized
//! assert_eq!(b"48656c6c6f2c20776f726c64".to_vec(), i);
//! ```

use simple_error::{SimpleResult, bail};

use base64;
use base32;
use inflate;

#[cfg(feature = "serialize")]
use serde::{Serialize, Deserialize};

/// When performing an XorByConstant transformation, this represents the size
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Copy)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum XorSize {
    /// One byte / 8 bits - eg, `0x12`
    EightBit(u8),

    /// Two bytes / 16 bits - eg, `0x1234`
    SixteenBit(u16),

    /// Four bytes / 32 bits - eg, `0x12345678`
    ThirtyTwoBit(u32),

    /// Eight bytes / 64 bits - eg, `0x123456789abcdef0`
    SixtyFourBit(u64),
}

/// Which transformation to perform.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Copy)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum H2Transformation {
    /// No transformation - simply returns the same value. Mostly here for
    /// testing.
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "abcdef"
    /// let i: Vec<u8> = b"abcdef".to_vec();
    ///
    /// // Output: "abcdef"
    /// let o = H2Transformation::Null.transform(&i);
    /// assert_eq!(Ok(b"abcdef".to_vec()), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// n/a
    Null,

    /// Xor each byte / word / dword / qword by a constant. Operates on eight,
    /// 16, 32, or 64-bit chunks.
    ///
    /// # Examples
    ///
    /// ## Eight bit
    ///
    /// ```
    /// use h2transformer::{H2Transformation, XorSize};
    ///
    /// // Input: "\x00\x01\x02\x03", XorSize::EightBit(0xFF)
    /// let i: Vec<u8> = b"\x00\x01\x02\x03".to_vec();
    ///
    /// // Output: "\xff\xfe\xfd\xfc"
    /// let o = H2Transformation::XorByConstant(XorSize::EightBit(0xFF)).transform(&i);
    /// assert_eq!(Ok(b"\xff\xfe\xfd\xfc".to_vec()), o);
    /// ```
    ///
    /// ## Sixteen bit
    ///
    /// ```
    /// use h2transformer::{H2Transformation, XorSize};
    ///
    /// // Input: "\x00\x01\x02\x03", XorSize::SixteenBit(0xFF00)
    /// let i: Vec<u8> = b"\x00\x01\x02\x03".to_vec();

    /// // Output: "\xFF\x01\xFD\x03"
    /// let o = H2Transformation::XorByConstant(XorSize::SixteenBit(0xFF00)).transform(&i);
    /// assert_eq!(Ok(b"\xff\x01\xfd\x03".to_vec()), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// The size of the input buffer must be a multiple of the XOR bit size.
    ///
    /// ```
    /// use h2transformer::{H2Transformation, XorSize};
    ///
    /// let i: Vec<u8> = b"\x00".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::XorByConstant(XorSize::SixteenBit(0xFF00)).transform(&i).is_err());
    /// ```
    XorByConstant(XorSize),

    /// Convert from standard Base64 with padding.
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "AQIDBA=="
    /// let i: Vec<u8> = b"AQIDBA==".to_vec();
    ///
    /// // Output: "\x01\x02\x03\x04"
    /// let o = H2Transformation::FromBase64.transform(&i).unwrap();
    ///
    /// assert_eq!(b"\x01\x02\x03\x04".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid Base64 with correct padding and decode to full bytes.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base64~".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase64.transform(&i).is_err());
    /// ```
    FromBase64,

    /// Convert from standard Base64 with NO padding.
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "AQIDBA"
    /// let i: Vec<u8> = b"AQIDBA".to_vec();
    ///
    /// // Output: "\x01\x02\x03\x04"
    /// let o = H2Transformation::FromBase64NoPadding.transform(&i).unwrap();
    ///
    /// assert_eq!(b"\x01\x02\x03\x04".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid Base64 with NO padding whatsoever, and decode to full bytes.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base64~".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase64NoPadding.transform(&i).is_err());
    /// ```
    FromBase64NoPadding,

    /// Convert from standard Base64 with optional padding, with some attempt
    /// to ignore problems.
    ///
    /// This is a ONE-WAY transformation!
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "AQIDBA="
    /// let i: Vec<u8> = b"AQIDBA=".to_vec();
    ///
    /// // Output: "\x01\x02\x03\x04"
    /// let o = H2Transformation::FromBase64Permissive.transform(&i).unwrap();
    ///
    /// assert_eq!(b"\x01\x02\x03\x04".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid enough Base64.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base64~".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase64Permissive.transform(&i).is_err());
    /// ```
    FromBase64Permissive,

    /// Convert from URL-safe Base64 with padding - that is, `+` becomes `-`
    /// and `/` becomes `_`.
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "aa--_z8="
    /// let i: Vec<u8> = b"aa--_z8=".to_vec();
    ///
    /// // Output: "\x69\xaf\xbe\xff\x3f"
    /// let o = H2Transformation::FromBase64URL.transform(&i).unwrap();
    ///
    /// assert_eq!(b"\x69\xaf\xbe\xff\x3f".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid Base64 with correct padding and decode to full bytes.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base64~".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase64URL.transform(&i).is_err());
    /// ```
    FromBase64URL,

    /// Convert from URL-safe Base64 with NO padding.
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "aa--_z8"
    /// let i: Vec<u8> = b"aa--_z8".to_vec();
    ///
    /// // Output: "\x69\xaf\xbe\xff\x3f"
    /// let o = H2Transformation::FromBase64URLNoPadding.transform(&i).unwrap();
    ///
    /// assert_eq!(b"\x69\xaf\xbe\xff\x3f".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid Base64 with NO padding whatsoever, and decode to full bytes.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base64~".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase64URLNoPadding.transform(&i).is_err());
    /// ```
    FromBase64URLNoPadding,

    /// Convert from URL-safe Base64URL with optional padding, with some attempt
    /// to ignore problems.
    ///
    /// This is a ONE-WAY transformation!
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "aa--_z8"
    /// let i: Vec<u8> = b"aa--_z8".to_vec();
    ///
    /// // Output: "\x69\xaf\xbe\xff\x3f"
    /// let o = H2Transformation::FromBase64URLPermissive.transform(&i).unwrap();
    ///
    /// assert_eq!(b"\x69\xaf\xbe\xff\x3f".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid enough Base64.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base64~".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase64URLPermissive.transform(&i).is_err());
    /// ```
    FromBase64URLPermissive,

    /// Convert from standard Base32 with padding. Case is ignored.
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "AEBAGBA="
    /// let i: Vec<u8> = b"AEBAGBA=".to_vec();
    ///
    /// // Output: "\x01\x02\x03\x04"
    /// let o = H2Transformation::FromBase32.transform(&i).unwrap();
    ///
    /// assert_eq!(b"\x01\x02\x03\x04".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid Base32 with correct padding and decode to full bytes.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base32~".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase32.transform(&i).is_err());
    /// ```
    FromBase32,

    /// Convert from standard Base32 with no padding. Case is ignored.
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "AEBAGBA"
    /// let i: Vec<u8> = b"AEBAGBA".to_vec();
    ///
    /// // Output: "\x01\x02\x03\x04"
    /// let o = H2Transformation::FromBase32NoPadding.transform(&i).unwrap();
    ///
    /// assert_eq!(b"\x01\x02\x03\x04".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid Base32 with no padding and decode to full bytes.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base32~".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase32NoPadding.transform(&i).is_err());
    /// ```
    FromBase32NoPadding,

    /// Convert from Base32 using the Crockford alphabet, which does not allow
    /// padding. Case is ignored, and ambiguous letters (like i/l/L) are
    /// treated the same. Untransforming is possible, but will be normalized.
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "91JPRV3F"
    /// let i: Vec<u8> = b"91JPRV3F".to_vec();
    ///
    /// // Output: "Hello"
    /// let o = H2Transformation::FromBase32Crockford.transform(&i).unwrap();
    ///
    /// assert_eq!(b"Hello".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid Base32 Crockford with no padding and decode to full bytes.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base32~".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase32Crockford.transform(&i).is_err());
    /// ```
    FromBase32Crockford,

    /// Convert from standard Base32 with optional padding. Any non-Base32
    /// characters are ignored and discarded.
    ///
    /// This is a ONE-WAY transformation!
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "AEBAGBA="
    /// let i: Vec<u8> = b"AEBAGBA=".to_vec();
    ///
    /// // Output: "\x01\x02\x03\x04"
    /// let o = H2Transformation::FromBase32.transform(&i).unwrap();
    ///
    /// assert_eq!(b"\x01\x02\x03\x04".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be close enough to Base32 and decode to full bytes.
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"Not valid base32~0123456789".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase32Permissive.transform(&i).is_err());
    /// ```
    FromBase32Permissive,

    /// Convert from Base32 using the Crockford alphabet, but allow optional
    /// padding. Case is ignored, and ambiguous letters (like i/l/L) are
    /// treated the same. All non-Base32 characters are ignored.
    ///
    /// This is a ONE-WAY transformation!
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "91JPRV3F=="
    /// let i: Vec<u8> = b"91JPRV3F==".to_vec();
    ///
    /// // Output: "Hello"
    /// let o = H2Transformation::FromBase32CrockfordPermissive.transform(&i).unwrap();
    ///
    /// assert_eq!(b"Hello".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid enough Base32 Crockford and decode to full bytes (the
    /// letter 'u', for example, is not allowed)
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// let i: Vec<u8> = b"uuuuu".to_vec();
    ///
    /// // Error
    /// assert!(H2Transformation::FromBase32CrockfordPermissive.transform(&i).is_err());
    /// ```
    FromBase32CrockfordPermissive,

    /// Convert from Zlib "Deflated" format with no header. Uses the
    /// [inflate](https://github.com/image-rs/inflate) library.
    ///
    /// This is a ONE-WAY transformation!
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid deflated data.
    FromDeflated,

    /// Convert from Zlib "Deflated" format with a header. Uses the
    /// [inflate](https://github.com/image-rs/inflate) library.
    ///
    /// This is a ONE-WAY transformation!
    ///
    /// # Restrictions / errors
    ///
    /// Must be valid deflated data with a valid checksum.
    FromDeflatedZlib,

    /// Convert from a hex string. Case is ignored.
    ///
    /// # Example
    ///
    /// ```
    /// use h2transformer::H2Transformation;
    ///
    /// // Input: "41424344"
    /// let i: Vec<u8> = b"41424344".to_vec();
    ///
    /// // Output: "ABCD"
    /// let o = H2Transformation::FromHex.transform(&i).unwrap();
    ///
    /// assert_eq!(b"ABCD".to_vec(), o);
    /// ```
    ///
    /// # Restrictions / errors
    ///
    /// Must be a hex string with an even length, made up of the digits 0-9
    /// and a-f.
    FromHex,
}

/// A list of transformations that can automatically be detected.
///
/// This is used as a basis for the `detect()` call. Many transformations
/// are overly broad (such as `FromBase32Permissive`), overly useless (such as
/// `Null`), or require configuration (such as `FromHex`). We skip those and
/// only look at potentially interesting transformations.
const TRANSFORMATIONS_THAT_CAN_BE_DETECTED: [H2Transformation; 10] = [
    H2Transformation::FromBase64,
    H2Transformation::FromBase64NoPadding,
    H2Transformation::FromBase64URL,
    H2Transformation::FromBase64URLNoPadding,
    H2Transformation::FromBase32,
    H2Transformation::FromBase32NoPadding,
    H2Transformation::FromBase32Crockford,

    H2Transformation::FromDeflated,
    H2Transformation::FromDeflatedZlib,

    H2Transformation::FromHex,
];

impl H2Transformation {
    fn transform_null(buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
        Ok(buffer.clone())
    }

    fn untransform_null(buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
        Ok(buffer.clone())
    }

    fn check_null(_buffer: &Vec<u8>) -> bool {
        true
    }

    fn transform_xor(buffer: &Vec<u8>, xs: XorSize) -> SimpleResult<Vec<u8>> {
        if !Self::check_xor(buffer, xs) {
            bail!("Xor failed: Xor isn't a multiple of the buffer size");
        }

        // Clone the buffer so we can edit in place
        let mut buffer = buffer.clone();

        match xs {
            XorSize::EightBit(c) => {
                // Transform in-place, since we can
                for n in &mut buffer {
                    *n = *n ^ c;
                }
            },
            XorSize::SixteenBit(c) => {
                let xorer: Vec<u8> = vec![
                    ((c >> 8) & 0x00FF) as u8,
                    ((c >> 0) & 0x00FF) as u8,
                ];

                let mut xor_position: usize = 0;
                for n in &mut buffer {
                    *n = *n ^ (xorer[xor_position]);
                    xor_position = (xor_position + 1) % 2;
                }
            },
            XorSize::ThirtyTwoBit(c) => {
                let xorer: Vec<u8> = vec![
                    ((c >> 24) & 0x00FF) as u8,
                    ((c >> 16) & 0x00FF) as u8,
                    ((c >> 8)  & 0x00FF) as u8,
                    ((c >> 0)  & 0x00FF) as u8,
                ];

                let mut xor_position: usize = 0;
                for n in &mut buffer {
                    *n = *n ^ (xorer[xor_position]);
                    xor_position = (xor_position + 1) % 4;
                }
            },
            XorSize::SixtyFourBit(c) => {
                let xorer: Vec<u8> = vec![
                    ((c >> 56) & 0x00FF) as u8,
                    ((c >> 48) & 0x00FF) as u8,
                    ((c >> 40) & 0x00FF) as u8,
                    ((c >> 32) & 0x00FF) as u8,
                    ((c >> 24) & 0x00FF) as u8,
                    ((c >> 16) & 0x00FF) as u8,
                    ((c >> 8)  & 0x00FF) as u8,
                    ((c >> 0)  & 0x00FF) as u8,
                ];

                let mut xor_position: usize = 0;
                for n in &mut buffer {
                    *n = *n ^ (xorer[xor_position]);
                    xor_position = (xor_position + 1) % 8;
                }
            },
        };

        Ok(buffer)
    }

    fn untransform_xor(buffer: &Vec<u8>, xs: XorSize) -> SimpleResult<Vec<u8>> {
        // Untransform is identical to transform
        Self::transform_xor(buffer, xs)
    }

    fn check_xor(buffer: &Vec<u8>, xs: XorSize) -> bool {
        match xs {
            XorSize::EightBit(_)     => true,
            XorSize::SixteenBit(_)   => {
                (buffer.len() % 2) == 0
            },
            XorSize::ThirtyTwoBit(_) => {
                (buffer.len() % 4) == 0
            },
            XorSize::SixtyFourBit(_) => {
                (buffer.len() % 8) == 0
            },
        }
    }

    fn transform_base64(buffer: &Vec<u8>, config: base64::Config) -> SimpleResult<Vec<u8>> {
        let original_length = buffer.len();

        // Decode
        let out = match base64::decode_config(buffer, config) {
            Ok(r) => r,
            Err(e) => bail!("Couldn't decode base64: {}", e),
        };

        // Ensure it encodes to the same length - we can't handle length changes
        if base64::encode_config(&out, config).len() != original_length {
            bail!("Base64 didn't decode correctly (the length changed with decode->encode, check padding)");
        }

        Ok(out)
    }

    fn untransform_base64(buffer: &Vec<u8>, config: base64::Config) -> SimpleResult<Vec<u8>> {
        Ok(base64::encode_config(buffer, config).into_bytes())
    }

    fn check_base64(buffer: &Vec<u8>, config: base64::Config) -> bool {
        // The only reasonable way to check is by just doing it (since the
        // config is opaque to us)
        Self::transform_base64(buffer, config).is_ok()
    }

    fn transform_base64_permissive(buffer: &Vec<u8>, config: base64::Config) -> SimpleResult<Vec<u8>> {
        // Filter out any control characters and spaces
        let buffer: Vec<u8> = buffer.clone().into_iter().filter(|b| {
            *b > 0x20 && *b < 0x80
        }).collect();

        // Decode
        let out = match base64::decode_config(buffer, config) {
            Ok(r) => r,
            Err(e) => bail!("Couldn't decode base64: {}", e),
        };

        Ok(out)
    }

    fn check_base64_permissive(buffer: &Vec<u8>, config: base64::Config) -> bool {
        // The only reasonable way to check is by just doing it (since the
        // config is opaque to us)
        Self::transform_base64_permissive(buffer, config).is_ok()
    }

    fn transform_base32(buffer: &Vec<u8>, alphabet: base32::Alphabet) -> SimpleResult<Vec<u8>> {
        let original_length = buffer.len();

        let s = match std::str::from_utf8(buffer) {
            Ok(s) => s,
            Err(e) => bail!("Couldn't convert the buffer into a string: {}", e),
        };

        // Decode
        let out = match base32::decode(alphabet, &s) {
            Some(r) => r,
            None => bail!("Couldn't decode base32"),
        };

        // Ensure it encodes to the same length - we can't handle length changes
        if base32::encode(alphabet, &out).into_bytes().len() != original_length {
            bail!("Base32 didn't decode correctly");
        }

        Ok(out)
    }

    fn untransform_base32(buffer: &Vec<u8>, alphabet: base32::Alphabet) -> SimpleResult<Vec<u8>> {
        Ok(base32::encode(alphabet, buffer).into_bytes())
    }

    fn check_base32(buffer: &Vec<u8>, alphabet: base32::Alphabet) -> bool {
        // The only reasonable way to check is by just doing it
        Self::transform_base32(buffer, alphabet).is_ok()
    }

    fn transform_base32_permissive(buffer: &Vec<u8>, alphabet: base32::Alphabet) -> SimpleResult<Vec<u8>> {
        // Filter out any obviously impossible characters
        let buffer: Vec<u8> = buffer.clone().into_iter().filter(|b| {
            (*b >= 0x30 && *b <= 0x39) || (*b >= 0x41 && *b <= 0x5a) || (*b >= 0x61 && *b <= 0x7a)
        }).collect();

        let s = match String::from_utf8(buffer) {
            Ok(s) => s,
            Err(e) => bail!("Couldn't convert the buffer into a string: {}", e),
        };

        // Decode
        match base32::decode(alphabet, &s) {
            Some(r) => Ok(r),
            None => bail!("Couldn't decode base32"),
        }
    }

    fn check_base32_permissive(buffer: &Vec<u8>, alphabet: base32::Alphabet) -> bool {
        // The only reasonable way to check is by just doing it
        Self::transform_base32_permissive(buffer, alphabet).is_ok()
    }

    fn transform_deflated(buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
        match inflate::inflate_bytes(buffer) {
            Ok(b) => Ok(b),
            Err(e) => bail!("Couldn't inflate: {}", e),
        }
    }

    fn check_deflated(buffer: &Vec<u8>) -> bool {
        // Extra short strings kinda sorta decode, but a zero-length string is
        // a minimum 6 characters so just enforce that
        buffer.len() > 5 && Self::transform_deflated(buffer).is_ok()
    }

    fn transform_deflated_zlib(buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
        match inflate::inflate_bytes_zlib(buffer) {
            Ok(b) => Ok(b),
            Err(e) => bail!("Couldn't inflate: {}", e),
        }
    }

    fn check_deflated_zlib(buffer: &Vec<u8>) -> bool {
        // The only reasonable way to check is by just doing it
        Self::transform_deflated_zlib(buffer).is_ok()
    }

    fn transform_hex(buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
        let s = match std::str::from_utf8(buffer) {
            Ok(s) => s,
            Err(e) => bail!("Couldn't convert the buffer into a string: {}", e),
        };

        match hex::decode(s) {
            Ok(s) => Ok(s),
            Err(e) => bail!("Couldn't decode hex: {}", e),
        }
    }

    fn untransform_hex(buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
        Ok(hex::encode(buffer).into_bytes())
    }

    fn check_hex(buffer: &Vec<u8>) -> bool {
        Self::transform_hex(buffer).is_ok()
    }

    // fn transform_XXX(buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
    //     bail!("Not implemented yet!");
    // }

    // fn untransform_XXX(buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
    //     bail!("Not implemented yet!");
    // }

    // fn check_XXX(buffer: &Vec<u8>) -> bool {
    //     bail!("Not implemented yet!");
    // }

    /// Transform a buffer into another buffer, without changing the original.
    pub fn transform(&self, buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
        // We can never handle 0-length buffers
        if buffer.len() == 0 {
            bail!("Cannot transform 0-length buffer");
        }

        match self {
            Self::Null                          => Self::transform_null(buffer),
            Self::XorByConstant(xs)             => Self::transform_xor(buffer, *xs),

            Self::FromBase64                    => Self::transform_base64(buffer, base64::STANDARD),
            Self::FromBase64NoPadding           => Self::transform_base64(buffer, base64::STANDARD_NO_PAD),
            Self::FromBase64Permissive          => Self::transform_base64_permissive(buffer, base64::STANDARD_NO_PAD),

            Self::FromBase64URL                 => Self::transform_base64(buffer, base64::URL_SAFE),
            Self::FromBase64URLNoPadding        => Self::transform_base64(buffer, base64::URL_SAFE_NO_PAD),
            Self::FromBase64URLPermissive       => Self::transform_base64_permissive(buffer, base64::URL_SAFE_NO_PAD),

            Self::FromBase32                    => Self::transform_base32(buffer, base32::Alphabet::RFC4648 { padding: true }),
            Self::FromBase32NoPadding           => Self::transform_base32(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32Crockford           => Self::transform_base32(buffer, base32::Alphabet::Crockford),

            Self::FromBase32Permissive          => Self::transform_base32_permissive(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32CrockfordPermissive => Self::transform_base32_permissive(buffer, base32::Alphabet::Crockford),

            Self::FromDeflated                  => Self::transform_deflated(buffer),
            Self::FromDeflatedZlib              => Self::transform_deflated_zlib(buffer),

            Self::FromHex                       => Self::transform_hex(buffer),

            //Self::From                          => Self::transform_(buffer),
        }
    }

    /// Transform a buffer backwards, if possible. The length of the result will
    /// match the length of the original buffer, but the data may be normalized.
    /// The original buffer is not changed.
    pub fn untransform(&self, buffer: &Vec<u8>) -> SimpleResult<Vec<u8>> {
        // We can never handle 0-length buffers
        if buffer.len() == 0 {
            bail!("Cannot untransform 0-length buffer");
        }

        match self {
            Self::Null                          => Self::untransform_null(buffer),
            Self::XorByConstant(xs)             => Self::untransform_xor(buffer, *xs),

            Self::FromBase64                    => Self::untransform_base64(buffer, base64::STANDARD),
            Self::FromBase64NoPadding           => Self::untransform_base64(buffer, base64::STANDARD_NO_PAD),
            Self::FromBase64Permissive          => bail!("Base64Permissive is one-way"),

            Self::FromBase64URL                 => Self::untransform_base64(buffer, base64::URL_SAFE),
            Self::FromBase64URLNoPadding        => Self::untransform_base64(buffer, base64::URL_SAFE_NO_PAD),
            Self::FromBase64URLPermissive       => bail!("Base64URLPermissive is one-way"),

            Self::FromBase32                    => Self::untransform_base32(buffer, base32::Alphabet::RFC4648 { padding: true }),
            Self::FromBase32NoPadding           => Self::untransform_base32(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32Crockford           => Self::untransform_base32(buffer, base32::Alphabet::Crockford),

            Self::FromBase32Permissive          => bail!("Base32Permissive is one-way"),
            Self::FromBase32CrockfordPermissive => bail!("Base32CrockfordPermissive is one-way"),

            Self::FromDeflated                  => bail!("Deflated is one-way"),
            Self::FromDeflatedZlib              => bail!("DeflatedZlib is one-way"),

            Self::FromHex                       => Self::untransform_hex(buffer),

            //Self::From                          => Self::untransform_(buffer),
        }
    }

    /// Check whether a buffer can be transformed by this variant.
    ///
    /// Warning: This is a semi-expensive operation for most variants; unless
    /// the transformation is based on length or another easy-to-check factor,
    /// we simply clone the data and attempt to transform it.
    pub fn can_transform(&self, buffer: &Vec<u8>) -> bool {
        // We can never handle 0-length buffers
        if buffer.len() == 0 {
            return false;
        }

        match self {
            Self::Null                          => Self::check_null(buffer),
            Self::XorByConstant(xs)             => Self::check_xor(buffer, *xs),

            Self::FromBase64                    => Self::check_base64(buffer, base64::STANDARD),
            Self::FromBase64NoPadding           => Self::check_base64(buffer, base64::STANDARD_NO_PAD),
            Self::FromBase64Permissive          => Self::check_base64_permissive(buffer, base64::STANDARD_NO_PAD),

            Self::FromBase64URL                 => Self::check_base64(buffer, base64::URL_SAFE),
            Self::FromBase64URLNoPadding        => Self::check_base64(buffer, base64::URL_SAFE_NO_PAD),
            Self::FromBase64URLPermissive       => Self::check_base64_permissive(buffer, base64::URL_SAFE_NO_PAD),

            Self::FromBase32                    => Self::check_base32(buffer, base32::Alphabet::RFC4648 { padding: true }),
            Self::FromBase32NoPadding           => Self::check_base32(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32Crockford           => Self::check_base32(buffer, base32::Alphabet::Crockford),

            Self::FromBase32Permissive          => Self::check_base32_permissive(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32CrockfordPermissive => Self::check_base32_permissive(buffer, base32::Alphabet::Crockford),

            Self::FromDeflated                  => Self::check_deflated(buffer),
            Self::FromDeflatedZlib              => Self::check_deflated_zlib(buffer),

            Self::FromHex                       => Self::check_hex(buffer),

            //Self::From                          => Self::check_(buffer),
        }
    }

    /// Determines if the transformation can be undone.
    ///
    /// Does not require a buffer, because the variant itself is enough to
    /// make this determination.
    pub fn is_two_way(&self) -> bool {
        match self {
            Self::Null                          => true,
            Self::XorByConstant(_)              => true,
            Self::FromBase64                    => true,
            Self::FromBase64NoPadding           => true,
            Self::FromBase64URL                 => true,
            Self::FromBase64URLNoPadding        => true,
            Self::FromBase32                    => true,
            Self::FromBase32NoPadding           => true,
            Self::FromBase32Crockford           => true,
            Self::FromHex                       => true,

            Self::FromBase64Permissive          => false,
            Self::FromBase64URLPermissive       => false,
            Self::FromBase32Permissive          => false,
            Self::FromBase32CrockfordPermissive => false,
            Self::FromDeflated                  => false,
            Self::FromDeflatedZlib              => false,

        }
    }

    /// Returns a list of possible transformations that will work on this
    /// buffer.
    ///
    /// This is VERY expensive, as it attempts to transform using every
    /// potential variant.
    pub fn detect(buffer: &Vec<u8>) -> Vec<&H2Transformation> {
        TRANSFORMATIONS_THAT_CAN_BE_DETECTED.iter().filter(|t| {
            t.can_transform(buffer)
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_null() -> SimpleResult<()> {
        assert_eq!(true, H2Transformation::Null.is_two_way());

        let tests: Vec<(Vec<u8>, SimpleResult<Vec<u8>>)> = vec![
            (vec![1],             Ok(vec![1])),
            (vec![1, 2, 3],       Ok(vec![1, 2, 3])),
            (vec![1, 2, 3, 4, 5], Ok(vec![1, 2, 3, 4, 5])),
        ];

        for (test, expected) in tests {
            assert!(H2Transformation::Null.can_transform(&test));

            let result = H2Transformation::Null.transform(&test);
            assert_eq!(expected, result);

            let result = H2Transformation::Null.untransform(&result?);
            assert_eq!(Ok(test), result);
        }

        Ok(())
    }

    #[test]
    fn test_xor8() -> SimpleResult<()> {
        assert_eq!(true, H2Transformation::XorByConstant(XorSize::EightBit(0)).is_two_way());

        let tests: Vec<(u8, Vec<u8>, SimpleResult<Vec<u8>>)> = vec![
            (0, vec![1],             Ok(vec![1])),
            (0, vec![1, 2, 3],       Ok(vec![1, 2, 3])),
            (0, vec![1, 2, 3, 4, 5], Ok(vec![1, 2, 3, 4, 5])),

            (1, vec![1],             Ok(vec![0])),
            (1, vec![1, 2, 3],       Ok(vec![0, 3, 2])),
            (1, vec![1, 2, 3, 4, 5], Ok(vec![0, 3, 2, 5, 4])),

            (0xFF, vec![1],             Ok(vec![254])),
            (0xFF, vec![1, 2, 3],       Ok(vec![254, 253, 252])),
            (0xFF, vec![1, 2, 3, 4, 5], Ok(vec![254, 253, 252, 251, 250])),
        ];

        for (c, test, expected) in tests {
            assert!(H2Transformation::XorByConstant(XorSize::EightBit(c)).can_transform(&test));

            let result = H2Transformation::XorByConstant(XorSize::EightBit(c)).transform(&test);
            assert_eq!(expected, result);

            let result = H2Transformation::XorByConstant(XorSize::EightBit(c)).untransform(&result?);
            assert_eq!(Ok(test), result);
        }

        Ok(())
    }

    #[test]
    fn test_xor16() -> SimpleResult<()> {
        let t = H2Transformation::XorByConstant(XorSize::SixteenBit(0x0000));

        // It can transform even-length vectors
        assert!(t.can_transform(&vec![0x11, 0x22]));
        assert!(t.can_transform(&vec![0x11, 0x22, 0x33, 0x44]));

        // It cannot transform odd-length vectors
        assert!(!t.can_transform(&vec![0x11]));
        assert!(!t.can_transform(&vec![0x11, 0x22, 0x33]));

        // Simplest examples
        let t = H2Transformation::XorByConstant(XorSize::SixteenBit(0x0000));
        assert_eq!(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66], t.transform(&vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66])?);

        let t = H2Transformation::XorByConstant(XorSize::SixteenBit(0xFFFF));
        assert_eq!(vec![0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99], t.transform(&vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66])?);

        // More complex examples
        let t = H2Transformation::XorByConstant(XorSize::SixteenBit(0x1234));

        // First byte: 0x11 & 0x12 = 0x03
        // Second byte: 0x22 & 0x34 = 0x16
        assert_eq!(vec![0x03, 0x16], t.transform(&vec![0x11, 0x22])?);

        // Third byte: 0x33 & 0x12 = 0x21
        // Fourth byte: 0x44 & 0x34 = 0x70
        assert_eq!(vec![0x03, 0x16, 0x21, 0x70], t.transform(&vec![0x11, 0x22, 0x33, 0x44])?);

        // Fail on bad strings
        assert!(t.transform(&vec![0x11]).is_err());

        Ok(())
    }

    #[test]
    fn test_xor32() -> SimpleResult<()> {
        let t = H2Transformation::XorByConstant(XorSize::ThirtyTwoBit(0x00000000));

        // It can transform multiple-of-4 vectors
        assert!(t.can_transform(&vec![0x11, 0x22, 0x33, 0x44]));
        assert!(t.can_transform(&vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));

        // It cannot transform odd-length vectors
        assert!(!t.can_transform(&vec![0x11]));
        assert!(!t.can_transform(&vec![0x11, 0x33]));
        assert!(!t.can_transform(&vec![0x11, 0x22, 0x33]));
        assert!(!t.can_transform(&vec![0x11, 0x22, 0x33, 0x44, 0x55]));

        // Simplest examples
        let t = H2Transformation::XorByConstant(XorSize::ThirtyTwoBit(0x00000000));
        assert_eq!(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], t.transform(&vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])?);

        let t = H2Transformation::XorByConstant(XorSize::ThirtyTwoBit(0xFFFFFFFF));
        assert_eq!(vec![0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77], t.transform(&vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])?);

        // More complex examples
        let t = H2Transformation::XorByConstant(XorSize::ThirtyTwoBit(0x12345678));

        // First byte:  0x11 & 0x12 = 0x03
        // Second byte: 0x22 & 0x34 = 0x16
        // Third byte:  0x33 & 0x56 = 0x65
        // Fourth byte: 0x44 & 0x78 = 0x3c
        assert_eq!(vec![0x03, 0x16, 0x65, 0x3c], t.transform(&vec![0x11, 0x22, 0x33, 0x44])?);

        // Fifth byte:   0x55 & 0x12 = 0x47
        // Sixth byte:   0x66 & 0x34 = 0x52
        // Seventh byte: 0x77 & 0x56 = 0x21
        // Eighth byte:  0x88 & 0x78 = 0xf0
        assert_eq!(vec![0x03, 0x16, 0x65, 0x3c, 0x47, 0x52, 0x21, 0xf0], t.transform(&vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])?);

        //assert_eq!(vec![0x03, 0x16, 0x21, 0x70], t.transform(&vec![0x11, 0x22, 0x33, 0x44])?);

        Ok(())
    }

    #[test]
    fn test_xor64() -> SimpleResult<()> {
        let t = H2Transformation::XorByConstant(XorSize::SixtyFourBit(0x0000000000000000));

        // It can transform multiple-of-8 vectors
        assert!(t.can_transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]));
        assert!(t.can_transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));

        // It cannot transform anything else
        assert!(!t.can_transform(&vec![0x00]));
        assert!(!t.can_transform(&vec![0x00, 0x11]));
        assert!(!t.can_transform(&vec![0x00, 0x11, 0x22]));
        assert!(!t.can_transform(&vec![0x00, 0x11, 0x22, 0x33]));
        assert!(!t.can_transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44]));
        assert!(!t.can_transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert!(!t.can_transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        assert!(!t.can_transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));

        // Simplest examples
        let t = H2Transformation::XorByConstant(XorSize::SixtyFourBit(0x0000000000000000));
        assert_eq!(
            vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            t.transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])?
        );

        let t = H2Transformation::XorByConstant(XorSize::SixtyFourBit(0xFFFFFFFFFFFFFFFF));
        assert_eq!(
            vec![0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00],
            t.transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])?
        );

        // // More complex examples
        let t = H2Transformation::XorByConstant(XorSize::SixtyFourBit(0x0123456789abcdef));

        // First byte:   0x00 & 0x01 = 0x01
        // Second byte:  0x11 & 0x23 = 0x32
        // Third byte:   0x22 & 0x45 = 0x67
        // Fourth byte:  0x33 & 0x67 = 0x54
        // Fifth byte:   0x44 & 0x89 = 0xcd
        // Sixth byte:   0x55 & 0xab = 0xfe
        // Seventh byte: 0x66 & 0xcd = 0xab
        // Eighth byte:  0x77 & 0xef = 0x98
        assert_eq!(
            vec![0x01, 0x32, 0x67, 0x54, 0xcd, 0xfe, 0xab, 0x98],
            t.transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])?
        );

        // First byte:   0x88 & 0x01 = 0x89
        // Second byte:  0x99 & 0x23 = 0xba
        // Third byte:   0xaa & 0x45 = 0xef
        // Fourth byte:  0xbb & 0x67 = 0xdc
        // Fifth byte:   0xcc & 0x89 = 0x45
        // Sixth byte:   0xdd & 0xab = 0x76
        // Seventh byte: 0xee & 0xcd = 0x23
        // Eighth byte:  0xff & 0xef = 0x10
        assert_eq!(
           vec![0x01, 0x32, 0x67, 0x54, 0xcd, 0xfe, 0xab, 0x98, 0x89, 0xba, 0xef, 0xdc, 0x45, 0x76, 0x23, 0x10],
            t.transform(&vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])?
        );

        Ok(())
    }

    // Just a small convenience function for tests
    fn b(s: &[u8]) -> Vec<u8> {
        s.to_vec()
    }

    #[test]
    fn test_base64_standard() -> SimpleResult<()> {
        let t = H2Transformation::FromBase64;
        assert_eq!(true, t.is_two_way());

        // Short string: "\x00"
        assert!(t.can_transform(&b(b"AA==")));
        let result = t.transform(&b(b"AA=="))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"AA=="), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        assert!(t.can_transform(&b(b"AAECAwQFBg==")));
        let result = t.transform(&b(b"AAECAwQFBg=="))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"AAECAwQFBg=="), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        assert!(t.can_transform(&b(b"aa++/z8=")));
        let result = t.transform(&b(b"aa++/z8="))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"aa++/z8="), original);

        // Do padding wrong
        assert!(!t.can_transform(&b(b"AA")));
        assert!(!t.can_transform(&b(b"AA=")));
        assert!(!t.can_transform(&b(b"AA===")));
        assert!(!t.can_transform(&b(b"AA====")));

        assert!(t.transform(&b(b"AA")).is_err());
        assert!(t.transform(&b(b"AA=")).is_err());
        assert!(t.transform(&b(b"AA===")).is_err());
        assert!(t.transform(&b(b"AA====")).is_err());

        // Wrong characters
        assert!(t.transform(&b(b"aa--_z8=")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_standard_no_padding() -> SimpleResult<()> {
        let t = H2Transformation::FromBase64NoPadding;
        assert_eq!(true, t.is_two_way());

        // Short string: "\x00"
        assert!(t.can_transform(&b(b"AA")));
        let result = t.transform(&b(b"AA"))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"AA"), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        assert!(t.can_transform(&b(b"AAECAwQFBg")));
        let result = t.transform(&b(b"AAECAwQFBg"))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"AAECAwQFBg"), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        let result = t.transform(&b(b"aa++/z8"))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"aa++/z8"), original);

        // Do padding wrong
        assert!(t.transform(&b(b"AA=")).is_err());
        assert!(t.transform(&b(b"AA==")).is_err());
        assert!(t.transform(&b(b"AA===")).is_err());
        assert!(t.transform(&b(b"AA====")).is_err());

        // Wrong characters
        assert!(t.transform(&b(b"aa--_z8")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_permissive() -> SimpleResult<()> {
        let t = H2Transformation::FromBase64Permissive;
        assert_eq!(false, t.is_two_way());

        // Short string: "\x00" with various padding
        assert!(t.can_transform(&b(b"AA")));
        assert!(t.can_transform(&b(b"AA=")));
        assert!(t.can_transform(&b(b"AA==")));
        assert_eq!(b(b"\x00"), t.transform(&b(b"AA"))?);
        assert_eq!(b(b"\x00"), t.transform(&b(b"AA="))?);
        assert_eq!(b(b"\x00"), t.transform(&b(b"AA=="))?);

        // Add a bunch of control characters
        assert_eq!(b(b"\x00\x00\x00\x00"), t.transform(&b(b"A A\nAAA\n    \t\rA=\n="))?);

        Ok(())
    }

    #[test]
    fn test_base64_url() -> SimpleResult<()> {
        let t = H2Transformation::FromBase64URL;
        assert_eq!(true, t.is_two_way());

        // Short string: "\x00"
        let result = t.transform(&b(b"AA=="))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"AA=="), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        let result = t.transform(&b(b"AAECAwQFBg=="))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"AAECAwQFBg=="), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        let result = t.transform(&b(b"aa--_z8="))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(&result)?;
        assert!(t.can_transform(&b(b"aa--_z8=")));
        assert_eq!(b(b"aa--_z8="), original);

        // Do padding wrong
        assert!(t.transform(&b(b"AA")).is_err());
        assert!(t.transform(&b(b"AA=")).is_err());
        assert!(t.transform(&b(b"AA===")).is_err());
        assert!(t.transform(&b(b"AA====")).is_err());

        // Wrong characters
        assert!(!t.can_transform(&b(b"aa++/z8=")));
        assert!(t.transform(&b(b"aa++/z8=")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_standard_url_no_padding() -> SimpleResult<()> {
        let t = H2Transformation::FromBase64URLNoPadding;
        assert_eq!(true, t.is_two_way());

        // Short string: "\x00"
        let result = t.transform(&b(b"AA"))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"AA"), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        let result = t.transform(&b(b"AAECAwQFBg"))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"AAECAwQFBg"), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        let result = t.transform(&b(b"aa--_z8"))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"aa--_z8"), original);

        // Do padding wrong
        assert!(t.transform(&b(b"AA=")).is_err());
        assert!(t.transform(&b(b"AA==")).is_err());
        assert!(t.transform(&b(b"AA===")).is_err());
        assert!(t.transform(&b(b"AA====")).is_err());

        // Wrong characters
        assert!(t.transform(&b(b"aa++/z8")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_url_permissive() -> SimpleResult<()> {
        let t = H2Transformation::FromBase64URLPermissive;
        assert_eq!(false, t.is_two_way());

        // Short string: "\x00" with various padding
        assert_eq!(b(b"\x00"), t.transform(&b(b"AA"))?);
        assert_eq!(b(b"\x00"), t.transform(&b(b"AA="))?);
        assert_eq!(b(b"\x00"), t.transform(&b(b"AA=="))?);

        // Add a bunch of control characters
        assert_eq!(b(b"\x00\x00\x00\x00"), t.transform(&b(b"A A\nAAA\n    \t\rA=\n="))?);

        Ok(())
    }

    #[test]
    fn test_base32_standard() -> SimpleResult<()> {
        let t = H2Transformation::FromBase32;
        assert_eq!(true, t.is_two_way());

        // Short string: "\x00"
        let t = H2Transformation::FromBase32;
        let result = t.transform(&b(b"IE======"))?;
        assert_eq!(b(b"A"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"IE======"), original);

        // Longer string: "ABCDEF"
        let t = H2Transformation::FromBase32;
        let result = t.transform(&b(b"IFBEGRCFIY======"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"IFBEGRCFIY======"), original);

        // It's okay to be case insensitive
        let t = H2Transformation::FromBase32;
        let result = t.transform(&b(b"ifbegrcfiy======"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"IFBEGRCFIY======"), original);

        // Do padding wrong
        let t = H2Transformation::FromBase32;
        assert!(t.transform(&b(b"IE")).is_err());
        assert!(t.transform(&b(b"IE=")).is_err());
        assert!(t.transform(&b(b"IE==")).is_err());
        assert!(t.transform(&b(b"IE===")).is_err());
        assert!(t.transform(&b(b"IE====")).is_err());
        assert!(t.transform(&b(b"IE=====")).is_err());
        assert!(t.transform(&b(b"IE=======")).is_err());
        assert!(t.transform(&b(b"IE========")).is_err());

        // Wrong characters
        let t = H2Transformation::FromBase32;
        assert!(t.transform(&b(b"I.======")).is_err());

        Ok(())
    }

    #[test]
    fn test_base32_no_padding() -> SimpleResult<()> {
        let t = H2Transformation::FromBase32NoPadding;
        assert_eq!(true, t.is_two_way());

        // Short string: "\x00"
        let t = H2Transformation::FromBase32NoPadding;
        let result = t.transform(&b(b"IE"))?;
        assert_eq!(b(b"A"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"IE"), original);

        // Longer string: "ABCDEF"
        let t = H2Transformation::FromBase32NoPadding;
        let result = t.transform(&b(b"IFBEGRCFIY"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"IFBEGRCFIY"), original);

        // It's okay to be case insensitive
        let t = H2Transformation::FromBase32NoPadding;
        let result = t.transform(&b(b"ifbegrcfiy"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"IFBEGRCFIY"), original);

        // Do padding wrong
        let t = H2Transformation::FromBase32NoPadding;
        assert!(t.transform(&b(b"IE=")).is_err());
        assert!(t.transform(&b(b"IE==")).is_err());
        assert!(t.transform(&b(b"IE===")).is_err());
        assert!(t.transform(&b(b"IE====")).is_err());
        assert!(t.transform(&b(b"IE=====")).is_err());
        assert!(t.transform(&b(b"IE======")).is_err());
        assert!(t.transform(&b(b"IE=======")).is_err());
        assert!(t.transform(&b(b"IE========")).is_err());

        // Wrong characters
        let t = H2Transformation::FromBase32NoPadding;
        assert!(t.transform(&b(b"A.")).is_err());

        Ok(())
    }

    #[test]
    fn test_base32_crockford() -> SimpleResult<()> {
        let t = H2Transformation::FromBase32Crockford;
        assert_eq!(true, t.is_two_way());

        // Short string: "\x00"
        let t = H2Transformation::FromBase32Crockford;
        let result = t.transform(&b(b"84"))?;
        assert_eq!(b(b"A"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"84"), original);

        // Longer string: "ABCDEF"
        let t = H2Transformation::FromBase32Crockford;
        let result = t.transform(&b(b"85146H258R"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"85146H258R"), original);

        // It's okay to be case insensitive
        let t = H2Transformation::FromBase32Crockford;
        let result = t.transform(&b(b"85146h258r"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(&result)?;
        assert_eq!(b(b"85146H258R"), original);

        // Do padding wrong
        let t = H2Transformation::FromBase32Crockford;
        assert!(t.transform(&b(b"84=")).is_err());
        assert!(t.transform(&b(b"84==")).is_err());
        assert!(t.transform(&b(b"84===")).is_err());
        assert!(t.transform(&b(b"84====")).is_err());
        assert!(t.transform(&b(b"84=====")).is_err());
        assert!(t.transform(&b(b"84======")).is_err());
        assert!(t.transform(&b(b"84=======")).is_err());
        assert!(t.transform(&b(b"84========")).is_err());

        // Wrong characters
        let t = H2Transformation::FromBase32Crockford;
        assert!(t.transform(&b(b"A.")).is_err());

        Ok(())
    }

    #[test]
    fn test_base32_permissive() -> SimpleResult<()> {
        let t = H2Transformation::FromBase32Permissive;
        assert_eq!(false, t.is_two_way());

        // Short string: "\x00"
        let t = H2Transformation::FromBase32Permissive;
        let result = t.transform(&b(b"IE======"))?;
        assert_eq!(b(b"A"), result);

        // Longer string: "ABCDEF"
        let t = H2Transformation::FromBase32Permissive;
        let result = t.transform(&b(b"IFBEGRCFIY======"))?;
        assert_eq!(b(b"ABCDEF"), result);

        // It's okay to be case insensitive
        let t = H2Transformation::FromBase32Permissive;
        let result = t.transform(&b(b"ifbegrcfiy======"))?;
        assert_eq!(b(b"ABCDEF"), result);

        // Do padding wrong
        let t = H2Transformation::FromBase32Permissive;
        assert_eq!(b(b"A"), t.transform(&b(b"IE"))?);
        assert_eq!(b(b"A"), t.transform(&b(b"IE="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"IE=="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"IE==="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"IE===="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"IE====="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"IE============="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"I=============E"))?);
        assert_eq!(b(b"A"), t.transform(&b(b"IE============="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"I.@#$...E...======"))?);

        // We can still error with bad characters
        assert!(t.transform(&b(b"1234567890")).is_err());

        Ok(())
    }

    #[test]
    fn test_base32_crockford_permissive() -> SimpleResult<()> {
        let t = H2Transformation::FromBase32CrockfordPermissive;
        assert_eq!(false, t.is_two_way());

        // Short string: "\x00"
        let t = H2Transformation::FromBase32CrockfordPermissive;
        let result = t.transform(&b(b"84======"))?;
        assert_eq!(b(b"A"), result);

        // Longer string: "ABCDEF"
        let t = H2Transformation::FromBase32CrockfordPermissive;
        let result = t.transform(&b(b"85146H258R======"))?;
        assert_eq!(b(b"ABCDEF"), result);

        // It's okay to be case insensitive
        let t = H2Transformation::FromBase32CrockfordPermissive;
        let result = t.transform(&b(b"85146h258r======"))?;
        assert_eq!(b(b"ABCDEF"), result);

        // Do padding wrong
        let t = H2Transformation::FromBase32CrockfordPermissive;
        assert_eq!(b(b"A"), t.transform(&b(b"84"))?);
        assert_eq!(b(b"A"), t.transform(&b(b"84="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"84=="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"84==="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"84===="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"84====="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"84============="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"8==---========4"))?);
        assert_eq!(b(b"A"), t.transform(&b(b"84============="))?);
        assert_eq!(b(b"A"), t.transform(&b(b"8.@#$...4...======"))?);

        // We can still error with bad characters
        assert!(t.transform(&b(b"no u")).is_err());

        Ok(())
    }

    #[test]
    fn test_deflate() -> SimpleResult<()> {
        let t = H2Transformation::FromDeflated;

        let result = t.transform(&b(b"\x03\x00\x00\x00\x00\x01"))?;
        assert_eq!(0, result.len());

        let result = t.transform(&b(b"\x63\x00\x00\x00\x01\x00\x01"))?;
        assert_eq!(vec![0x00], result);

        let result = t.transform(&b(b"\x63\x60\x80\x01\x00\x00\x0a\x00\x01"))?;
        assert_eq!(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], result);

        let result = t.transform(&b(b"\x63\x60\x64\x62\x66\x61\x65\x63\xe7\xe0\x04\x00\x00\xaf\x00\x2e"))?;
        assert_eq!(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09], result);

        // Best compression
        let result = t.transform(&b(b"\x73\x74\x72\x76\x01\x00\x02\x98\x01\x0b"))?;
        assert_eq!(vec![0x41, 0x42, 0x43, 0x44], result);

        // No compression
        let result = t.transform(&b(b"\x01\x04\x00\xfb\xff\x41\x42\x43\x44\x02\x98\x01\x0b"))?;
        assert_eq!(vec![0x41, 0x42, 0x43, 0x44], result);

        // Try an intentional error
        assert!(t.transform(&b(b"\xFF")).is_err());

        Ok(())
    }

    #[test]
    fn test_deflate_zlib() -> SimpleResult<()> {
        let t = H2Transformation::FromDeflatedZlib;

        let result = t.transform(&b(b"\x78\x9c\x03\x00\x00\x00\x00\x01"))?;
        assert_eq!(0, result.len());

        let result = t.transform(&b(b"\x78\x9c\x63\x00\x00\x00\x01\x00\x01"))?;
        assert_eq!(vec![0x00], result);

        let result = t.transform(&b(b"\x78\x9c\x63\x60\x80\x01\x00\x00\x0a\x00\x01"))?;
        assert_eq!(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], result);

        let result = t.transform(&b(b"\x78\x9c\x63\x60\x64\x62\x66\x61\x65\x63\xe7\xe0\x04\x00\x00\xaf\x00\x2e"))?;
        assert_eq!(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09], result);

        // Best compression
        let result = t.transform(&b(b"\x78\x9c\x73\x74\x72\x76\x01\x00\x02\x98\x01\x0b"))?;
        assert_eq!(vec![0x41, 0x42, 0x43, 0x44], result);

        // No compression
        let result = t.transform(&b(b"\x78\x01\x01\x04\x00\xfb\xff\x41\x42\x43\x44\x02\x98\x01\x0b"))?;
        assert_eq!(vec![0x41, 0x42, 0x43, 0x44], result);

        // Try an intentional error
        assert!(t.transform(&b(b"\xFF")).is_err());

        Ok(())
    }

    #[test]
    fn test_hex() -> SimpleResult<()> {
        let t = H2Transformation::FromHex;

        assert!(t.is_two_way());
        assert!(t.can_transform(&b(b"00")));
        assert!(t.can_transform(&b(b"0001")));
        assert!(t.can_transform(&b(b"000102feff")));
        assert!(!t.can_transform(&b(b"0")));
        assert!(!t.can_transform(&b(b"001")));
        assert!(!t.can_transform(&b(b"00102FEff")));
        assert!(!t.can_transform(&b(b"fg")));
        assert!(!t.can_transform(&b(b"+=")));

        assert_eq!(vec![0x00], t.transform(&b(b"00"))?);
        assert_eq!(vec![0x00, 0x01], t.transform(&b(b"0001"))?);
        assert_eq!(vec![0x00, 0x01, 0x02, 0xfe, 0xff], t.transform(&b(b"000102fEFf"))?);

        assert_eq!(b(b"00"), t.untransform(&vec![0x00])?);
        assert_eq!(b(b"0001"), t.untransform(&vec![0x00, 0x01])?);
        assert_eq!(b(b"000102feff"), t.untransform(&vec![0x00, 0x01, 0x02, 0xfe, 0xff])?);

        assert!(t.transform(&b(b"abababag")).is_err());

        Ok(())
    }

    #[test]
    fn test_detect() -> SimpleResult<()> {
        let tests: Vec<_> = vec![
            (
                "Testcase: 'A'",
                b(b"A"),
                vec![
                ],
            ),

            (
                "Testcase: 'AA'",
                b(b"AA"),
                vec![
                    &H2Transformation::FromBase64NoPadding,
                    &H2Transformation::FromBase64URLNoPadding,
                    &H2Transformation::FromHex,
                    &H2Transformation::FromBase32NoPadding,
                    &H2Transformation::FromBase32Crockford,
                ],
            ),

            (
                "Testcase: 'AA=='",
                b(b"AA=="),
                vec![
                    &H2Transformation::FromBase64,
                    &H2Transformation::FromBase64URL,
                ],
            ),

            (
                "Testcase: '/+AAAA=='",
                b(b"/+AAAA=="),
                vec![
                    &H2Transformation::FromBase64,
                ],
            ),

            (
                "Testcase: '-_AAAA=='",
                b(b"-_AAAA=="),
                vec![
                    &H2Transformation::FromBase64URL,
                    &H2Transformation::FromDeflated,
                ],
            ),

            (
                "Testcase: Simple deflated",
                b(b"\x03\x00\x00\x00\x00\x01"),
                vec![
                    &H2Transformation::FromDeflated,
                ]
            ),

            (
                "Testcase: Zlib deflated",
                b(b"\x78\x9c\x03\x00\x00\x00\x00\x01"),
                vec![
                    &H2Transformation::FromDeflatedZlib,
                ]
            ),

            (
                "Testcase: Base32",
                b(b"ORSXG5BRGIZSA2DFNRWG6==="),
                vec![
                    &H2Transformation::FromBase32,
                ]
            ),

            (
                "Testcase: Base32 no padding",
                b(b"ORSXG5BRGIZSA2DFNRWG6"),
                vec![
                    &H2Transformation::FromBase32NoPadding,
                    &H2Transformation::FromBase32Crockford,
                ]
            ),

            (
                "Testcase: Base32 crockford",
                b(b"EHJQ6X1H68SJ0T35DHP6Y"),
                vec![
                    &H2Transformation::FromBase32Crockford,
                ]
            ),
        ];

        // Do this in a loop since we have to sort both vectors
        for (desc, s, r) in tests {
            let mut t = H2Transformation::detect(&s);
            t.sort();

            let mut r = r.clone();
            r.sort();

            assert_eq!(t, r, "{}", desc);
        }

        Ok(())
    }
}
