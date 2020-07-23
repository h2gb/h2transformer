//! [![Crate](https://img.shields.io/crates/v/h2transformer.svg)](https://crates.io/crates/h2transformer)
//!
//! H2Transformer is a library for transforming raw data between encodings.
//!
//! # Features
//!
//! Conversions are bidirectional when possible. That means data can be
//! converted, edited, then converted back *without changing the length*.
//!
//! There is NO guarantee that the data will be identical afterwards, however;
//! for example, `FromBase32` will normalize case.
//!
//! The other big feature is detecting encoding. A buffer can be analyzed and
//! a list of possible formats are returned.
//!
//! We attempt to be efficient by - whenever possible - editing the buffer in-
//! place. Detecting encoding is slow, however, since we literally clone +
//! convert the vector.
//!
//! # Usage
//!
//! TODO
//!
//!
//! ```
//! ```

use simple_error::{SimpleResult, bail};

use base64;
use base32;
use inflate;

#[cfg(feature = "serialize")]
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Copy)]
pub enum XorSize {
    EightBit(u8),
    SixteenBit(u16),
    ThirtyTwoBit(u32),
    SixtyFourBit(u64),
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Copy)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum Transformation {
    Null,
    XorByConstant(XorSize),

    FromBase64,
    FromBase64NoPadding,
    FromBase64Permissive,

    FromBase64URL,
    FromBase64URLNoPadding,
    FromBase64URLPermissive,

    FromBase32,
    FromBase32NoPadding,
    FromBase32Crockford,

    FromBase32Permissive,
    FromBase32CrockfordPermissive,

    FromDeflated,
    FromDeflatedZlib,

    FromHex,
}

const TRANSFORMATIONS_THAT_CAN_BE_DETECTED: [Transformation; 10] = [
    Transformation::FromBase64,
    Transformation::FromBase64NoPadding,
    Transformation::FromBase64URL,
    Transformation::FromBase64URLNoPadding,
    Transformation::FromBase32,
    Transformation::FromBase32NoPadding,
    Transformation::FromBase32Crockford,

    Transformation::FromDeflated,
    Transformation::FromDeflatedZlib,

    Transformation::FromHex,
];

impl Transformation {
    fn transform_null(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        Ok(buffer)
    }

    fn untransform_null(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        Ok(buffer)
    }

    fn check_null(_buffer: &Vec<u8>) -> bool {
        true
    }

    fn transform_xor(mut buffer: Vec<u8>, xs: XorSize) -> SimpleResult<Vec<u8>> {
        if !Self::check_xor(&buffer, xs) {
            bail!("Xor failed: Xor isn't a multiple of the buffer size");
        }

        // TODO: Validate size
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

    fn untransform_xor(buffer: Vec<u8>, xs: XorSize) -> SimpleResult<Vec<u8>> {
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

    fn transform_base64(buffer: Vec<u8>, config: base64::Config) -> SimpleResult<Vec<u8>> {
        let original_length = buffer.len();

        // Decode
        let out = match base64::decode_config(buffer, config) {
            Ok(r) => r,
            Err(e) => bail!("Couldn't decode base64: {}", e),
        };

        // Ensure it encodes to the same length - we can't handle length changes
        if base64::encode_config(&out, config).len() != original_length {
            bail!("Base64 didn't decode correctly (the length changed with decode->encode)");
        }

        Ok(out)
    }

    fn untransform_base64(buffer: Vec<u8>, config: base64::Config) -> SimpleResult<Vec<u8>> {
        Ok(base64::encode_config(buffer, config).into_bytes())
    }

    fn check_base64(buffer: &Vec<u8>, config: base64::Config) -> bool {
        // The only reasonable way to check is by just doing it (since the
        // config is opaque to us)
        Self::transform_base64(buffer.clone(), config).is_ok()
    }

    fn transform_base64_permissive(buffer: Vec<u8>, config: base64::Config) -> SimpleResult<Vec<u8>> {
        // Filter out any control characters and spaces
        let buffer: Vec<u8> = buffer.into_iter().filter(|b| {
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
        Self::transform_base64_permissive(buffer.clone(), config).is_ok()
    }

    fn transform_base32(buffer: Vec<u8>, alphabet: base32::Alphabet) -> SimpleResult<Vec<u8>> {
        let original_length = buffer.len();

        let s = match String::from_utf8(buffer) {
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

    fn untransform_base32(buffer: Vec<u8>, alphabet: base32::Alphabet) -> SimpleResult<Vec<u8>> {
        Ok(base32::encode(alphabet, &buffer).into_bytes())
    }

    fn check_base32(buffer: &Vec<u8>, alphabet: base32::Alphabet) -> bool {
        // The only reasonable way to check is by just doing it
        Self::transform_base32(buffer.clone(), alphabet).is_ok()
    }

    fn transform_base32_permissive(buffer: Vec<u8>, alphabet: base32::Alphabet) -> SimpleResult<Vec<u8>> {
        // Filter out any obviously impossible characters
        let buffer: Vec<u8> = buffer.into_iter().filter(|b| {
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
        Self::transform_base32_permissive(buffer.clone(), alphabet).is_ok()
    }

    fn transform_deflated(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        match inflate::inflate_bytes(&buffer) {
            Ok(b) => Ok(b),
            Err(e) => bail!("Couldn't inflate: {}", e),
        }
    }

    fn check_deflated(buffer: &Vec<u8>) -> bool {
        // Extra short strings kinda sorta decode, but a zero-length string is
        // a minimum 6 characters so just enforce that
        buffer.len() > 5 && Self::transform_deflated(buffer.clone()).is_ok()
    }

    fn transform_deflated_zlib(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        match inflate::inflate_bytes_zlib(&buffer) {
            Ok(b) => Ok(b),
            Err(e) => bail!("Couldn't inflate: {}", e),
        }
    }

    fn check_deflated_zlib(buffer: &Vec<u8>) -> bool {
        // The only reasonable way to check is by just doing it
        Self::transform_deflated_zlib(buffer.clone()).is_ok()
    }

    fn transform_hex(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        let s = match String::from_utf8(buffer) {
            Ok(s) => s,
            Err(e) => bail!("Couldn't convert the buffer into a string: {}", e),
        };

        match hex::decode(s) {
            Ok(s) => Ok(s),
            Err(e) => bail!("Couldn't decode hex: {}", e),
        }
    }

    fn untransform_hex(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        Ok(hex::encode(buffer).into_bytes())
    }

    fn check_hex(buffer: &Vec<u8>) -> bool {
        Self::transform_hex(buffer.clone()).is_ok()
    }

    // fn transform_XXX(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
    //     bai!l("Not implemented yet!");
    // }

    // fn untransform_XXX(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
    //     bail!("Not implemented yet!");
    // }

    // fn check_XXX(buffer: &Vec<u8>) -> bool {
    //     bail!("Not implemented yet!");
    // }

    pub fn transform(&self, buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
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

    pub fn untransform(&self, buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
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

    pub fn can_untransform(&self) -> bool {
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

    pub fn detect(buffer: &Vec<u8>) -> Vec<&Transformation> {
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
        assert_eq!(true, Transformation::Null.can_untransform());

        let tests: Vec<(Vec<u8>, SimpleResult<Vec<u8>>)> = vec![
            (vec![1],             Ok(vec![1])),
            (vec![1, 2, 3],       Ok(vec![1, 2, 3])),
            (vec![1, 2, 3, 4, 5], Ok(vec![1, 2, 3, 4, 5])),
        ];

        for (test, expected) in tests {
            assert!(Transformation::Null.can_transform(&test));

            let result = Transformation::Null.transform(test.clone());
            assert_eq!(expected, result);

            let result = Transformation::Null.untransform(result?);
            assert_eq!(Ok(test), result);
        }

        Ok(())
    }

    #[test]
    fn test_xor8() -> SimpleResult<()> {
        assert_eq!(true, Transformation::XorByConstant(XorSize::EightBit(0)).can_untransform());

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
            assert!(Transformation::XorByConstant(XorSize::EightBit(c)).can_transform(&test));

            let result = Transformation::XorByConstant(XorSize::EightBit(c)).transform(test.clone());
            assert_eq!(expected, result);

            let result = Transformation::XorByConstant(XorSize::EightBit(c)).untransform(result?);
            assert_eq!(Ok(test), result);
        }

        Ok(())
    }

    #[test]
    fn test_xor16() -> SimpleResult<()> {
        let t = Transformation::XorByConstant(XorSize::SixteenBit(0x0000));

        // It can transform even-length vectors
        assert!(t.can_transform(&vec![0x11, 0x22]));
        assert!(t.can_transform(&vec![0x11, 0x22, 0x33, 0x44]));

        // It cannot transform odd-length vectors
        assert!(!t.can_transform(&vec![0x11]));
        assert!(!t.can_transform(&vec![0x11, 0x22, 0x33]));

        // Simplest examples
        let t = Transformation::XorByConstant(XorSize::SixteenBit(0x0000));
        assert_eq!(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66], t.transform(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66])?);

        let t = Transformation::XorByConstant(XorSize::SixteenBit(0xFFFF));
        assert_eq!(vec![0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99], t.transform(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66])?);

        // More complex examples
        let t = Transformation::XorByConstant(XorSize::SixteenBit(0x1234));

        // First byte: 0x11 & 0x12 = 0x03
        // Second byte: 0x22 & 0x34 = 0x16
        assert_eq!(vec![0x03, 0x16], t.transform(vec![0x11, 0x22])?);

        // Third byte: 0x33 & 0x12 = 0x21
        // Fourth byte: 0x44 & 0x34 = 0x70
        assert_eq!(vec![0x03, 0x16, 0x21, 0x70], t.transform(vec![0x11, 0x22, 0x33, 0x44])?);

        // Fail on bad strings
        assert!(t.transform(vec![0x11]).is_err());

        Ok(())
    }

    #[test]
    fn test_xor32() -> SimpleResult<()> {
        let t = Transformation::XorByConstant(XorSize::ThirtyTwoBit(0x00000000));

        // It can transform multiple-of-4 vectors
        assert!(t.can_transform(&vec![0x11, 0x22, 0x33, 0x44]));
        assert!(t.can_transform(&vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));

        // It cannot transform odd-length vectors
        assert!(!t.can_transform(&vec![0x11]));
        assert!(!t.can_transform(&vec![0x11, 0x33]));
        assert!(!t.can_transform(&vec![0x11, 0x22, 0x33]));
        assert!(!t.can_transform(&vec![0x11, 0x22, 0x33, 0x44, 0x55]));

        // Simplest examples
        let t = Transformation::XorByConstant(XorSize::ThirtyTwoBit(0x00000000));
        assert_eq!(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], t.transform(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])?);

        let t = Transformation::XorByConstant(XorSize::ThirtyTwoBit(0xFFFFFFFF));
        assert_eq!(vec![0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77], t.transform(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])?);

        // More complex examples
        let t = Transformation::XorByConstant(XorSize::ThirtyTwoBit(0x12345678));

        // First byte:  0x11 & 0x12 = 0x03
        // Second byte: 0x22 & 0x34 = 0x16
        // Third byte:  0x33 & 0x56 = 0x65
        // Fourth byte: 0x44 & 0x78 = 0x3c
        assert_eq!(vec![0x03, 0x16, 0x65, 0x3c], t.transform(vec![0x11, 0x22, 0x33, 0x44])?);

        // Fifth byte:   0x55 & 0x12 = 0x47
        // Sixth byte:   0x66 & 0x34 = 0x52
        // Seventh byte: 0x77 & 0x56 = 0x21
        // Eighth byte:  0x88 & 0x78 = 0xf0
        assert_eq!(vec![0x03, 0x16, 0x65, 0x3c, 0x47, 0x52, 0x21, 0xf0], t.transform(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])?);

        //assert_eq!(vec![0x03, 0x16, 0x21, 0x70], t.transform(vec![0x11, 0x22, 0x33, 0x44])?);

        Ok(())
    }

    #[test]
    fn test_xor64() -> SimpleResult<()> {
        let t = Transformation::XorByConstant(XorSize::SixtyFourBit(0x0000000000000000));

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
        let t = Transformation::XorByConstant(XorSize::SixtyFourBit(0x0000000000000000));
        assert_eq!(
            vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            t.transform(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])?
        );

        let t = Transformation::XorByConstant(XorSize::SixtyFourBit(0xFFFFFFFFFFFFFFFF));
        assert_eq!(
            vec![0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00],
            t.transform(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])?
        );

        // // More complex examples
        let t = Transformation::XorByConstant(XorSize::SixtyFourBit(0x0123456789abcdef));

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
            t.transform(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])?
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
            t.transform(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])?
        );

        Ok(())
    }

    // Just a small convenience function for tests
    fn b(s: &[u8]) -> Vec<u8> {
        Vec::from(s)
    }

    #[test]
    fn test_base64_standard() -> SimpleResult<()> {
        let t = Transformation::FromBase64;
        assert_eq!(true, t.can_untransform());

        // Short string: "\x00"
        assert!(t.can_transform(&b(b"AA==")));
        let result = t.transform(b(b"AA=="))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AA=="), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        assert!(t.can_transform(&b(b"AAECAwQFBg==")));
        let result = t.transform(b(b"AAECAwQFBg=="))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AAECAwQFBg=="), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        assert!(t.can_transform(&b(b"aa++/z8=")));
        let result = t.transform(b(b"aa++/z8="))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"aa++/z8="), original);

        // Do padding wrong
        assert!(!t.can_transform(&b(b"AA")));
        assert!(!t.can_transform(&b(b"AA=")));
        assert!(!t.can_transform(&b(b"AA===")));
        assert!(!t.can_transform(&b(b"AA====")));

        assert!(t.transform(b(b"AA")).is_err());
        assert!(t.transform(b(b"AA=")).is_err());
        assert!(t.transform(b(b"AA===")).is_err());
        assert!(t.transform(b(b"AA====")).is_err());

        // Wrong characters
        assert!(t.transform(b(b"aa--_z8=")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_standard_no_padding() -> SimpleResult<()> {
        let t = Transformation::FromBase64NoPadding;
        assert_eq!(true, t.can_untransform());

        // Short string: "\x00"
        assert!(t.can_transform(&b(b"AA")));
        let result = t.transform(b(b"AA"))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AA"), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        assert!(t.can_transform(&b(b"AAECAwQFBg")));
        let result = t.transform(b(b"AAECAwQFBg"))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AAECAwQFBg"), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        let result = t.transform(b(b"aa++/z8"))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"aa++/z8"), original);

        // Do padding wrong
        assert!(t.transform(b(b"AA=")).is_err());
        assert!(t.transform(b(b"AA==")).is_err());
        assert!(t.transform(b(b"AA===")).is_err());
        assert!(t.transform(b(b"AA====")).is_err());

        // Wrong characters
        assert!(t.transform(b(b"aa--_z8")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_permissive() -> SimpleResult<()> {
        let t = Transformation::FromBase64Permissive;
        assert_eq!(false, t.can_untransform());

        // Short string: "\x00" with various padding
        assert!(t.can_transform(&b(b"AA")));
        assert!(t.can_transform(&b(b"AA=")));
        assert!(t.can_transform(&b(b"AA==")));
        assert_eq!(b(b"\x00"), t.transform(b(b"AA"))?);
        assert_eq!(b(b"\x00"), t.transform(b(b"AA="))?);
        assert_eq!(b(b"\x00"), t.transform(b(b"AA=="))?);

        // Add a bunch of control characters
        assert_eq!(b(b"\x00\x00\x00\x00"), t.transform(b(b"A A\nAAA\n    \t\rA=\n="))?);

        Ok(())
    }

    #[test]
    fn test_base64_url() -> SimpleResult<()> {
        let t = Transformation::FromBase64URL;
        assert_eq!(true, t.can_untransform());

        // Short string: "\x00"
        let result = t.transform(b(b"AA=="))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AA=="), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        let result = t.transform(b(b"AAECAwQFBg=="))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AAECAwQFBg=="), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        let result = t.transform(b(b"aa--_z8="))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(result)?;
        assert!(t.can_transform(&b(b"aa--_z8=")));
        assert_eq!(b(b"aa--_z8="), original);

        // Do padding wrong
        assert!(t.transform(b(b"AA")).is_err());
        assert!(t.transform(b(b"AA=")).is_err());
        assert!(t.transform(b(b"AA===")).is_err());
        assert!(t.transform(b(b"AA====")).is_err());

        // Wrong characters
        assert!(!t.can_transform(&b(b"aa++/z8=")));
        assert!(t.transform(b(b"aa++/z8=")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_standard_url_no_padding() -> SimpleResult<()> {
        let t = Transformation::FromBase64URLNoPadding;
        assert_eq!(true, t.can_untransform());

        // Short string: "\x00"
        let result = t.transform(b(b"AA"))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AA"), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        let result = t.transform(b(b"AAECAwQFBg"))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AAECAwQFBg"), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        let result = t.transform(b(b"aa--_z8"))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"aa--_z8"), original);

        // Do padding wrong
        assert!(t.transform(b(b"AA=")).is_err());
        assert!(t.transform(b(b"AA==")).is_err());
        assert!(t.transform(b(b"AA===")).is_err());
        assert!(t.transform(b(b"AA====")).is_err());

        // Wrong characters
        assert!(t.transform(b(b"aa++/z8")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_url_permissive() -> SimpleResult<()> {
        let t = Transformation::FromBase64URLPermissive;
        assert_eq!(false, t.can_untransform());

        // Short string: "\x00" with various padding
        assert_eq!(b(b"\x00"), t.transform(b(b"AA"))?);
        assert_eq!(b(b"\x00"), t.transform(b(b"AA="))?);
        assert_eq!(b(b"\x00"), t.transform(b(b"AA=="))?);

        // Add a bunch of control characters
        assert_eq!(b(b"\x00\x00\x00\x00"), t.transform(b(b"A A\nAAA\n    \t\rA=\n="))?);

        Ok(())
    }

    #[test]
    fn test_base32_standard() -> SimpleResult<()> {
        let t = Transformation::FromBase32;
        assert_eq!(true, t.can_untransform());

        // Short string: "\x00"
        let t = Transformation::FromBase32;
        let result = t.transform(b(b"IE======"))?;
        assert_eq!(b(b"A"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"IE======"), original);

        // Longer string: "ABCDEF"
        let t = Transformation::FromBase32;
        let result = t.transform(b(b"IFBEGRCFIY======"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"IFBEGRCFIY======"), original);

        // It's okay to be case insensitive
        let t = Transformation::FromBase32;
        let result = t.transform(b(b"ifbegrcfiy======"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"IFBEGRCFIY======"), original);

        // Do padding wrong
        let t = Transformation::FromBase32;
        assert!(t.transform(b(b"IE")).is_err());
        assert!(t.transform(b(b"IE=")).is_err());
        assert!(t.transform(b(b"IE==")).is_err());
        assert!(t.transform(b(b"IE===")).is_err());
        assert!(t.transform(b(b"IE====")).is_err());
        assert!(t.transform(b(b"IE=====")).is_err());
        assert!(t.transform(b(b"IE=======")).is_err());
        assert!(t.transform(b(b"IE========")).is_err());

        // Wrong characters
        let t = Transformation::FromBase32;
        assert!(t.transform(b(b"I.======")).is_err());

        Ok(())
    }

    #[test]
    fn test_base32_no_padding() -> SimpleResult<()> {
        let t = Transformation::FromBase32NoPadding;
        assert_eq!(true, t.can_untransform());

        // Short string: "\x00"
        let t = Transformation::FromBase32NoPadding;
        let result = t.transform(b(b"IE"))?;
        assert_eq!(b(b"A"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"IE"), original);

        // Longer string: "ABCDEF"
        let t = Transformation::FromBase32NoPadding;
        let result = t.transform(b(b"IFBEGRCFIY"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"IFBEGRCFIY"), original);

        // It's okay to be case insensitive
        let t = Transformation::FromBase32NoPadding;
        let result = t.transform(b(b"ifbegrcfiy"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"IFBEGRCFIY"), original);

        // Do padding wrong
        let t = Transformation::FromBase32NoPadding;
        assert!(t.transform(b(b"IE=")).is_err());
        assert!(t.transform(b(b"IE==")).is_err());
        assert!(t.transform(b(b"IE===")).is_err());
        assert!(t.transform(b(b"IE====")).is_err());
        assert!(t.transform(b(b"IE=====")).is_err());
        assert!(t.transform(b(b"IE======")).is_err());
        assert!(t.transform(b(b"IE=======")).is_err());
        assert!(t.transform(b(b"IE========")).is_err());

        // Wrong characters
        let t = Transformation::FromBase32NoPadding;
        assert!(t.transform(b(b"A.")).is_err());

        Ok(())
    }

    #[test]
    fn test_base32_crockford() -> SimpleResult<()> {
        let t = Transformation::FromBase32Crockford;
        assert_eq!(true, t.can_untransform());

        // Short string: "\x00"
        let t = Transformation::FromBase32Crockford;
        let result = t.transform(b(b"84"))?;
        assert_eq!(b(b"A"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"84"), original);

        // Longer string: "ABCDEF"
        let t = Transformation::FromBase32Crockford;
        let result = t.transform(b(b"85146H258R"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"85146H258R"), original);

        // It's okay to be case insensitive
        let t = Transformation::FromBase32Crockford;
        let result = t.transform(b(b"85146h258r"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"85146H258R"), original);

        // Do padding wrong
        let t = Transformation::FromBase32Crockford;
        assert!(t.transform(b(b"84=")).is_err());
        assert!(t.transform(b(b"84==")).is_err());
        assert!(t.transform(b(b"84===")).is_err());
        assert!(t.transform(b(b"84====")).is_err());
        assert!(t.transform(b(b"84=====")).is_err());
        assert!(t.transform(b(b"84======")).is_err());
        assert!(t.transform(b(b"84=======")).is_err());
        assert!(t.transform(b(b"84========")).is_err());

        // Wrong characters
        let t = Transformation::FromBase32Crockford;
        assert!(t.transform(b(b"A.")).is_err());

        Ok(())
    }

    #[test]
    fn test_base32_permissive() -> SimpleResult<()> {
        let t = Transformation::FromBase32Permissive;
        assert_eq!(false, t.can_untransform());

        // Short string: "\x00"
        let t = Transformation::FromBase32Permissive;
        let result = t.transform(b(b"IE======"))?;
        assert_eq!(b(b"A"), result);

        // Longer string: "ABCDEF"
        let t = Transformation::FromBase32Permissive;
        let result = t.transform(b(b"IFBEGRCFIY======"))?;
        assert_eq!(b(b"ABCDEF"), result);

        // It's okay to be case insensitive
        let t = Transformation::FromBase32Permissive;
        let result = t.transform(b(b"ifbegrcfiy======"))?;
        assert_eq!(b(b"ABCDEF"), result);

        // Do padding wrong
        let t = Transformation::FromBase32Permissive;
        assert_eq!(b(b"A"), t.transform(b(b"IE"))?);
        assert_eq!(b(b"A"), t.transform(b(b"IE="))?);
        assert_eq!(b(b"A"), t.transform(b(b"IE=="))?);
        assert_eq!(b(b"A"), t.transform(b(b"IE==="))?);
        assert_eq!(b(b"A"), t.transform(b(b"IE===="))?);
        assert_eq!(b(b"A"), t.transform(b(b"IE====="))?);
        assert_eq!(b(b"A"), t.transform(b(b"IE============="))?);
        assert_eq!(b(b"A"), t.transform(b(b"I=============E"))?);
        assert_eq!(b(b"A"), t.transform(b(b"IE============="))?);
        assert_eq!(b(b"A"), t.transform(b(b"I.@#$...E...======"))?);

        // We can still error with bad characters
        assert!(t.transform(b(b"1234567890")).is_err());

        Ok(())
    }

    #[test]
    fn test_base32_crockford_permissive() -> SimpleResult<()> {
        let t = Transformation::FromBase32CrockfordPermissive;
        assert_eq!(false, t.can_untransform());

        // Short string: "\x00"
        let t = Transformation::FromBase32CrockfordPermissive;
        let result = t.transform(b(b"84======"))?;
        assert_eq!(b(b"A"), result);

        // Longer string: "ABCDEF"
        let t = Transformation::FromBase32CrockfordPermissive;
        let result = t.transform(b(b"85146H258R======"))?;
        assert_eq!(b(b"ABCDEF"), result);

        // It's okay to be case insensitive
        let t = Transformation::FromBase32CrockfordPermissive;
        let result = t.transform(b(b"85146h258r======"))?;
        assert_eq!(b(b"ABCDEF"), result);

        // Do padding wrong
        let t = Transformation::FromBase32CrockfordPermissive;
        assert_eq!(b(b"A"), t.transform(b(b"84"))?);
        assert_eq!(b(b"A"), t.transform(b(b"84="))?);
        assert_eq!(b(b"A"), t.transform(b(b"84=="))?);
        assert_eq!(b(b"A"), t.transform(b(b"84==="))?);
        assert_eq!(b(b"A"), t.transform(b(b"84===="))?);
        assert_eq!(b(b"A"), t.transform(b(b"84====="))?);
        assert_eq!(b(b"A"), t.transform(b(b"84============="))?);
        assert_eq!(b(b"A"), t.transform(b(b"8==---========4"))?);
        assert_eq!(b(b"A"), t.transform(b(b"84============="))?);
        assert_eq!(b(b"A"), t.transform(b(b"8.@#$...4...======"))?);

        // We can still error with bad characters
        assert!(t.transform(b(b"no u")).is_err());

        Ok(())
    }

    #[test]
    fn test_deflate() -> SimpleResult<()> {
        let t = Transformation::FromDeflated;

        let result = t.transform(b(b"\x03\x00\x00\x00\x00\x01"))?;
        assert_eq!(0, result.len());

        let result = t.transform(b(b"\x63\x00\x00\x00\x01\x00\x01"))?;
        assert_eq!(vec![0x00], result);

        let result = t.transform(b(b"\x63\x60\x80\x01\x00\x00\x0a\x00\x01"))?;
        assert_eq!(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], result);

        let result = t.transform(b(b"\x63\x60\x64\x62\x66\x61\x65\x63\xe7\xe0\x04\x00\x00\xaf\x00\x2e"))?;
        assert_eq!(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09], result);

        // Best compression
        let result = t.transform(b(b"\x73\x74\x72\x76\x01\x00\x02\x98\x01\x0b"))?;
        assert_eq!(vec![0x41, 0x42, 0x43, 0x44], result);

        // No compression
        let result = t.transform(b(b"\x01\x04\x00\xfb\xff\x41\x42\x43\x44\x02\x98\x01\x0b"))?;
        assert_eq!(vec![0x41, 0x42, 0x43, 0x44], result);

        // Try an intentional error
        assert!(t.transform(b(b"\xFF")).is_err());

        Ok(())
    }

    #[test]
    fn test_deflate_zlib() -> SimpleResult<()> {
        let t = Transformation::FromDeflatedZlib;

        let result = t.transform(b(b"\x78\x9c\x03\x00\x00\x00\x00\x01"))?;
        assert_eq!(0, result.len());

        let result = t.transform(b(b"\x78\x9c\x63\x00\x00\x00\x01\x00\x01"))?;
        assert_eq!(vec![0x00], result);

        let result = t.transform(b(b"\x78\x9c\x63\x60\x80\x01\x00\x00\x0a\x00\x01"))?;
        assert_eq!(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], result);

        let result = t.transform(b(b"\x78\x9c\x63\x60\x64\x62\x66\x61\x65\x63\xe7\xe0\x04\x00\x00\xaf\x00\x2e"))?;
        assert_eq!(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09], result);

        // Best compression
        let result = t.transform(b(b"\x78\x9c\x73\x74\x72\x76\x01\x00\x02\x98\x01\x0b"))?;
        assert_eq!(vec![0x41, 0x42, 0x43, 0x44], result);

        // No compression
        let result = t.transform(b(b"\x78\x01\x01\x04\x00\xfb\xff\x41\x42\x43\x44\x02\x98\x01\x0b"))?;
        assert_eq!(vec![0x41, 0x42, 0x43, 0x44], result);

        // Try an intentional error
        assert!(t.transform(b(b"\xFF")).is_err());

        Ok(())
    }

    #[test]
    fn test_hex() -> SimpleResult<()> {
        let t = Transformation::FromHex;

        assert!(t.can_untransform());
        assert!(t.can_transform(&b(b"00")));
        assert!(t.can_transform(&b(b"0001")));
        assert!(t.can_transform(&b(b"000102feff")));
        assert!(!t.can_transform(&b(b"0")));
        assert!(!t.can_transform(&b(b"001")));
        assert!(!t.can_transform(&b(b"00102FEff")));
        assert!(!t.can_transform(&b(b"fg")));
        assert!(!t.can_transform(&b(b"+=")));

        assert_eq!(vec![0x00], t.transform(b(b"00"))?);
        assert_eq!(vec![0x00, 0x01], t.transform(b(b"0001"))?);
        assert_eq!(vec![0x00, 0x01, 0x02, 0xfe, 0xff], t.transform(b(b"000102fEFf"))?);

        assert_eq!(b(b"00"), t.untransform(vec![0x00])?);
        assert_eq!(b(b"0001"), t.untransform(vec![0x00, 0x01])?);
        assert_eq!(b(b"000102feff"), t.untransform(vec![0x00, 0x01, 0x02, 0xfe, 0xff])?);

        assert!(t.transform(b(b"abababag")).is_err());

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
                    &Transformation::FromBase64NoPadding,
                    &Transformation::FromBase64URLNoPadding,
                    &Transformation::FromHex,
                    &Transformation::FromBase32NoPadding,
                    &Transformation::FromBase32Crockford,
                ],
            ),

            (
                "Testcase: 'AA=='",
                b(b"AA=="),
                vec![
                    &Transformation::FromBase64,
                    &Transformation::FromBase64URL,
                ],
            ),

            (
                "Testcase: '/+AAAA=='",
                b(b"/+AAAA=="),
                vec![
                    &Transformation::FromBase64,
                ],
            ),

            (
                "Testcase: '-_AAAA=='",
                b(b"-_AAAA=="),
                vec![
                    &Transformation::FromBase64URL,
                    &Transformation::FromDeflated,
                ],
            ),

            (
                "Testcase: Simple deflated",
                b(b"\x03\x00\x00\x00\x00\x01"),
                vec![
                    &Transformation::FromDeflated,
                ]
            ),

            (
                "Testcase: Zlib deflated",
                b(b"\x78\x9c\x03\x00\x00\x00\x00\x01"),
                vec![
                    &Transformation::FromDeflatedZlib,
                ]
            ),

            (
                "Testcase: Base32",
                b(b"ORSXG5BRGIZSA2DFNRWG6==="),
                vec![
                    &Transformation::FromBase32,
                ]
            ),

            (
                "Testcase: Base32 no padding",
                b(b"ORSXG5BRGIZSA2DFNRWG6"),
                vec![
                    &Transformation::FromBase32NoPadding,
                    &Transformation::FromBase32Crockford,
                ]
            ),

            (
                "Testcase: Base32 crockford",
                b(b"EHJQ6X1H68SJ0T35DHP6Y"),
                vec![
                    &Transformation::FromBase32Crockford,
                ]
            ),
        ];

        // Do this in a loop since we have to sort both vectors
        for (desc, s, r) in tests {
            let mut t = Transformation::detect(&s);
            t.sort();

            let mut r = r.clone();
            r.sort();

            assert_eq!(t, r, "{}", desc);
        }

        Ok(())
    }
}
