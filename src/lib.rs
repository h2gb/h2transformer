//! [![Crate](https://img.shields.io/crates/v/h2transformer.svg)](https://crates.io/crates/h2transformer)
//!
//! H2Transformer is a library for transforming raw data between encodings.
//!
//!
//! # Features
//!
//! Conversions are bidirectional when possible. That means data can be
//! converted, edited, then converted back *without changing the length*.
//!
//! There is NO guarantee that the data will be identical aftewards, however;
//! `FromBase32` will normalize case.
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

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum Transformation {
    Null,

    XorByConstant(u8),

    FromBase64,
    FromBase64Permissive,
    FromBase64Custom(base64::Config),
    FromBase64CustomPermissive(base64::Config),
    FromBase32,
    FromBase32NoPadding,
    FromBase32Crockford,

    FromBase32Permissive,
    FromBase32CrockfordPermissive,

    FromDeflated,
    FromDeflatedZlib,

    //FromHex,
    //FromBinary,
}

const TRANSFORMATIONS_THAT_CAN_BE_DETECTED: [Transformation; 10] = [
    Transformation::Null,

    Transformation::FromBase64,
    Transformation::FromBase64Permissive,
    Transformation::FromBase32,
    Transformation::FromBase32NoPadding,
    Transformation::FromBase32Crockford,

    Transformation::FromBase32Permissive,
    Transformation::FromBase32CrockfordPermissive,

    Transformation::FromDeflated,
    Transformation::FromDeflatedZlib,
];
// ]);

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

    fn transform_xor8(mut buffer: Vec<u8>, c: u8) -> SimpleResult<Vec<u8>> {
        // Transform in-place, since we can
        for n in &mut buffer {
            *n = *n ^ c;
        }
        Ok(buffer)
    }

    fn untransform_xor8(buffer: Vec<u8>, c: u8) -> SimpleResult<Vec<u8>> {
        Self::transform_xor8(buffer, c)
    }

    fn check_xor8(_buffer: &Vec<u8>, _c: u8) -> bool {
        true
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
        // The only reasonable way to check is by just doing it
        Self::transform_deflated(buffer.clone()).is_ok()
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

    pub fn transform(&self, buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        match self {
            Self::Null                               => Self::transform_null(buffer),
            Self::XorByConstant(c)                   => Self::transform_xor8(buffer, *c),

            Self::FromBase64                         => Self::transform_base64(buffer, base64::STANDARD),
            Self::FromBase64Custom(config)           => Self::transform_base64(buffer, *config),
            Self::FromBase64Permissive               => Self::transform_base64_permissive(buffer, base64::STANDARD),
            Self::FromBase64CustomPermissive(config) => Self::transform_base64_permissive(buffer, *config),

            Self::FromBase32                         => Self::transform_base32(buffer, base32::Alphabet::RFC4648 { padding: true }),
            Self::FromBase32NoPadding                => Self::transform_base32(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32Crockford                => Self::transform_base32(buffer, base32::Alphabet::Crockford),

            Self::FromBase32Permissive               => Self::transform_base32_permissive(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32CrockfordPermissive      => Self::transform_base32_permissive(buffer, base32::Alphabet::Crockford),

            Self::FromDeflated                       => Self::transform_deflated(buffer),
            Self::FromDeflatedZlib                   => Self::transform_deflated_zlib(buffer),
        }
    }

    pub fn untransform(&self, buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        match self {
            Self::Null                          => Self::untransform_null(buffer),
            Self::XorByConstant(c)              => Self::untransform_xor8(buffer, *c),

            Self::FromBase64                    => Self::untransform_base64(buffer, base64::STANDARD),
            Self::FromBase64Custom(config)      => Self::untransform_base64(buffer, *config),
            Self::FromBase64Permissive          => bail!("Base64Permissive is one-way"),
            Self::FromBase64CustomPermissive(_) => bail!("Base64CustomPermissive is one-way"),

            Self::FromBase32                    => Self::untransform_base32(buffer, base32::Alphabet::RFC4648 { padding: true }),
            Self::FromBase32NoPadding           => Self::untransform_base32(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32Crockford           => Self::untransform_base32(buffer, base32::Alphabet::Crockford),

            Self::FromBase32Permissive          => bail!("Base32Permissive is one-way"),
            Self::FromBase32CrockfordPermissive => bail!("Base32CrockfordPermissive is one-way"),

            Self::FromDeflated                  => bail!("Deflated is one-way"),
            Self::FromDeflatedZlib              => bail!("DeflatedZlib is one-way"),
        }
    }

    pub fn can_transform(&self, buffer: &Vec<u8>) -> bool {
        match self {
            Self::Null                               => Self::check_null(buffer),
            Self::XorByConstant(c)                   => Self::check_xor8(buffer, *c),

            Self::FromBase64                         => Self::check_base64(buffer, base64::STANDARD),
            Self::FromBase64Custom(config)           => Self::check_base64(buffer, *config),
            Self::FromBase64Permissive               => Self::check_base64_permissive(buffer, base64::STANDARD),
            Self::FromBase64CustomPermissive(config) => Self::check_base64_permissive(buffer, *config),

            Self::FromBase32                         => Self::check_base32(buffer, base32::Alphabet::RFC4648 { padding: true }),
            Self::FromBase32NoPadding                => Self::check_base32(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32Crockford                => Self::check_base32(buffer, base32::Alphabet::Crockford),

            Self::FromBase32Permissive               => Self::check_base32_permissive(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32CrockfordPermissive      => Self::check_base32_permissive(buffer, base32::Alphabet::Crockford),

            Self::FromDeflated                       => Self::check_deflated(buffer),
            Self::FromDeflatedZlib                   => Self::check_deflated_zlib(buffer),
        }
    }

    pub fn can_untransform(&self) -> bool {
        match self {
            Self::Null                          => true,
            Self::XorByConstant(_)              => true,
            Self::FromBase64                    => true,
            Self::FromBase64Custom(_)           => true,
            Self::FromBase64Permissive          => false,
            Self::FromBase64CustomPermissive(_) => false,
            Self::FromBase32                    => true,
            Self::FromBase32NoPadding           => true,
            Self::FromBase32Crockford           => true,
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
            (vec![],              Ok(vec![])),
            (vec![1],             Ok(vec![1])),
            (vec![1, 2, 3],       Ok(vec![1, 2, 3])),
            (vec![1, 2, 3, 4, 5], Ok(vec![1, 2, 3, 4, 5])),
        ];

        for (test, expected) in tests {
            let result = Transformation::Null.transform(test.clone());
            assert_eq!(expected, result);

            let result = Transformation::Null.untransform(result?);
            assert_eq!(Ok(test), result);
        }

        Ok(())
    }

    #[test]
    fn test_xor_by_constant() -> SimpleResult<()> {
        assert_eq!(true, Transformation::XorByConstant(0).can_untransform());

        let tests: Vec<(u8, Vec<u8>, SimpleResult<Vec<u8>>)> = vec![
            (0, vec![],              Ok(vec![])),

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
            let result = Transformation::XorByConstant(c).transform(test.clone());
            assert_eq!(expected, result);

            let result = Transformation::XorByConstant(c).untransform(result?);
            assert_eq!(Ok(test), result);
        }

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

        // Empty string: ""
        let t = Transformation::FromBase64;
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b""), original);

        // Short string: "\x00"
        let t = Transformation::FromBase64;
        let result = t.transform(b(b"AA=="))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AA=="), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        let t = Transformation::FromBase64;
        let result = t.transform(b(b"AAECAwQFBg=="))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AAECAwQFBg=="), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        let t = Transformation::FromBase64;
        let result = t.transform(b(b"aa++/z8="))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"aa++/z8="), original);

        // Do padding wrong
        let t = Transformation::FromBase64;
        assert!(t.transform(b(b"AA")).is_err());
        assert!(t.transform(b(b"AA=")).is_err());
        assert!(t.transform(b(b"AA===")).is_err());
        assert!(t.transform(b(b"AA====")).is_err());

        // Wrong characters
        let t = Transformation::FromBase64;
        assert!(t.transform(b(b"aa--_z8=")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_custom() -> SimpleResult<()> {
        let t = Transformation::FromBase64Custom(base64::STANDARD_NO_PAD);
        assert_eq!(true, t.can_untransform());

        // Empty string: ""
        let t = Transformation::FromBase64Custom(base64::STANDARD_NO_PAD);
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b""), original);

        // Short string: "\x00"
        let t = Transformation::FromBase64Custom(base64::STANDARD_NO_PAD);
        let result = t.transform(b(b"AA"))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AA"), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        let t = Transformation::FromBase64Custom(base64::STANDARD_NO_PAD);
        let result = t.transform(b(b"AAECAwQFBg"))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AAECAwQFBg"), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        let t = Transformation::FromBase64Custom(base64::STANDARD_NO_PAD);
        let result = t.transform(b(b"aa++/z8"))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"aa++/z8"), original);

        // URL Safe with odd characters: "\x69\xaf\xbe\xff\x3f"
        let t = Transformation::FromBase64Custom(base64::URL_SAFE);
        let result = t.transform(b(b"aa--_z8="))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"aa--_z8="), original);

        // URL Safe with odd characters and no padding: "\x69\xaf\xbe\xff\x3f"
        let t = Transformation::FromBase64Custom(base64::URL_SAFE_NO_PAD);
        let result = t.transform(b(b"aa--_z8"))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"aa--_z8"), original);

        // Do padding wrong
        let t = Transformation::FromBase64Custom(base64::STANDARD_NO_PAD);
        assert!(t.transform(b(b"AA==")).is_err());
        assert!(t.transform(b(b"AAE=")).is_err());
        assert!(t.transform(b(b"AAECAw==")).is_err());

        // Wrong characters for standard
        let t = Transformation::FromBase64Custom(base64::STANDARD_NO_PAD);
        assert!(t.transform(b(b"aa--_z8")).is_err());

        // Wrong characters for URL
        let t = Transformation::FromBase64Custom(base64::URL_SAFE);
        assert!(t.transform(b(b"aa++/z8=")).is_err());

        Ok(())
    }

    #[test]
    fn test_base64_permissive() -> SimpleResult<()> {
        let t = Transformation::FromBase64Permissive;
        assert_eq!(false, t.can_untransform());

        // Empty string: ""
        let t = Transformation::FromBase64Permissive;
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);

        // Short string: "\x00" with various padding
        let t = Transformation::FromBase64Permissive;
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

        // Empty string: ""
        let t = Transformation::FromBase32;
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b""), original);

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

        // Empty string: ""
        let t = Transformation::FromBase32NoPadding;
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b""), original);

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

        // Empty string: ""
        let t = Transformation::FromBase32Crockford;
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b""), original);

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

        // Empty string: ""
        let t = Transformation::FromBase32Permissive;
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);

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

        // Empty string: ""
        let t = Transformation::FromBase32CrockfordPermissive;
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);

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
    fn test_detect() -> SimpleResult<()> {
        // let r = Transformation::detect(&b(b"\x78\x9c\x03\x00\x00\x00\x00\x01"));
        // let expected: Vec<Transformation> = vec![
        //     Transformation::Null,
        //     Transformation::FromBase32Permissive,
        //     Transformation::FromBase32CrockfordPermissive,
        //     Transformation::FromDeflatedZlib
        // ];
        // assert_eq!(expected, r);

        //println!("{:?}", ;

        // println!("{:?}", Transformation::detect(&b(b"AAECAwQFBg==")));
        // println!("{:?}", Transformation::detect(&b(b"aa--_z8")));
        // println!("{:?}", Transformation::detect(&b(b"\x03\x00\x00\x00\x00\x01")));
        // println!("{:?}", Transformation::detect(&b(b"IE=====")));
        // println!("{:?}", Transformation::detect(&b(b"A A\nAAA\n    \t\rA=\n=")));

        Ok(())
    }
}
