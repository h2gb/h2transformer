//! [![Crate](https://img.shields.io/crates/v/h2transformer.svg)](https://crates.io/crates/h2transformer)
//!
//! A thingy
//!
//! # Goal
//!
//!
//! # Usage
//!
//!
//! ```
//! ```

use simple_error::{SimpleResult, bail};
use base64;
use base32;

#[cfg(feature = "serialize")]
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum Transformation {
    Null,
    //FromHex,
    //FromBinary,
    FromBase64Standard,
    FromBase64Custom(base64::Config),
    FromBase64Permissive,
    FromBase64CustomPermissive(base64::Config),
    FromBase32Standard,
    FromBase32NoPadding,
    FromBase32Crockford,

    FromBase32Permissive,
    FromBase32CrockfordPermissive,
    XorByConstant(u8),
    //UnDeflate,
}

impl Transformation {
    fn transform_null(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        Ok(buffer)
    }

    fn untransform_null(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        Ok(buffer)
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

    // fn from_deflate_transform(buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
    // }

    pub fn transform(&self, buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        match self {
            Self::Null                               => Self::transform_null(buffer),
            Self::XorByConstant(c)                   => Self::transform_xor8(buffer, *c),

            Self::FromBase64Standard                 => Self::transform_base64(buffer, base64::STANDARD),
            Self::FromBase64Custom(config)           => Self::transform_base64(buffer, *config),
            Self::FromBase64Permissive               => Self::transform_base64_permissive(buffer, base64::STANDARD),
            Self::FromBase64CustomPermissive(config) => Self::transform_base64_permissive(buffer, *config),

            Self::FromBase32Standard                 => Self::transform_base32(buffer, base32::Alphabet::RFC4648 { padding: true }),
            Self::FromBase32NoPadding                => Self::transform_base32(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32Crockford                => Self::transform_base32(buffer, base32::Alphabet::Crockford),

            Self::FromBase32Permissive               => Self::transform_base32_permissive(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32CrockfordPermissive      => Self::transform_base32_permissive(buffer, base32::Alphabet::Crockford),
        }
    }

    pub fn can_transform(&self, buffer: &Vec<u8>) -> bool {
        match self {
            Self::Null             => true,
            Self::XorByConstant(_) => true,

            // When we can't be sure, just clone the buffer and try
            _                      => self.transform(buffer.clone()).is_ok(),
        }
    }

    pub fn untransform(&self, buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        match self {
            Self::Null                          => Self::untransform_null(buffer),
            Self::XorByConstant(c)              => Self::untransform_xor8(buffer, *c),

            Self::FromBase64Standard            => Self::untransform_base64(buffer, base64::STANDARD),
            Self::FromBase64Custom(config)      => Self::untransform_base64(buffer, *config),
            Self::FromBase64Permissive          => bail!("Base64Permissive is one-way"),
            Self::FromBase64CustomPermissive(_) => bail!("Base64CustomPermissive is one-way"),

            Self::FromBase32Standard            => Self::untransform_base32(buffer, base32::Alphabet::RFC4648 { padding: true }),
            Self::FromBase32NoPadding           => Self::untransform_base32(buffer, base32::Alphabet::RFC4648 { padding: false }),
            Self::FromBase32Crockford           => Self::untransform_base32(buffer, base32::Alphabet::Crockford),

            Self::FromBase32Permissive          => bail!("Base32Permissive is one-way"),
            Self::FromBase32CrockfordPermissive => bail!("Base32CrockfordPermissive is one-way"),
        }
    }

    pub fn can_untransform(&self) -> bool {
        match self {
            Self::Null                          => true,
            Self::FromBase64Standard            => true,
            Self::FromBase64Custom(_)           => true,
            Self::FromBase64Permissive          => false,
            Self::FromBase64CustomPermissive(_) => false,
            Self::FromBase32Standard            => true,
            Self::FromBase32NoPadding           => true,
            Self::FromBase32Crockford           => true,
            Self::FromBase32Permissive          => false,
            Self::FromBase32CrockfordPermissive => false,
            Self::XorByConstant(_)              => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_null() {
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

            let result = Transformation::Null.untransform(result.unwrap());
            assert_eq!(Ok(test), result);
        }
    }

    #[test]
    fn test_xor_by_constant() {
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

            let result = Transformation::XorByConstant(c).untransform(result.unwrap());
            assert_eq!(Ok(test), result);
        }
    }

    // Just a small convenience function for tests
    fn b(s: &[u8]) -> Vec<u8> {
        Vec::from(s)
    }

    #[test]
    fn test_base64_standard() -> SimpleResult<()> {
        let t = Transformation::FromBase64Standard;
        assert_eq!(true, t.can_untransform());

        // Empty string: ""
        let t = Transformation::FromBase64Standard;
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b""), original);

        // Short string: "\x00"
        let t = Transformation::FromBase64Standard;
        let result = t.transform(b(b"AA=="))?;
        assert_eq!(b(b"\x00"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AA=="), original);

        // Longer string: "\x00\x01\x02\x03\x04\x05\x06"
        let t = Transformation::FromBase64Standard;
        let result = t.transform(b(b"AAECAwQFBg=="))?;
        assert_eq!(b(b"\x00\x01\x02\x03\x04\x05\x06"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"AAECAwQFBg=="), original);

        // Weird string: "\x69\xaf\xbe\xff\x3f"
        let t = Transformation::FromBase64Standard;
        let result = t.transform(b(b"aa++/z8="))?;
        assert_eq!(b(b"\x69\xaf\xbe\xff\x3f"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"aa++/z8="), original);

        // Do padding wrong
        let t = Transformation::FromBase64Standard;
        assert!(t.transform(b(b"AA")).is_err());
        assert!(t.transform(b(b"AA=")).is_err());
        assert!(t.transform(b(b"AA===")).is_err());
        assert!(t.transform(b(b"AA====")).is_err());

        // Wrong characters
        let t = Transformation::FromBase64Standard;
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
        let t = Transformation::FromBase32Standard;
        assert_eq!(true, t.can_untransform());

        // Empty string: ""
        let t = Transformation::FromBase32Standard;
        let result = t.transform(b(b""))?;
        assert_eq!(b(b""), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b""), original);

        // Short string: "\x00"
        let t = Transformation::FromBase32Standard;
        let result = t.transform(b(b"IE======"))?;
        assert_eq!(b(b"A"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"IE======"), original);

        // Longer string: "ABCDEF"
        let t = Transformation::FromBase32Standard;
        let result = t.transform(b(b"IFBEGRCFIY======"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"IFBEGRCFIY======"), original);

        // It's okay to be case insensitive
        let t = Transformation::FromBase32Standard;
        let result = t.transform(b(b"ifbegrcfiy======"))?;
        assert_eq!(b(b"ABCDEF"), result);
        let original = t.untransform(result)?;
        assert_eq!(b(b"IFBEGRCFIY======"), original);

        // Do padding wrong
        let t = Transformation::FromBase32Standard;
        assert!(t.transform(b(b"IE")).is_err());
        assert!(t.transform(b(b"IE=")).is_err());
        assert!(t.transform(b(b"IE==")).is_err());
        assert!(t.transform(b(b"IE===")).is_err());
        assert!(t.transform(b(b"IE====")).is_err());
        assert!(t.transform(b(b"IE=====")).is_err());
        assert!(t.transform(b(b"IE=======")).is_err());
        assert!(t.transform(b(b"IE========")).is_err());

        // Wrong characters
        let t = Transformation::FromBase32Standard;
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
        assert_eq!(b(b"A"), t.transform(b(b"IE")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"IE=")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"IE==")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"IE===")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"IE====")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"IE=====")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"IE=============")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"I=============E")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"IE=============")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"I.@#$...E...======")).unwrap());

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
        assert_eq!(b(b"A"), t.transform(b(b"84")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"84=")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"84==")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"84===")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"84====")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"84=====")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"84=============")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"8==---========4")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"84=============")).unwrap());
        assert_eq!(b(b"A"), t.transform(b(b"8.@#$...4...======")).unwrap());

        // We can still error with bad characters
        assert!(t.transform(b(b"no u")).is_err());

        Ok(())
    }
}
