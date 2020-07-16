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

#[cfg(feature = "serialize")]
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum Transformation {
    Null,
    FromHex,
    FromBinary,
    FromBase64Standard,
    FromBase64Custom(base64::Config),
    FromBase32,
    XorByConstant(u8),
    UnDeflate,
}

impl Transformation {
    fn _xor_by_constant(mut buffer: Vec<u8>, c: u8) -> SimpleResult<Vec<u8>> {
        // Transform in-place, since we can
        for n in &mut buffer {
            *n = *n ^ c
        }
        Ok(buffer)
    }

    fn _from_base64_transform(buffer: Vec<u8>, config: base64::Config) -> SimpleResult<Vec<u8>> {
        let original_length = buffer.len();

        // Decode
        let out = match base64::decode_config(buffer, config) {
            Ok(r) => r,
            Err(e) => bail!("Couldn't decode base64: {}", e),
        };

        // Ensure it encodes to the same length - we can't handle length changes
        if base64::encode_config(&out, config).len() != original_length {
            bail!("Base64 didn't decode correctly; try validating the padding");
        }

        Ok(out)
    }

    fn _from_base64_untransform(buffer: Vec<u8>, config: base64::Config) -> SimpleResult<Vec<u8>> {
        Ok(base64::encode_config(buffer, config).into_bytes())
    }

    pub fn transform(self, buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        match self {
            Self::XorByConstant(c) => Self::_xor_by_constant(buffer, c),
            Self::Null => Ok(buffer),
            Self::FromBase64Standard => Self::_from_base64_transform(buffer, base64::STANDARD),
            Self::FromBase64Custom(config) => Self::_from_base64_transform(buffer, config),
            _ => bail!("Not implemented"),
        }
    }

    pub fn untransform(self, buffer: Vec<u8>) -> SimpleResult<Vec<u8>> {
        match self {
            Self::XorByConstant(c) => Self::_xor_by_constant(buffer, c),
            Self::Null => Ok(buffer),
            Self::FromBase64Standard => Self::_from_base64_untransform(buffer, base64::STANDARD),
            Self::FromBase64Custom(config) => Self::_from_base64_untransform(buffer, config),
            _ => bail!("Not implemented"),
        }
    }

    pub fn can_untransform(self) -> bool {
        match self {
            Self::Null                => true,
            Self::FromHex             => true,
            Self::FromBinary          => true,
            Self::FromBase64Standard  => true,
            Self::FromBase64Custom(_) => true,
            Self::FromBase32          => true,
            Self::XorByConstant(_)    => true,
            Self::UnDeflate           => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_null() {
        assert!(true, Transformation::Null.can_untransform());

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
        assert!(true, Transformation::XorByConstant(0).can_untransform());

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

    #[test]
    fn test_base64_standard() {
        assert!(true, Transformation::FromBase64Standard.can_untransform());

        let good_tests: Vec<(Vec<u8>, SimpleResult<Vec<u8>>)> = vec![
            (Vec::from(String::from("").as_bytes()),             Ok(Vec::from(String::from("").as_bytes()))),
            (Vec::from(String::from("aGVsbG8=").as_bytes()),     Ok(Vec::from(String::from("hello").as_bytes()))),
            (Vec::from(String::from("AA==").as_bytes()),         Ok(vec![0])),
            (Vec::from(String::from("AAE=").as_bytes()),         Ok(vec![0, 1])),
            (Vec::from(String::from("AAEC").as_bytes()),         Ok(vec![0, 1, 2])),
            (Vec::from(String::from("AAECAw==").as_bytes()),     Ok(vec![0, 1, 2, 3])),
            (Vec::from(String::from("AAECAwQ=").as_bytes()),     Ok(vec![0, 1, 2, 3, 4])),
            (Vec::from(String::from("AAECAwQF").as_bytes()),     Ok(vec![0, 1, 2, 3, 4, 5])),
            (Vec::from(String::from("AAECAwQFBg==").as_bytes()), Ok(vec![0, 1, 2, 3, 4, 5, 6])),
            (Vec::from(String::from("AAECAwQFBv8=").as_bytes()), Ok(vec![0, 1, 2, 3, 4, 5, 6, 255])),
            (Vec::from(String::from("aa++/z8=").as_bytes()),     Ok(vec![105, 175, 190, 255, 63])),
        ];

        for (test, expected) in good_tests {
            let result = Transformation::FromBase64Standard.transform(test.clone());
            assert_eq!(expected, result);

            let result = Transformation::FromBase64Standard.untransform(result.unwrap());
            assert_eq!(Ok(test), result);
        }

        let bad_tests: Vec<Vec<u8>> = vec![
            Vec::from(String::from("AAECAwQFBv8").as_bytes()),
            Vec::from(String::from("AAECAwQFBv8==").as_bytes()),
            Vec::from(String::from("AAECAwQFBv8===").as_bytes()),
            Vec::from(String::from("AAECAwQFBv8====").as_bytes()),
            Vec::from(String::from("%").as_bytes()),
            Vec::from(String::from("%%").as_bytes()),
            Vec::from(String::from("%%%").as_bytes()),
            Vec::from(String::from("%%%%").as_bytes()),
        ];

        for test in bad_tests {
            let result = Transformation::FromBase64Standard.transform(test.clone());
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_base64_custom() {
        assert!(true, Transformation::FromBase64Custom(base64::STANDARD_NO_PAD).can_untransform());

        let good_tests: Vec<(base64::Config, Vec<u8>, SimpleResult<Vec<u8>>)> = vec![
            (base64::STANDARD_NO_PAD, Vec::from(String::from("").as_bytes()),            Ok(Vec::from(String::from("").as_bytes()))),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAwQF").as_bytes()),    Ok(vec![0, 1, 2, 3, 4, 5])),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AA").as_bytes()),          Ok(vec![0])),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAE").as_bytes()),         Ok(vec![0, 1])),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAEC").as_bytes()),        Ok(vec![0, 1, 2])),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAw").as_bytes()),      Ok(vec![0, 1, 2, 3])),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAwQ").as_bytes()),     Ok(vec![0, 1, 2, 3, 4])),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAwQF").as_bytes()),    Ok(vec![0, 1, 2, 3, 4, 5])),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAwQFBg").as_bytes()),  Ok(vec![0, 1, 2, 3, 4, 5, 6])),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAwQFBv8").as_bytes()), Ok(vec![0, 1, 2, 3, 4, 5, 6, 255])),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("aa++/z8").as_bytes()),     Ok(vec![105, 175, 190, 255, 63])),

            (base64::URL_SAFE,        Vec::from(String::from("AA==").as_bytes()),        Ok(vec![0])),
            (base64::URL_SAFE,        Vec::from(String::from("AAE=").as_bytes()),        Ok(vec![0, 1])),
            (base64::URL_SAFE,        Vec::from(String::from("AAEC").as_bytes()),        Ok(vec![0, 1, 2])),
            (base64::URL_SAFE,        Vec::from(String::from("aa--_z8=").as_bytes()),    Ok(vec![105, 175, 190, 255, 63])),

            (base64::URL_SAFE_NO_PAD, Vec::from(String::from("AA").as_bytes()),          Ok(vec![0])),
            (base64::URL_SAFE_NO_PAD, Vec::from(String::from("AAE").as_bytes()),         Ok(vec![0, 1])),
            (base64::URL_SAFE_NO_PAD, Vec::from(String::from("AAEC").as_bytes()),        Ok(vec![0, 1, 2])),
            (base64::URL_SAFE_NO_PAD, Vec::from(String::from("aa--_z8").as_bytes()),     Ok(vec![105, 175, 190, 255, 63])),
        ];

        for (config, test, expected) in good_tests {
            let result = Transformation::FromBase64Custom(config).transform(test.clone());
            assert_eq!(expected, result);

            let result = Transformation::FromBase64Custom(config).untransform(result.unwrap());
            assert_eq!(Ok(test), result);
        }

        let bad_tests: Vec<(base64::Config, Vec<u8>)> = vec![
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AA==").as_bytes())),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAE=").as_bytes())),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAw==").as_bytes())),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAwQ=").as_bytes())),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAwQFBg==").as_bytes())),
            (base64::STANDARD_NO_PAD, Vec::from(String::from("AAECAwQFBv8=").as_bytes())),

            (base64::URL_SAFE,        Vec::from(String::from("AA").as_bytes())),
            (base64::URL_SAFE,        Vec::from(String::from("AAE").as_bytes())),
            (base64::URL_SAFE,        Vec::from(String::from("aa++/z8=").as_bytes())),

            (base64::URL_SAFE_NO_PAD, Vec::from(String::from("AA==").as_bytes())),
            (base64::URL_SAFE_NO_PAD, Vec::from(String::from("AAE=").as_bytes())),
            (base64::URL_SAFE_NO_PAD, Vec::from(String::from("aa++/z8").as_bytes())),
        ];

        for (config, test) in bad_tests {
            let result = Transformation::FromBase64Custom(config).transform(test.clone());
            assert!(result.is_err());
        }
    }
}
