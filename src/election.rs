use der::asn1::{BitString, OctetString};
use der::{Any, Decode, Encode};

use crate::asn1::general_string::GeneralString;
use crate::asn1::oid::ID_IVXV_ECC_ELGAMAL;
use crate::asn1::schemas::{
    AlgorithmIdentifier, ECCElGamalParameters, ECCElGamalPublicKey, SubjectPublicKeyInfo,
};
use crate::codec::{pem_to_der, point_to_sec1, spki_to_point};
use crate::{elgamal, ParseError};

/// An election's ElGamal public key.
pub struct ElectionPublicKey {
    key: elgamal::PublicKey,
    election_id: String,
    spki: SubjectPublicKeyInfo,
}

impl ElectionPublicKey {
    /// Create an election public key from an ElGamal public key.
    pub fn new(key: elgamal::PublicKey, election_id: &str) -> Result<Self, ParseError> {
        let params = ECCElGamalParameters {
            curve: GeneralString::from("P-384"),
            election_id: GeneralString::from(election_id),
            lifted: None,
        };

        let encoded_key = ECCElGamalPublicKey {
            pub_y: OctetString::new(point_to_sec1(key.as_point()))?,
        }
        .to_der()?;

        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: ID_IVXV_ECC_ELGAMAL,
                parameters: Some(Any::encode_from(&params)?),
            },
            subject_public_key: BitString::new(0, encoded_key)?,
        };

        Ok(Self {
            key,
            election_id: election_id.to_owned(),
            spki,
        })
    }

    /// Parse a DER-encoded election public key.
    pub fn from_der(der: &[u8]) -> Result<Self, ParseError> {
        let spki = SubjectPublicKeyInfo::from_der(der)?;
        let params: ECCElGamalParameters = algorithm_parameters(&spki)?.decode_as()?;

        check_curve(params.curve.as_bytes())?;

        Ok(Self {
            key: elgamal::PublicKey::new(spki_to_point(&spki)?),
            election_id: election_id(params.election_id.as_bytes())?,
            spki,
        })
    }

    /// Parse a PEM-encoded election public key.
    pub fn from_pem(pem: &str) -> Result<Self, ParseError> {
        Self::from_der(&pem_to_der(pem)?)
    }

    /// The election identifier.
    pub fn election_id(&self) -> &str {
        &self.election_id
    }

    /// The key itself.
    pub const fn key(&self) -> &elgamal::PublicKey {
        &self.key
    }

    /// The `SubjectPublicKeyInfo`.
    pub const fn spki(&self) -> &SubjectPublicKeyInfo {
        &self.spki
    }
}

fn algorithm_parameters(spki: &SubjectPublicKeyInfo) -> Result<&der::Any, ParseError> {
    spki.algorithm
        .parameters
        .as_ref()
        .ok_or(ParseError::MissingParameters)
}

fn check_curve(name: &[u8]) -> Result<(), ParseError> {
    if name == b"P-384" {
        Ok(())
    } else {
        Err(ParseError::UnsupportedCurve {
            name: String::from_utf8_lossy(name).into_owned(),
        })
    }
}

fn election_id(bytes: &[u8]) -> Result<String, ParseError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| ParseError::ElectionIdEncoding)
}
