use der::Decode;

use crate::asn1::schemas::{ECCElGamalParameters, SubjectPublicKeyInfo};
use crate::codec::{pem_to_der, spki_to_point};
use crate::{elgamal, ParseError};

/// An election's ElGamal public key.
pub struct ElectionPublicKey {
    key: elgamal::PublicKey,
    election_id: String,
    spki: SubjectPublicKeyInfo,
}

impl ElectionPublicKey {
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
