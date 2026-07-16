use der::asn1::Uint;
use der::Decode;
use p384::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p384::elliptic_curve::PrimeField;
use p384::{FieldBytes, ProjectivePoint, Scalar, Sec1Point};

use crate::asn1::schemas::{ECCElGamalPublicKey, SubjectPublicKeyInfo};
use crate::ParseError;

/// Width of a P-384 scalar in bytes.
pub const SCALAR_BYTES: usize = 48;

/// Decode a SEC1-encoded curve point.
pub fn point_from_sec1(octets: &[u8]) -> Result<ProjectivePoint, ParseError> {
    let encoded = Sec1Point::from_bytes(octets).map_err(|_| ParseError::PointEncoding)?;
    Option::from(ProjectivePoint::from_sec1_point(&encoded)).ok_or(ParseError::PointNotOnCurve)
}

/// Encode a curve point in SEC1 uncompressed form.
pub fn point_to_sec1(point: &ProjectivePoint) -> Vec<u8> {
    point.to_sec1_point(false).as_bytes().to_vec()
}

/// Convert an unsigned ASN.1 integer to a scalar.
pub fn scalar_from_uint_bytes(octets: &[u8]) -> Result<Scalar, ParseError> {
    if octets.len() > SCALAR_BYTES {
        return Err(ParseError::IntegerTooLong {
            len: octets.len(),
            max: SCALAR_BYTES,
        });
    }

    let mut bytes = FieldBytes::default();
    bytes[SCALAR_BYTES - octets.len()..].copy_from_slice(octets);
    Option::from(Scalar::from_repr(bytes)).ok_or(ParseError::ScalarOutOfRange)
}

/// Convert an ASN.1 unsigned integer to a scalar.
pub fn scalar_from_uint(uint: &Uint) -> Result<Scalar, ParseError> {
    scalar_from_uint_bytes(uint.as_bytes())
}

/// Convert a scalar to an ASN.1 unsigned integer.
pub fn scalar_to_uint(scalar: &Scalar) -> Result<Uint, ParseError> {
    Ok(Uint::new(&scalar.to_bytes())?)
}

/// Extract the group element from a `SubjectPublicKeyInfo`.
pub fn spki_to_point(spki: &SubjectPublicKeyInfo) -> Result<ProjectivePoint, ParseError> {
    let inner = spki
        .subject_public_key
        .as_bytes()
        .ok_or(ParseError::BitStringUnaligned)?;
    point_from_sec1(ECCElGamalPublicKey::from_der(inner)?.pub_y.as_bytes())
}

pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, ParseError> {
    Ok(pem::parse(pem)?.into_contents())
}
