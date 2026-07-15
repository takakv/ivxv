use der::asn1::OctetString;
use der::{Decode, Encode};
use p384::elliptic_curve::rand_core::CryptoRng;
use p384::elliptic_curve::{Field, Generate};
use p384::{NonZeroScalar, ProjectivePoint, Scalar};

use crate::asn1::oid::ID_IVXV_ECC_ELGAMAL;
use crate::asn1::schemas::{AlgorithmIdentifier, ECCElGamalCiphertext, ElGamalCiphertextInfo};
use crate::codec::{point_from_sec1, point_to_sec1};
use crate::error::ParseError;

/// An ElGamal public key `Y ← xG`.
pub struct PublicKey(ProjectivePoint);

/// An ElGamal secret key `x`.
pub struct SecretKey(NonZeroScalar);

/// A message in its group-element form.
pub struct Plaintext(ProjectivePoint);

/// An ElGamal ciphertext `(U, V)`
pub struct Ciphertext {
    /// `U ← rG`, the blinding factor.
    pub u: ProjectivePoint,
    /// `V ← m + rY`, the blinded message.
    pub v: ProjectivePoint,
}

/// The encryption randomness `r`.
pub struct Randomness(Scalar);

impl PublicKey {
    /// Wrap a group element as a public key.
    pub const fn new(point: ProjectivePoint) -> Self {
        Self(point)
    }

    /// The underlying group element.
    pub const fn as_point(&self) -> &ProjectivePoint {
        &self.0
    }

    /// Encrypt a group element, drawing fresh randomness.
    pub fn encrypt(&self, m: &Plaintext, rng: &mut impl CryptoRng) -> (Ciphertext, Randomness) {
        let r = Randomness(Scalar::random(rng));
        (self.encrypt_with(m, &r), r)
    }

    /// Encrypt a group element with given randomness.
    pub fn encrypt_with(&self, m: &Plaintext, r: &Randomness) -> Ciphertext {
        Ciphertext {
            u: ProjectivePoint::GENERATOR * r.0,
            v: m.0 + self.0 * r.0,
        }
    }

    /// Encrypt a scalar in the lifted scheme, drawing fresh randomness.
    pub fn encrypt_lifted(&self, m: &Scalar, rng: &mut impl CryptoRng) -> (Ciphertext, Randomness) {
        self.encrypt(&Plaintext::lift(m), rng)
    }
}

impl SecretKey {
    /// Generate a fresh secret key.
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        Self(NonZeroScalar::generate_from_rng(rng))
    }

    /// Wrap a scalar as a secret key.
    pub const fn new(scalar: NonZeroScalar) -> Self {
        Self(scalar)
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(ProjectivePoint::GENERATOR * *self.0)
    }

    /// Decrypt the encrypted group element.
    pub fn decrypt(&self, ct: &Ciphertext) -> Plaintext {
        Plaintext(ct.v - ct.u * *self.0)
    }
}

impl Plaintext {
    /// Wrap a group element as a message.
    pub const fn new(point: ProjectivePoint) -> Self {
        Self(point)
    }

    /// 'Lift' a scalar into the group: `M ← mG`.
    pub fn lift(m: &Scalar) -> Self {
        Self(ProjectivePoint::GENERATOR * m)
    }

    /// The underlying group element.
    pub const fn as_point(&self) -> &ProjectivePoint {
        &self.0
    }

    /// SEC1 uncompressed encoding of the group element.
    pub fn to_sec1(&self) -> Vec<u8> {
        point_to_sec1(&self.0)
    }

    /// Decode a plaintext.
    pub fn from_der(der: &[u8]) -> Result<Self, ParseError> {
        Ok(Self(point_from_sec1(
            OctetString::from_der(der)?.as_bytes(),
        )?))
    }

    /// Encode the plaintext.
    pub fn to_der(&self) -> Result<Vec<u8>, ParseError> {
        Ok(OctetString::new(self.to_sec1())?.to_der()?)
    }
}

impl Randomness {
    /// Wrap a scalar as encryption randomness.
    pub const fn new(r: Scalar) -> Self {
        Self(r)
    }

    /// The underlying scalar.
    pub const fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    /// The big-endian bytes of the scalar.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Unblind the ciphertext using encryption randomness: `M ← V - rY`.
    pub fn unblind(&self, pk: &PublicKey, ct: &Ciphertext) -> Plaintext {
        Plaintext(ct.v - pk.0 * self.0)
    }
}

impl Ciphertext {
    /// Decode an `ElGamalCiphertextInfo`.
    pub fn from_der(der: &[u8]) -> Result<Self, ParseError> {
        Self::from_info(&ElGamalCiphertextInfo::from_der(der)?)
    }

    /// Extract the group elements from a decoded `ElGamalCiphertextInfo`.
    pub fn from_info(info: &ElGamalCiphertextInfo) -> Result<Self, ParseError> {
        Ok(Self {
            u: point_from_sec1(info.ciphertext.u_blind.as_bytes())?,
            v: point_from_sec1(info.ciphertext.v_blinded_message.as_bytes())?,
        })
    }

    /// Encode an `ElGamalCiphertextInfo`.
    pub fn to_der(&self) -> Result<Vec<u8>, ParseError> {
        Ok(self.to_info()?.to_der()?)
    }

    /// Build the DER object.
    pub fn to_info(&self) -> Result<ElGamalCiphertextInfo, ParseError> {
        Ok(ElGamalCiphertextInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: ID_IVXV_ECC_ELGAMAL,
                parameters: None,
            },
            ciphertext: ECCElGamalCiphertext {
                u_blind: OctetString::new(point_to_sec1(&self.u))?,
                v_blinded_message: OctetString::new(point_to_sec1(&self.v))?,
            },
        })
    }
}
