use der::asn1::OctetString;
use der::{Decode, Encode};
use p384::{ProjectivePoint, Scalar};
use thiserror::Error;

use crate::asn1::general_string::GeneralString;
use crate::asn1::schemas::{self, ECCElGamalDecryptionChallenge, ElGamalCiphertextInfo};
use crate::codec::{point_from_sec1, scalar_from_uint};
use crate::election::ElectionPublicKey;
use crate::elgamal::{Ciphertext, Plaintext};
use crate::proofs::fiatshamir;
use crate::ParseError;

const PROOF_DOMAIN: &str = "DECRYPTION";

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("message commitment check failed")]
    MsgCommitment,

    #[error("key commitment check failed")]
    KeyCommitment,
}

#[derive(Debug, Error)]
pub enum DecryptionVerifyError {
    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error("decryption proof invalid ({0})")]
    Invalid(#[from] DecryptionError),
}

/// A ZKP that a ciphertext decrypts to a particular plaintext.
pub struct DecryptionProof {
    msg_commitment: ProjectivePoint,
    key_commitment: ProjectivePoint,
    response: Scalar,
    wire: schemas::ECCElGamalDecryptionProof,
}

impl DecryptionProof {
    /// Decode a proof.
    pub fn from_der(der: &[u8]) -> Result<Self, ParseError> {
        Self::from_wire(&schemas::ECCElGamalDecryptionProof::from_der(der)?)
    }

    /// Extract the elements from a decoded proof structure.
    pub fn from_wire(wire: &schemas::ECCElGamalDecryptionProof) -> Result<Self, ParseError> {
        Ok(Self {
            msg_commitment: point_from_sec1(wire.a_msg_commitment.as_bytes())?,
            key_commitment: point_from_sec1(wire.b_key_commitment.as_bytes())?,
            response: scalar_from_uint(&wire.s_response)?,
            wire: wire.clone(),
        })
    }

    /// The commitment `A ← kU`.
    pub const fn msg_commitment(&self) -> &ProjectivePoint {
        &self.msg_commitment
    }

    /// The commitment `B ← kG`.
    pub const fn key_commitment(&self) -> &ProjectivePoint {
        &self.key_commitment
    }

    /// The response `s ← c·x + k`.
    pub const fn response(&self) -> Scalar {
        self.response
    }
}

pub struct DecryptionContext<'a> {
    pk: &'a ElectionPublicKey,
}

impl<'a> DecryptionContext<'a> {
    /// Fix the election key that proofs are checked against.
    pub const fn new(pk: &'a ElectionPublicKey) -> Self {
        Self { pk }
    }

    /// Verify the ZKP of correct decryption.
    pub fn verify(
        &self,
        ciphertext: &ElGamalCiphertextInfo,
        plaintext: &Plaintext,
        proof: &DecryptionProof,
    ) -> Result<(), DecryptionVerifyError> {
        let ct = Ciphertext::from_info(ciphertext)?;
        let decrypted = OctetString::new(plaintext.to_sec1()).map_err(ParseError::from)?;

        let k = fiatshamir::challenge(&self.derive_seed(
            ciphertext,
            &decrypted,
            &proof.wire.a_msg_commitment,
            &proof.wire.b_key_commitment,
        )?);

        let u = ct.u;
        let v = ct.v;
        let a = proof.msg_commitment;
        let b = proof.key_commitment;
        let s = proof.response;

        let lhs1 = u * s;
        let rhs1 = a + (v - plaintext.as_point()) * k;

        if lhs1 != rhs1 {
            return Err(DecryptionError::MsgCommitment.into());
        }

        let lhs2 = ProjectivePoint::GENERATOR * s;
        let rhs2 = b + *self.pk.key().as_point() * k;

        if lhs2 != rhs2 {
            return Err(DecryptionError::KeyCommitment.into());
        }

        Ok(())
    }

    /// Build the strong Fiat–Shamir seed.
    fn derive_seed(
        &self,
        ciphertext: &ElGamalCiphertextInfo,
        decrypted: &OctetString,
        msg_commitment: &OctetString,
        key_commitment: &OctetString,
    ) -> Result<Vec<u8>, ParseError> {
        let domain = GeneralString::from(PROOF_DOMAIN);

        Ok(ECCElGamalDecryptionChallenge {
            ni_proof_domain: &domain,
            public_key: self.pk.spki(),
            ciphertext_info: ciphertext,
            encoded_plaintext: decrypted,
            a_msg_commitment: msg_commitment,
            b_key_commitment: key_commitment,
        }
        .to_der()?)
    }
}
