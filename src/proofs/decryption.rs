use der::asn1::OctetString;
use der::{Decode, Encode};
use p384::elliptic_curve::rand_core::CryptoRng;
use p384::elliptic_curve::Field;
use p384::{ProjectivePoint, Scalar};
use thiserror::Error;

use crate::asn1::general_string::GeneralString;
use crate::asn1::schemas::{self, ECCElGamalDecryptionChallenge, ElGamalCiphertextInfo};
use crate::codec::{point_from_sec1, point_to_sec1, scalar_from_uint, scalar_to_uint};
use crate::election::ElectionPublicKey;
use crate::elgamal::{Ciphertext, Plaintext, SecretKey};
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

    /// Prove that `ciphertext` decrypts to `plaintext` under `sk`.
    pub fn prove(
        &self,
        sk: &SecretKey,
        ciphertext: &ElGamalCiphertextInfo,
        plaintext: &Plaintext,
        rng: &mut impl CryptoRng,
    ) -> Result<DecryptionProof, ParseError> {
        let ct = Ciphertext::from_info(ciphertext)?;

        let t = Scalar::random(rng);
        let a = ct.u * t;
        let b = ProjectivePoint::GENERATOR * t;

        let a_octets = OctetString::new(point_to_sec1(&a))?;
        let b_octets = OctetString::new(point_to_sec1(&b))?;
        let m_octets = OctetString::new(plaintext.to_sec1())?;

        let challenge =
            fiatshamir::challenge(&self.derive_seed(ciphertext, &m_octets, &a_octets, &b_octets)?);

        let s = challenge * *sk.as_scalar().as_ref() + t;

        Ok(DecryptionProof {
            wire: schemas::ECCElGamalDecryptionProof {
                a_msg_commitment: a_octets,
                b_key_commitment: b_octets,
                s_response: scalar_to_uint(&s)?,
            },
            msg_commitment: a,
            key_commitment: b,
            response: s,
        })
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

    /// Decode a ciphertext, message and proof,
    /// then verify the ZKP of correct decryption.
    pub fn verify_der(
        &self,
        ciphertext_der: &[u8],
        message_der: &[u8],
        proof_der: &[u8],
    ) -> Result<(), DecryptionVerifyError> {
        let ciphertext =
            ElGamalCiphertextInfo::from_der(ciphertext_der).map_err(ParseError::from)?;
        let plaintext = Plaintext::from_der(message_der)?;
        self.verify(
            &ciphertext,
            &plaintext,
            &DecryptionProof::from_der(proof_der)?,
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    use p384::elliptic_curve::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    struct Fixture {
        sk: SecretKey,
        election_pk: ElectionPublicKey,
        info: ElGamalCiphertextInfo,
        plaintext: Plaintext,
        rng: ChaCha20Rng,
    }

    fn fixture() -> Fixture {
        let mut rng = ChaCha20Rng::seed_from_u64(0x1234);

        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public_key();

        let message = Plaintext::lift(&Scalar::random(&mut rng));
        let (ciphertext, _) = pk.encrypt(&message, &mut rng);

        let decrypted = sk.decrypt(&ciphertext);
        assert_eq!(decrypted.as_point(), message.as_point());

        let election_pk = ElectionPublicKey::new(pk, "test").unwrap();

        Fixture {
            sk,
            election_pk,
            info: ciphertext.to_info().unwrap(),
            plaintext: message,
            rng,
        }
    }

    #[test]
    fn honest_proof_verifies() {
        let mut f = fixture();
        let ctx = DecryptionContext::new(&f.election_pk);

        let proof = ctx.prove(&f.sk, &f.info, &f.plaintext, &mut f.rng).unwrap();

        ctx.verify(&f.info, &f.plaintext, &proof).unwrap();
    }

    #[test]
    fn tampered_response_fails_message_check() {
        let mut f = fixture();
        let ctx = DecryptionContext::new(&f.election_pk);

        let mut proof = ctx.prove(&f.sk, &f.info, &f.plaintext, &mut f.rng).unwrap();

        proof.response += Scalar::ONE;

        let err = ctx.verify(&f.info, &f.plaintext, &proof).unwrap_err();
        assert!(matches!(
            err,
            DecryptionVerifyError::Invalid(DecryptionError::MsgCommitment)
        ));
    }

    #[test]
    fn tampered_key_commitment_fails_key_check() {
        let mut f = fixture();
        let ctx = DecryptionContext::new(&f.election_pk);

        let mut proof = ctx.prove(&f.sk, &f.info, &f.plaintext, &mut f.rng).unwrap();

        proof.key_commitment += ProjectivePoint::GENERATOR;

        let err = ctx.verify(&f.info, &f.plaintext, &proof).unwrap_err();
        assert!(matches!(
            err,
            DecryptionVerifyError::Invalid(DecryptionError::KeyCommitment)
        ));
    }

    #[test]
    fn wrong_plaintext_fails_message_check() {
        let mut f = fixture();
        let ctx = DecryptionContext::new(&f.election_pk);

        let proof = ctx.prove(&f.sk, &f.info, &f.plaintext, &mut f.rng).unwrap();

        let other = Plaintext::lift(&Scalar::random(&mut f.rng));
        assert_ne!(other.as_point(), f.plaintext.as_point());

        let err = ctx.verify(&f.info, &other, &proof).unwrap_err();
        assert!(matches!(
            err,
            DecryptionVerifyError::Invalid(DecryptionError::MsgCommitment)
        ));
    }
}
