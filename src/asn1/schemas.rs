use der::asn1::{BitString, ObjectIdentifier, OctetString, Uint};
use der::{Any, Encode, EncodeValue, FixedTag, Length, Sequence, Tag, Writer};

use crate::asn1::general_string::GeneralString;

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

/// Currently, the ciphertext is the `ECCElGamalCiphertext` for simplicity
/// since only ECC IVXV is implemented.
/// The spec defines `ANY DEFINED BY algorithm`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ElGamalCiphertextInfo {
    pub algorithm: AlgorithmIdentifier,
    pub ciphertext: ECCElGamalCiphertext,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ECCElGamalParameters {
    pub curve: GeneralString,
    pub election_id: GeneralString,
    /// Not yet part of the spec, but speculated based on public configurations.
    pub lifted: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ECCElGamalPublicKey {
    pub pub_y: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ECCElGamalCiphertext {
    pub u_blind: OctetString,
    pub v_blinded_message: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ECCElGamalDecryptionProof {
    pub a_msg_commitment: OctetString,
    pub b_key_commitment: OctetString,
    pub s_response: Uint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ECCElGamalDecryptionChallenge<'a> {
    pub ni_proof_domain: &'a GeneralString,
    pub public_key: &'a SubjectPublicKeyInfo,
    pub ciphertext_info: &'a ElGamalCiphertextInfo,
    pub encoded_plaintext: &'a OctetString,
    pub a_msg_commitment: &'a OctetString,
    pub b_key_commitment: &'a OctetString,
}

impl FixedTag for ECCElGamalDecryptionChallenge<'_> {
    const TAG: Tag = Tag::Sequence;
}

impl EncodeValue for ECCElGamalDecryptionChallenge<'_> {
    fn value_len(&self) -> der::Result<Length> {
        self.ni_proof_domain.encoded_len()?
            + self.public_key.encoded_len()?
            + self.ciphertext_info.encoded_len()?
            + self.encoded_plaintext.encoded_len()?
            + self.a_msg_commitment.encoded_len()?
            + self.b_key_commitment.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.ni_proof_domain.encode(writer)?;
        self.public_key.encode(writer)?;
        self.ciphertext_info.encode(writer)?;
        self.encoded_plaintext.encode(writer)?;
        self.a_msg_commitment.encode(writer)?;
        self.b_key_commitment.encode(writer)
    }
}
