use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    /// The bytes are not the expected ASN.1 structure.
    #[error("malformed ASN.1: {0}")]
    Asn1(#[from] der::Error),

    /// The bytes are not a SEC1 point encoding.
    #[error("invalid SEC1 point encoding")]
    PointEncoding,

    /// The bytes represent a point off the curve.
    #[error("point is not on the curve")]
    PointNotOnCurve,

    /// The ASN.1 integer is wider than the group scalar.
    #[error("integer is {len} bytes wide, exceeds the {max}-byte scalar width")]
    IntegerTooLong {
        /// Width of the integer, in bytes.
        len: usize,
        /// Width of a scalar, in bytes.
        max: usize,
    },

    /// The integer exceeds the group order.
    #[error("integer is not less than the group order")]
    ScalarOutOfRange,

    /// A `BIT STRING` has a bit-length that is not a byte multiple.
    #[error("bit string does not divide into bytes")]
    BitStringUnaligned,

    /// The bytes are not a well-formed PEM document.
    #[error("malformed PEM: {0}")]
    Pem(#[from] pem::PemError),

    /// A key's `AlgorithmIdentifier` lacks parameters.
    #[error("key has no algorithm parameters")]
    MissingParameters,

    /// IVXV currently only uses P-384.
    #[error("unsupported curve {name:?}, expected P-384")]
    UnsupportedCurve {
        /// The curve name in the key.
        name: String,
    },

    /// A key's election identifier is not UTF-8.
    #[error("election id is not valid UTF-8")]
    ElectionIdEncoding,
}
