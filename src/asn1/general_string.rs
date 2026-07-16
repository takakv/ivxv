//! An owned ASN.1 `GeneralString`, which the `der` crate does not yet provide.

use der::asn1::GeneralStringRef;
use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Result, Tag, Writer};

/// ASN.1 `GeneralString` type, since the `der` crate does not implement it yet.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct GeneralString(Vec<u8>);

impl GeneralString {
    /// Wrap the given bytes as a `GeneralString`.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The string contents, without the tag or length.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FixedTag for GeneralString {
    const TAG: Tag = Tag::GeneralString;
}

impl<'a> DecodeValue<'a> for GeneralString {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Ok(Self(reader.read_vec(header.length())?))
    }
}

impl EncodeValue for GeneralString {
    fn value_len(&self) -> Result<Length> {
        Length::try_from(self.0.len())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        writer.write(&self.0)
    }
}

impl From<&str> for GeneralString {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes())
    }
}

impl From<GeneralStringRef<'_>> for GeneralString {
    fn from(s: GeneralStringRef<'_>) -> Self {
        Self::new(s.as_bytes())
    }
}
