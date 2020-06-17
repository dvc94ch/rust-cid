use std::convert::TryFrom;

use multibase::{encode as base_encode, Base};
use multihash::{MultihashCode, MultihashDigest};
use unsigned_varint::{decode as varint_decode, encode as varint_encode};

use crate::codec::Codec;
use crate::error::{Error, Result};
use crate::version::Version;

/// Representation of a CID.
///
/// Usually you would use `Cid` instead, unless you have a custom Multihash code table
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord)]
pub struct Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    /// The version of CID.
    version: Version,
    /// The codec of CID.
    codec: C,
    /// The multihash of CID.
    hash: H::Multihash,
}

impl<C, H> Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    /// Create a new CIDv0.
    pub fn new_v0(hash: H::Multihash) -> Result<Self> {
        if hash.code().into() != 0x12 {
            return Err(Error::InvalidCidV0Multihash);
        }
        Ok(Self {
            version: Version::V0,
            // Convert the code of `DagProtobuf` into the given code table
            codec: C::try_from(Codec::DagProtobuf.into()).map_err(|_| Error::UnknownCodec)?,
            hash,
        })
    }

    /// Create a new CIDv1.
    pub fn new_v1(codec: C, hash: H::Multihash) -> Self {
        Self {
            version: Version::V1,
            codec,
            hash,
        }
    }

    /// Create a new CID.
    pub fn new(version: Version, codec: C, hash: H::Multihash) -> Result<Self> {
        match version {
            Version::V0 => {
                if codec.into() != u64::from(Codec::DagProtobuf) {
                    return Err(Error::InvalidCidV0Codec);
                }
                Self::new_v0(hash)
            }
            Version::V1 => Ok(Self::new_v1(codec, hash)),
        }
    }

    /// Returns the cid version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the cid codec.
    pub fn codec(&self) -> C {
        self.codec
    }

    /// Returns the cid multihash.
    pub fn hash(&self) -> &H::Multihash {
        &self.hash
    }

    fn to_string_v0(&self) -> String {
        Base::Base58Btc.encode(self.hash.to_bytes())
    }

    fn to_string_v1(&self) -> String {
        multibase::encode(Base::Base32Lower, self.to_bytes().as_slice())
    }

    fn to_bytes_v0(&self) -> Vec<u8> {
        self.hash.to_bytes()
    }

    fn to_bytes_v1(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(16);

        let mut buf = varint_encode::u64_buffer();
        let version = varint_encode::u64(self.version.into(), &mut buf);
        res.extend_from_slice(version);
        let mut buf = varint_encode::u64_buffer();
        let codec = varint_encode::u64(self.codec.into(), &mut buf);
        res.extend_from_slice(codec);
        res.extend_from_slice(&self.hash.to_bytes());

        res
    }

    /// Convert CID to encoded bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.version {
            Version::V0 => self.to_bytes_v0(),
            Version::V1 => self.to_bytes_v1(),
        }
    }

    /// Convert CID into a multibase encoded string
    ///
    /// # Example
    ///
    /// ```
    /// use cid::{Cid, Codec};
    /// use multibase::Base;
    /// use multihash::{Code, MultihashCode};
    ///
    /// let cid = Cid::<Codec, Code>::new_v1(Codec::Raw, Code::Sha2_256.digest(b"foo"));
    /// let encoded = cid.to_string_of_base(Base::Base64).unwrap();
    /// assert_eq!(encoded, "mAVUSICwmtGto/8aP+ZtFPB0wQTQTQi1wZIO/oPmKXohiZueu");
    /// ```
    pub fn to_string_of_base(&self, base: Base) -> Result<String> {
        match self.version {
            Version::V0 => {
                if base == Base::Base58Btc {
                    Ok(self.to_string_v0())
                } else {
                    Err(Error::InvalidCidV0Base)
                }
            }
            Version::V1 => Ok(base_encode(base, self.to_bytes())),
        }
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl<C, H> std::hash::Hash for Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    fn hash<T: std::hash::Hasher>(&self, state: &mut T) {
        self.to_bytes().hash(state);
    }
}

impl<C, H> std::fmt::Display for Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let output = match self.version {
            Version::V0 => self.to_string_v0(),
            Version::V1 => self.to_string_v1(),
        };
        write!(f, "{}", output)
    }
}

impl<C, H> std::str::FromStr for Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    type Err = Error;

    fn from_str(cid_str: &str) -> Result<Self> {
        Self::try_from(cid_str)
    }
}

impl<C, H> TryFrom<String> for Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    type Error = Error;

    fn try_from(cid_str: String) -> Result<Self> {
        Self::try_from(cid_str.as_str())
    }
}

impl<C, H> TryFrom<&str> for Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    type Error = Error;

    fn try_from(cid_str: &str) -> Result<Self> {
        static IPFS_DELIMETER: &str = "/ipfs/";

        let hash = match cid_str.find(IPFS_DELIMETER) {
            Some(index) => &cid_str[index + IPFS_DELIMETER.len()..],
            _ => cid_str,
        };

        if hash.len() < 2 {
            return Err(Error::InputTooShort);
        }

        let decoded = if Version::is_v0_str(hash) {
            Base::Base58Btc.decode(hash)?
        } else {
            let (_, decoded) = multibase::decode(hash)?;
            decoded
        };

        Self::try_from(decoded)
    }
}

impl<C, H> TryFrom<Vec<u8>> for Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from(bytes.as_slice())
    }
}

impl<C, H> TryFrom<&[u8]> for Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if Version::is_v0_binary(bytes) {
            let mh = H::Multihash::from_bytes(bytes)?;
            Self::new_v0(mh)
        } else {
            let (raw_version, remain) = varint_decode::u64(&bytes)?;
            let version = Version::try_from(raw_version)?;

            let (raw_codec, hash) = varint_decode::u64(&remain)?;
            let codec = C::try_from(raw_codec).map_err(|_| Error::UnknownCodec)?;

            let mh = H::Multihash::from_bytes(hash)?;

            Self::new(version, codec, mh)
        }
    }
}

impl<C, H> From<&Cid<C, H>> for Cid<C, H>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    fn from(cid: &Cid<C, H>) -> Self {
        cid.clone()
    }
}

impl<C, H> From<Cid<C, H>> for Vec<u8>
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    fn from(cid: Cid<C, H>) -> Self {
        cid.to_bytes()
    }
}

impl<C, H> From<Cid<C, H>> for String
where
    C: Into<u64> + TryFrom<u64> + Copy,
    H: MultihashCode,
{
    fn from(cid: Cid<C, H>) -> Self {
        cid.to_string()
    }
}
