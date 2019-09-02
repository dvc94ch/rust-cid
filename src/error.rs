use std::{error, fmt, io};

/// Error types
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Error {
    UnknownCodec,
    InputTooShort,
    ParsingError,
    InvalidCidVersion,
    InvalidCidV0Codec,
    InvalidCidV0Multihash,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        use self::Error::*;

        match *self {
            UnknownCodec => "Unknown codec",
            InputTooShort => "Input too short",
            ParsingError => "Failed to parse multihash",
            InvalidCidVersion => "Unrecognized CID version",
            InvalidCidV0Codec => "CIDv0 requires a dag-pb codec",
            InvalidCidV0Multihash => "CIDv0 requires a sha2-256 multihash",
        }
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Error {
        Error::ParsingError
    }
}

impl From<multibase::Error> for Error {
    fn from(_: multibase::Error) -> Error {
        Error::ParsingError
    }
}

impl From<multihash::Error> for Error {
    fn from(_: multihash::Error) -> Error {
        Error::ParsingError
    }
}

impl From<Error> for fmt::Error {
    fn from(_: Error) -> fmt::Error {
        fmt::Error {}
    }
}
