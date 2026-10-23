#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ohttp: {0}")]
    Ohttp(#[from] ohttp::Error),
    #[cfg(feature = "secp256k1")]
    #[error("bitcoin-ohttp: {0}")]
    BitcoinOhttp(#[from] bitcoin_ohttp::Error),
    #[error("bhttp: {0}")]
    Bhttp(#[from] bhttp::Error),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
    #[error("getrandom: {0}")]
    GetRandom(#[from] getrandom::Error),
    #[error(
        "bhttp payload ({needed} bytes) exceeds known padded bhttp request length ({known_padded_bhttp_req_length})"
    )]
    KnownLengthTooSmall {
        needed: usize,
        known_padded_bhttp_req_length: usize,
    },
    #[error("no key config found in response")]
    NoKeyConfig,
    #[error("inner message is not a response")]
    NotAResponse,
    #[error("path must stay on the client's target origin")]
    PathEscapesOrigin,
    #[cfg(feature = "bitreq")]
    #[error("bitreq: {0}")]
    Bitreq(#[from] bitreq::Error),
    #[cfg(feature = "bitreq")]
    #[error("relay returned unexpected status: {0}")]
    UnexpectedStatus(i32),
    #[cfg(feature = "bitreq")]
    #[error("relay url has no host")]
    NoRelayHost,
}
