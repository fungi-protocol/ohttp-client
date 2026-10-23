//! Sans-IO [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458) client.
//!
//! Builds and encapsulates BHTTP inner requests, decapsulates responses, and
//! parses gateway key configs. The caller sends the outer request.
//!
//! ```no_run
//! use ohttp_client::{OhttpClient, Url, parse_key_config};
//!
//! # fn send(req: &ohttp_client::OhttpRequest) -> Vec<u8> { unimplemented!() }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key_bytes: Vec<u8> = /* GET https://gateway.example/ohttp-keys */
//! #    vec![];
//! let client = OhttpClient::new(
//!     Url::parse("https://relay.example/")?,
//!     Url::parse("https://target.example/")?,
//!     parse_key_config(&key_bytes)?,
//! );
//!
//! // POST `req.body` to `req.url` with `req.content_type`.
//! let (req, ctx) = client.encapsulate(
//!     "POST",
//!     "/resource",
//!     &[("content-type", "text/plain")],
//!     &[],
//!     Some(b"hello"),
//! )?;
//! let outer_response_body = send(&req);
//! let response = ctx.decapsulate(&outer_response_body)?;
//! assert_eq!(response.status(), 200);
//! # Ok(())
//! # }
//! ```
//!
//! The `bitreq` feature adds `OhttpClient::from_gateway` and a request
//! builder that do the IO. The `wasm` feature adds `wasm-bindgen` exports for
//! browsers.

use std::io::Cursor;
use std::sync::Once;

use bhttp::{Message, Mode};

pub use url::Url;

mod error;
pub use error::Error;

#[cfg(feature = "bitreq")]
mod http;
#[cfg(feature = "bitreq")]
pub use http::RequestBuilder;

#[cfg(feature = "wasm")]
mod wasm;
#[cfg(feature = "wasm")]
pub use wasm::{EncapsulateBuilder, Encapsulated, WasmOhttpClient, WasmResponse};

#[cfg(feature = "harness")]
pub mod harness;

/// Media type of an encapsulated request, per RFC 9458.
pub const OHTTP_REQ_CONTENT_TYPE: &str = "message/ohttp-req";

/// A gateway key config, held by whichever OHTTP backend supports its KEM.
#[derive(Debug, Clone)]
pub struct KeyConfig(KeyConfigInner);

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // One per client.
enum KeyConfigInner {
    Ohttp(ohttp::KeyConfig),
    #[cfg(feature = "secp256k1")]
    Secp256k1(bitcoin_ohttp::KeyConfig),
}

impl From<ohttp::KeyConfig> for KeyConfig {
    fn from(config: ohttp::KeyConfig) -> Self {
        Self(KeyConfigInner::Ohttp(config))
    }
}

#[cfg(feature = "secp256k1")]
impl From<bitcoin_ohttp::KeyConfig> for KeyConfig {
    fn from(config: bitcoin_ohttp::KeyConfig) -> Self {
        Self(KeyConfigInner::Secp256k1(config))
    }
}

impl KeyConfig {
    /// Decode one config with the backend that supports its KEM, or `None`
    /// if no backend in this build does.
    fn decode(encoded: &[u8]) -> Result<Option<Self>, Error> {
        match ohttp::KeyConfig::decode(encoded) {
            Ok(config) => return Ok(Some(config.into())),
            Err(ohttp::Error::Unsupported) => {}
            Err(e) => return Err(e.into()),
        }
        // FIXME: `bitcoin-ohttp` 0.6 keeps AES-128-GCM suites when decoding, but
        // its secp256k1 sender cannot use them: a config listing AES-128-GCM
        // before ChaCha20Poly1305 fails to encapsulate with `InvalidKeyType`.
        #[cfg(feature = "secp256k1")]
        match bitcoin_ohttp::KeyConfig::decode(encoded) {
            Ok(config) => return Ok(Some(config.into())),
            Err(bitcoin_ohttp::Error::Unsupported) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(None)
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(match &self.0 {
            KeyConfigInner::Ohttp(config) => config.encode()?,
            #[cfg(feature = "secp256k1")]
            KeyConfigInner::Secp256k1(config) => config.encode()?,
        })
    }
}

/// Parse an `application/ohttp-keys` body (RFC 9540) and return the first
/// config this build can use.
pub fn parse_key_config(bytes: &[u8]) -> Result<KeyConfig, Error> {
    init();
    let mut configs = Vec::new();
    let mut rest = bytes;
    while let Some((len, tail)) = rest.split_first_chunk::<2>() {
        let (config, tail) = tail
            .split_at_checked(usize::from(u16::from_be_bytes(*len)))
            .ok_or(ohttp::Error::Truncated)?;
        configs.extend(KeyConfig::decode(config)?);
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(ohttp::Error::Truncated.into());
    }
    configs
        .into_iter()
        .find(has_usable_suite)
        .ok_or(Error::NoKeyConfig)
}

/// Whether `config` has a symmetric suite left after decoding.
///
/// `decode` drops unsupported suites but keeps a config with none, which makes
/// `ohttp::ClientRequest::from_config` panic. Suites are private, so this
/// checks the encoding: an empty suite list ends in a zero length field, and a
/// non-empty one ends in a nonzero AEAD id.
fn has_usable_suite(config: &KeyConfig) -> bool {
    config.encode().is_ok_and(|enc| !enc.ends_with(&[0, 0]))
}

fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        ohttp::init();
        #[cfg(feature = "secp256k1")]
        bitcoin_ohttp::init();
    });
}

/// An OHTTP client for one relay, target origin and gateway key config.
///
/// Each [`encapsulate`](Self::encapsulate) call takes a path on the target
/// origin. The target may differ from the gateway.
#[derive(Debug, Clone)]
pub struct OhttpClient {
    key_config: KeyConfig,
    relay: Url,
    /// Origin plus an optional base path.
    target: Url,
    known_padded_bhttp_req_length: Option<usize>,
}

impl OhttpClient {
    /// `target` is the base URL that request paths are appended to.
    pub fn new(relay: Url, target: Url, key_config: KeyConfig) -> Self {
        init();
        Self {
            relay,
            target,
            key_config,
            known_padded_bhttp_req_length: None,
        }
    }

    /// Pad each BHTTP inner request to `known_padded_bhttp_req_length` bytes
    /// with random trailing bytes. Encapsulation fails with
    /// [`Error::KnownLengthTooSmall`] if a request is longer.
    pub fn known_padded_bhttp_req_length(mut self, known_padded_bhttp_req_length: usize) -> Self {
        self.known_padded_bhttp_req_length = Some(known_padded_bhttp_req_length);
        self
    }

    /// Encapsulate an inner request to `path` on the target origin.
    ///
    /// `path` is appended to the target's path, and `query` pairs are
    /// percent-encoded and appended to its query. Returns the outer request to
    /// POST to the relay and the context that decapsulates its response.
    ///
    /// Fails with [`Error::PathEscapesOrigin`] if `path` is an absolute URL or
    /// leaves the target origin.
    pub fn encapsulate(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        query: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<(OhttpRequest, ResponseContext), Error> {
        let mut target = resolve_target(&self.target, path)?;
        if !query.is_empty() {
            let mut pairs = target.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        let authority = target[url::Position::BeforeHost..url::Position::AfterPort].as_bytes();
        let path_and_query = target[url::Position::BeforePath..].as_bytes();
        let mut inner = Message::request(
            method.as_bytes().to_vec(),
            target.scheme().as_bytes().to_vec(),
            authority.to_vec(),
            path_and_query.to_vec(),
        );
        for (name, value) in headers {
            inner.put_header(name.as_bytes(), value.as_bytes());
        }
        if let Some(body) = body {
            inner.write_content(body);
        }
        let bhttp_bytes = write_bhttp_payload(&inner, self.known_padded_bhttp_req_length)?;

        let (encapsulated, ctx) = match &self.key_config.0 {
            KeyConfigInner::Ohttp(config) => {
                let (encapsulated, ctx) = ohttp::ClientRequest::from_config(&mut config.clone())?
                    .encapsulate(&bhttp_bytes)?;
                (encapsulated, ResponseContextInner::Ohttp(ctx))
            }
            #[cfg(feature = "secp256k1")]
            KeyConfigInner::Secp256k1(config) => {
                let (encapsulated, ctx) =
                    bitcoin_ohttp::ClientRequest::from_config(&mut config.clone())?
                        .encapsulate(&bhttp_bytes)?;
                (encapsulated, ResponseContextInner::Secp256k1(ctx))
            }
        };
        Ok((
            OhttpRequest {
                url: self.relay.clone(),
                content_type: OHTTP_REQ_CONTENT_TYPE,
                body: encapsulated,
            },
            ResponseContext(ctx),
        ))
    }
}

/// Append `path` to `base`'s path. Unlike [`Url::join`], a leading `/` does
/// not replace `base`'s path.
fn resolve_target(base: &Url, path: &str) -> Result<Url, Error> {
    if path.starts_with("//") || Url::parse(path).is_ok() {
        return Err(Error::PathEscapesOrigin);
    }

    let (path_part, path_query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    let mut target = base.clone();
    target.set_path(&append_paths(base.path(), path_part));
    if let Some(q) = path_query {
        match target.query() {
            Some(existing) => {
                let mut merged = String::with_capacity(existing.len() + 1 + q.len());
                merged.push_str(existing);
                merged.push('&');
                merged.push_str(q);
                target.set_query(Some(&merged));
            }
            None => {
                target.set_query(Some(q));
            }
        }
    }

    if target.origin() != base.origin() {
        return Err(Error::PathEscapesOrigin);
    }
    Ok(target)
}

/// Join two URL paths with a single `/` between them.
fn append_paths(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        if base.is_empty() {
            "/".to_owned()
        } else {
            base.to_owned()
        }
    } else if base.is_empty() {
        format!("/{path}")
    } else {
        format!("{base}/{path}")
    }
}

/// Serialize `inner` as known-length BHTTP, padded with random bytes to
/// `known_padded_bhttp_req_length` if set.
fn write_bhttp_payload(
    inner: &Message,
    known_padded_bhttp_req_length: Option<usize>,
) -> Result<Vec<u8>, Error> {
    let mut msg = Vec::new();
    inner.write_bhttp(Mode::KnownLength, &mut msg)?;
    let Some(len) = known_padded_bhttp_req_length else {
        return Ok(msg);
    };
    if msg.len() > len {
        return Err(Error::KnownLengthTooSmall {
            needed: msg.len(),
            known_padded_bhttp_req_length: len,
        });
    }
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf)?;
    buf[..msg.len()].copy_from_slice(&msg);
    Ok(buf)
}

/// Outer request: POST `body` to `url` with `content_type`.
#[derive(Debug, Clone)]
pub struct OhttpRequest {
    pub url: Url,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

/// Decapsulates the response to one encapsulated request.
pub struct ResponseContext(ResponseContextInner);

enum ResponseContextInner {
    Ohttp(ohttp::ClientResponse),
    #[cfg(feature = "secp256k1")]
    Secp256k1(bitcoin_ohttp::ClientResponse),
}

impl ResponseContext {
    /// Decapsulate the relay's response body.
    pub fn decapsulate(self, encapsulated: &[u8]) -> Result<Response, Error> {
        let bhttp_bytes = match self.0 {
            ResponseContextInner::Ohttp(ctx) => ctx.decapsulate(encapsulated)?,
            #[cfg(feature = "secp256k1")]
            ResponseContextInner::Secp256k1(ctx) => ctx.decapsulate(encapsulated)?,
        };
        let inner = Message::read_bhttp(&mut Cursor::new(&bhttp_bytes[..]))?;
        let status = inner.control().status().ok_or(Error::NotAResponse)?.code();
        let headers = inner
            .header()
            .iter()
            .map(|f| (f.name().to_vec(), f.value().to_vec()))
            .collect();
        Ok(Response {
            status,
            headers,
            body: inner.content().to_vec(),
        })
    }
}

/// Decapsulated inner response.
#[derive(Debug, Clone)]
pub struct Response {
    status: u16,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> u16 {
        self.status
    }

    /// First value of header `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v.as_slice())
    }

    pub fn headers(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.headers
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ohttp::hpke::{Aead, Kdf, Kem};
    use ohttp::{KeyConfig, SymmetricSuite};

    /// Every KEM `ohttp` implements, including the post-quantum X-Wing.
    const SUPPORTED_KEMS: [Kem; 3] = [Kem::X25519Sha256, Kem::P256Sha256, Kem::XWing];

    fn test_key_config() -> KeyConfig {
        key_config_with_kem(Kem::X25519Sha256)
    }

    fn key_config_with_kem(kem: Kem) -> KeyConfig {
        init();
        KeyConfig::new(
            1,
            kem,
            vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)],
        )
        .unwrap()
    }

    fn test_client(config: impl Into<crate::KeyConfig>) -> OhttpClient {
        OhttpClient::new(
            Url::parse("https://relay.example/").unwrap(),
            Url::parse("https://target.example:8443/").unwrap(),
            config.into(),
        )
    }

    #[test]
    fn round_trip() {
        let server = ohttp::Server::new(test_key_config()).unwrap();
        let client = test_client(server.config().clone());

        let (req, ctx) = client
            .encapsulate(
                "POST",
                "/api/v1/thing?x=1",
                &[("content-type", "text/plain")],
                &[],
                Some(b"hello"),
            )
            .unwrap();
        assert_eq!(req.url.as_str(), "https://relay.example/");
        assert_eq!(req.content_type, "message/ohttp-req");

        // Gateway side: decapsulate and inspect the inner request.
        let (inner_bytes, server_ctx) = server.decapsulate(&req.body).unwrap();
        let inner = Message::read_bhttp(&mut Cursor::new(&inner_bytes[..])).unwrap();
        assert_eq!(inner.control().method(), Some(&b"POST"[..]));
        assert_eq!(inner.control().scheme(), Some(&b"https"[..]));
        assert_eq!(
            inner.control().authority(),
            Some(&b"target.example:8443"[..])
        );
        assert_eq!(inner.control().path(), Some(&b"/api/v1/thing?x=1"[..]));
        assert_eq!(
            inner.header().get(b"content-type"),
            Some(&b"text/plain"[..])
        );
        assert_eq!(inner.content(), b"hello");

        // Gateway responds; client decapsulates the inner response.
        let mut inner_res = Message::response(bhttp::StatusCode::try_from(200u16).unwrap());
        inner_res.put_header("content-type", "application/json");
        inner_res.write_content(b"{\"ok\":true}");
        let mut res_bytes = Vec::new();
        inner_res
            .write_bhttp(Mode::KnownLength, &mut res_bytes)
            .unwrap();
        let enc_res = server_ctx.encapsulate(&res_bytes).unwrap();

        let response = ctx.decapsulate(&enc_res).unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.header("Content-Type"),
            Some(&b"application/json"[..])
        );
        assert_eq!(response.body(), b"{\"ok\":true}");
    }

    #[test]
    fn encapsulate_appends_query_params() {
        let server = ohttp::Server::new(test_key_config()).unwrap();
        let client = OhttpClient::new(
            Url::parse("https://relay.example/").unwrap(),
            Url::parse("https://target.example/").unwrap(),
            server.config().clone().into(),
        );

        let (req, _) = client
            .encapsulate(
                "GET",
                "/echo?existing=1",
                &[],
                &[("x", "1"), ("q", "hello world")],
                None,
            )
            .unwrap();
        let (inner_bytes, _) = server.decapsulate(&req.body).unwrap();
        let inner = Message::read_bhttp(&mut Cursor::new(&inner_bytes[..])).unwrap();
        assert_eq!(
            inner.control().path(),
            Some(&b"/echo?existing=1&x=1&q=hello+world"[..])
        );
    }

    #[test]
    fn encapsulate_rejects_absolute_url() {
        let client = OhttpClient::new(
            Url::parse("https://relay.example/").unwrap(),
            Url::parse("https://target.example/").unwrap(),
            test_key_config().into(),
        );

        assert!(matches!(
            client.encapsulate("GET", "https://other.example/foo", &[], &[], None),
            Err(Error::PathEscapesOrigin)
        ));
        assert!(matches!(
            client.encapsulate("GET", "//evil.example/foo", &[], &[], None),
            Err(Error::PathEscapesOrigin)
        ));
    }

    #[test]
    fn encapsulate_appends_path_to_api_base() {
        let server = ohttp::Server::new(test_key_config()).unwrap();
        // No trailing slash on the API base — leading `/` on path must not drop `/api`.
        let client = OhttpClient::new(
            Url::parse("https://relay.example/").unwrap(),
            Url::parse("https://target.example/api").unwrap(),
            server.config().clone().into(),
        );

        let (req, _) = client
            .encapsulate("GET", "/tx/abc", &[], &[], None)
            .unwrap();
        let (inner_bytes, _) = server.decapsulate(&req.body).unwrap();
        let inner = Message::read_bhttp(&mut Cursor::new(&inner_bytes[..])).unwrap();
        assert_eq!(inner.control().path(), Some(&b"/api/tx/abc"[..]));

        let (req, _) = client
            .encapsulate("GET", "blocks/tip/height", &[], &[], None)
            .unwrap();
        let (inner_bytes, _) = server.decapsulate(&req.body).unwrap();
        let inner = Message::read_bhttp(&mut Cursor::new(&inner_bytes[..])).unwrap();
        assert_eq!(inner.control().path(), Some(&b"/api/blocks/tip/height"[..]));
    }

    #[test]
    fn append_paths_slash_normalization() {
        assert_eq!(append_paths("/api", "/tx/abc"), "/api/tx/abc");
        assert_eq!(append_paths("/api/", "/tx/abc"), "/api/tx/abc");
        assert_eq!(append_paths("/api", "tx/abc"), "/api/tx/abc");
        assert_eq!(append_paths("/", "/echo"), "/echo");
        assert_eq!(append_paths("", "echo"), "/echo");
    }

    #[test]
    fn parse_key_config_list() {
        let config = test_key_config();
        let encoded = KeyConfig::encode_list(&[&config]).unwrap();
        let parsed = parse_key_config(&encoded).unwrap();
        assert_eq!(parsed.encode().unwrap(), config.encode().unwrap());

        assert!(matches!(parse_key_config(&[]), Err(Error::NoKeyConfig)));
    }

    #[test]
    fn parse_key_config_accepts_every_supported_kem() {
        for kem in SUPPORTED_KEMS {
            let config = key_config_with_kem(kem);
            let encoded = KeyConfig::encode_list(&[&config]).unwrap();
            let parsed = parse_key_config(&encoded).unwrap();
            assert_eq!(parsed.encode().unwrap(), config.encode().unwrap());
        }
    }

    #[test]
    fn round_trips_with_every_supported_kem() {
        for kem in SUPPORTED_KEMS {
            let server = ohttp::Server::new(key_config_with_kem(kem)).unwrap();
            let client = test_client(server.config().clone());

            let (req, ctx) = client.encapsulate("GET", "/", &[], &[], None).unwrap();
            let (_, server_ctx) = server.decapsulate(&req.body).unwrap();

            let mut inner_res = Message::response(bhttp::StatusCode::try_from(200u16).unwrap());
            inner_res.write_content(b"ok");
            let mut res_bytes = Vec::new();
            inner_res
                .write_bhttp(Mode::KnownLength, &mut res_bytes)
                .unwrap();
            let enc_res = server_ctx.encapsulate(&res_bytes).unwrap();

            let response = ctx.decapsulate(&enc_res).unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.body(), b"ok");
        }
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn round_trips_with_secp256k1() {
        use bitcoin_ohttp::hpke::{Aead, Kdf, Kem};

        init();
        let config = bitcoin_ohttp::KeyConfig::new(
            1,
            Kem::K256Sha256,
            vec![bitcoin_ohttp::SymmetricSuite::new(
                Kdf::HkdfSha256,
                Aead::ChaCha20Poly1305,
            )],
        )
        .unwrap();
        let server = bitcoin_ohttp::Server::new(config).unwrap();
        let encoded = bitcoin_ohttp::KeyConfig::encode_list(&[server.config()]).unwrap();
        let client = test_client(parse_key_config(&encoded).unwrap());

        let (req, ctx) = client.encapsulate("GET", "/", &[], &[], None).unwrap();
        let (_, server_ctx) = server.decapsulate(&req.body).unwrap();

        let mut inner_res = Message::response(bhttp::StatusCode::try_from(200u16).unwrap());
        inner_res.write_content(b"ok");
        let mut res_bytes = Vec::new();
        inner_res
            .write_bhttp(Mode::KnownLength, &mut res_bytes)
            .unwrap();
        let enc_res = server_ctx.encapsulate(&res_bytes).unwrap();

        let response = ctx.decapsulate(&enc_res).unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"ok");
    }

    /// Encode `configs` as an `application/ohttp-keys` list, prefixing each
    /// with its two-byte length (mirrors `KeyConfig::encode_list`, but takes
    /// raw bytes so tests can build configs the crate refuses to construct).
    fn encode_raw_list(configs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for config in configs {
            let len = u16::try_from(config.len()).unwrap();
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(config);
        }
        out
    }

    /// A config whose only symmetric suite is one this build does not support,
    /// so `KeyConfig::decode` strips it and leaves the suite list empty.
    fn config_with_no_supported_suite() -> Vec<u8> {
        // `test_key_config` encodes as key_id | kem | pk | suite_len | kdf | aead;
        // swap its trailing suite for HkdfSha256 + AES-256-GCM.
        let mut encoded = test_key_config().encode().unwrap();
        let suite = encoded.len() - 4;
        encoded[suite..].copy_from_slice(&[
            0,
            u16::from(Kdf::HkdfSha256) as u8,
            0,
            u16::from(Aead::Aes256Gcm) as u8,
        ]);
        encoded
    }

    #[test]
    fn parse_key_config_skips_unsupported_kem() {
        // P-384 (0x0011) is in the spec but not in `ohttp`; `decode_list` drops
        // the config, so a later usable one is still selected.
        let mut unsupported = test_key_config().encode().unwrap();
        unsupported[1..3].copy_from_slice(&0x0011u16.to_be_bytes());
        let usable = test_key_config();

        let encoded = encode_raw_list(&[unsupported.clone(), usable.encode().unwrap()]);
        let parsed = parse_key_config(&encoded).unwrap();
        assert_eq!(parsed.encode().unwrap(), usable.encode().unwrap());

        assert!(matches!(
            parse_key_config(&encode_raw_list(&[unsupported])),
            Err(Error::NoKeyConfig)
        ));
    }

    #[test]
    fn parse_key_config_skips_config_with_no_supported_suite() {
        // Alone, it is not usable at all — and must not panic downstream.
        let unusable = config_with_no_supported_suite();
        assert!(matches!(
            parse_key_config(&encode_raw_list(std::slice::from_ref(&unusable))),
            Err(Error::NoKeyConfig)
        ));

        // Listed ahead of a usable config, it is skipped rather than selected.
        let usable = test_key_config();
        let encoded = encode_raw_list(&[unusable, usable.encode().unwrap()]);
        let parsed = parse_key_config(&encoded).unwrap();
        assert_eq!(parsed.encode().unwrap(), usable.encode().unwrap());

        // The selected config encapsulates without panicking.
        let client = test_client(parsed);
        assert!(client.encapsulate("GET", "/", &[], &[], None).is_ok());
    }

    #[test]
    fn encapsulate_pads_to_known_length() {
        let server = ohttp::Server::new(test_key_config()).unwrap();
        let known_padded_bhttp_req_length = 512;
        let client = test_client(server.config().clone())
            .known_padded_bhttp_req_length(known_padded_bhttp_req_length);

        let (req, _) = client
            .encapsulate(
                "POST",
                "/api/v1/thing",
                &[("content-type", "text/plain")],
                &[],
                Some(b"hello"),
            )
            .unwrap();

        let (inner_bytes, _) = server.decapsulate(&req.body).unwrap();
        assert_eq!(inner_bytes.len(), known_padded_bhttp_req_length);

        let mut cursor = Cursor::new(&inner_bytes[..]);
        let inner = Message::read_bhttp(&mut cursor).unwrap();
        assert_eq!(inner.content(), b"hello");
        let msg_len = cursor.position() as usize;
        assert!(msg_len < known_padded_bhttp_req_length);
        // Trailing padding is random, not zero-filled.
        assert!(inner_bytes[msg_len..].iter().any(|&b| b != 0));
    }

    #[test]
    fn encapsulate_rejects_known_length_too_small() {
        let client = test_client(test_key_config()).known_padded_bhttp_req_length(1);
        let result = client.encapsulate("POST", "/", &[], &[], Some(b"hello"));
        assert!(matches!(
            result,
            Err(Error::KnownLengthTooSmall {
                needed,
                known_padded_bhttp_req_length: 1
            }) if needed > 1
        ));
    }
}
