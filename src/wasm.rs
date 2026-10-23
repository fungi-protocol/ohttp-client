//! `wasm-bindgen` exports for browser hosts that do their own `fetch`.

use wasm_bindgen::prelude::*;

use crate::{parse_key_config, OhttpClient, Response, ResponseContext, Url};

fn js_err(err: impl std::fmt::Display) -> JsError {
    JsError::new(&err.to_string())
}

/// [`OhttpClient`] for JS. The host sends the outer request and passes the
/// response to [`Encapsulated::decapsulate`].
#[wasm_bindgen(js_name = OhttpClient)]
pub struct WasmOhttpClient {
    inner: OhttpClient,
}

#[wasm_bindgen(js_class = OhttpClient)]
impl WasmOhttpClient {
    #[wasm_bindgen(constructor)]
    pub fn new(relay: &str, target: &str, key_config: &[u8]) -> Result<WasmOhttpClient, JsError> {
        let relay = Url::parse(relay).map_err(js_err)?;
        let target = Url::parse(target).map_err(js_err)?;
        let key_config = parse_key_config(key_config).map_err(js_err)?;
        Ok(Self {
            inner: OhttpClient::new(relay, target, key_config),
        })
    }

    /// See [`OhttpClient::known_padded_bhttp_req_length`].
    pub fn known_padded_bhttp_req_length(mut self, n: usize) -> WasmOhttpClient {
        self.inner = self.inner.known_padded_bhttp_req_length(n);
        self
    }

    /// Start a request to `path` on the target origin.
    pub fn encapsulate(&self, method: &str, path: &str) -> EncapsulateBuilder {
        EncapsulateBuilder {
            client: self.inner.clone(),
            method: method.to_owned(),
            path: path.to_owned(),
            headers: Vec::new(),
            query: Vec::new(),
            body: None,
        }
    }
}

#[wasm_bindgen]
pub struct EncapsulateBuilder {
    client: OhttpClient,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl EncapsulateBuilder {
    pub fn header(mut self, name: &str, value: &str) -> EncapsulateBuilder {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn param(mut self, key: &str, value: &str) -> EncapsulateBuilder {
        self.query.push((key.to_owned(), value.to_owned()));
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> EncapsulateBuilder {
        self.body = Some(body);
        self
    }

    pub fn build(self) -> Result<Encapsulated, JsError> {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let query: Vec<(&str, &str)> = self
            .query
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let (req, ctx) = self
            .client
            .encapsulate(
                &self.method,
                &self.path,
                &headers,
                &query,
                self.body.as_deref(),
            )
            .map_err(js_err)?;
        Ok(Encapsulated {
            url: req.url.to_string(),
            content_type: req.content_type.to_owned(),
            body: req.body,
            context: ctx,
        })
    }
}

/// Outer request and the context that decapsulates its response.
#[wasm_bindgen]
pub struct Encapsulated {
    url: String,
    content_type: String,
    body: Vec<u8>,
    context: ResponseContext,
}

#[wasm_bindgen]
impl Encapsulated {
    #[wasm_bindgen(getter)]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn content_type(&self) -> String {
        self.content_type.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }

    /// Decapsulate the relay's response body.
    pub fn decapsulate(self, response_body: &[u8]) -> Result<WasmResponse, JsError> {
        self.context
            .decapsulate(response_body)
            .map(WasmResponse)
            .map_err(js_err)
    }
}

/// Decapsulated inner response.
#[wasm_bindgen(js_name = OhttpResponse)]
pub struct WasmResponse(Response);

#[wasm_bindgen(js_class = OhttpResponse)]
impl WasmResponse {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> u16 {
        self.0.status()
    }

    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.0.body().to_vec()
    }

    /// First value of header `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<Vec<u8>> {
        self.0.header(name).map(|v| v.to_vec())
    }
}
