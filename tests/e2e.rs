//! Client -> relay -> gateway -> target round trips against the harness.

use ohttp_client::harness::TestHarness;
use ohttp_client::{parse_key_config, OhttpClient, Url};

#[test]
fn e2e_through_relay_and_gateway() {
    let harness = TestHarness::start();

    let keys_res = bitreq::get(harness.gateway_url()).send().unwrap();
    assert_eq!(keys_res.status_code, 200);
    assert_eq!(
        keys_res.headers.get("content-type").map(String::as_str),
        Some("application/ohttp-keys")
    );

    let client = OhttpClient::new(
        Url::parse(harness.relay_url()).unwrap(),
        Url::parse(harness.target_url()).unwrap(),
        parse_key_config(keys_res.as_bytes()).unwrap(),
    );

    let (req, ctx) = client
        .encapsulate(
            "POST",
            "/echo",
            &[("content-type", "text/plain")],
            &[("x", "1")],
            Some(b"hello"),
        )
        .unwrap();
    let outer_res = bitreq::post(req.url.as_str())
        .with_header("content-type", req.content_type)
        .with_body(req.body.clone())
        .send()
        .unwrap();
    assert_eq!(
        outer_res.status_code,
        200,
        "relay says: {:?}",
        outer_res.as_str()
    );
    assert_eq!(
        outer_res.headers.get("content-type").map(String::as_str),
        Some("message/ohttp-res")
    );

    let response = ctx.decapsulate(outer_res.as_bytes()).unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-type"), Some(&b"text/plain"[..]));
    // The target echoes "<method> <path> <body>".
    assert_eq!(response.body(), b"POST /echo?x=1 hello");
}

/// The gateway ignores the random padding after a known-length message.
#[test]
fn e2e_with_known_length_padding() {
    let harness = TestHarness::start();

    let keys_res = bitreq::get(harness.gateway_url()).send().unwrap();
    assert_eq!(keys_res.status_code, 200);
    let key_config = parse_key_config(keys_res.as_bytes()).unwrap();

    let known_padded_bhttp_req_length = 1024;
    let client = OhttpClient::new(
        Url::parse(harness.relay_url()).unwrap(),
        Url::parse(harness.target_url()).unwrap(),
        key_config.clone(),
    )
    .known_padded_bhttp_req_length(known_padded_bhttp_req_length);

    let (req, ctx) = client
        .encapsulate(
            "POST",
            "/echo",
            &[("content-type", "text/plain")],
            &[("x", "1")],
            Some(b"hello"),
        )
        .unwrap();

    let (unpadded, _) = OhttpClient::new(
        Url::parse(harness.relay_url()).unwrap(),
        Url::parse(harness.target_url()).unwrap(),
        key_config,
    )
    .encapsulate(
        "POST",
        "/echo",
        &[("content-type", "text/plain")],
        &[("x", "1")],
        Some(b"hello"),
    )
    .unwrap();
    assert!(
        req.body.len() > unpadded.body.len(),
        "padded {} vs unpadded {}",
        req.body.len(),
        unpadded.body.len()
    );

    let outer_res = bitreq::post(req.url.as_str())
        .with_header("content-type", req.content_type)
        .with_body(req.body)
        .send()
        .unwrap();
    assert_eq!(
        outer_res.status_code,
        200,
        "relay says: {:?}",
        outer_res.as_str()
    );

    let response = ctx.decapsulate(outer_res.as_bytes()).unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-type"), Some(&b"text/plain"[..]));
    assert_eq!(response.body(), b"POST /echo?x=1 hello");
}

/// The outer request is sent by the `bitreq` request builder.
#[cfg(feature = "bitreq")]
#[test]
fn e2e_send_with_bitreq_feature() {
    let harness = TestHarness::start();

    let keys_res = bitreq::get(harness.gateway_url()).send().unwrap();
    assert_eq!(keys_res.status_code, 200);

    let client = OhttpClient::new(
        Url::parse(harness.relay_url()).unwrap(),
        Url::parse(harness.target_url()).unwrap(),
        parse_key_config(keys_res.as_bytes()).unwrap(),
    );

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let response = runtime
        .block_on(
            client
                .post("/echo")
                .param("x", "1")
                .header("content-type", "text/plain")
                .body("hello")
                .send(),
        )
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"POST /echo?x=1 hello");
}

/// The crate fetches the key config directly and sends the outer request,
/// both with `bitreq`.
#[cfg(feature = "bitreq")]
#[test]
fn e2e_fetch_key_config_and_send_with_bitreq() {
    let harness = TestHarness::start();
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let keys_res = bitreq::get(harness.gateway_url()).send().unwrap();
    assert_eq!(keys_res.status_code, 200);
    let key_config = parse_key_config(keys_res.as_bytes()).unwrap();

    let client = OhttpClient::new(
        Url::parse(harness.relay_url()).unwrap(),
        Url::parse(harness.target_url()).unwrap(),
        key_config,
    );

    let response = runtime
        .block_on(
            client
                .post("/echo")
                .param("x", "1")
                .header("content-type", "text/plain")
                .body("hello")
                .send(),
        )
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-type"), Some(&b"text/plain"[..]));
    assert_eq!(response.body(), b"POST /echo?x=1 hello");
}

/// [`OhttpClient::from_gateway`] fetches the key config through the relay
#[cfg(feature = "bitreq")]
#[test]
fn e2e_from_gateway() {
    let harness = TestHarness::start();
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let client = runtime
        .block_on(OhttpClient::from_gateway(
            Url::parse(harness.relay_url()).unwrap(),
            Url::parse(harness.target_url()).unwrap(),
            harness.gateway_url(),
        ))
        .unwrap();

    // The tunneled key config works for a round trip.
    let (req, ctx) = client
        .encapsulate(
            "POST",
            "/echo",
            &[("content-type", "text/plain")],
            &[("x", "1")],
            Some(b"hello"),
        )
        .unwrap();
    let gateway_res = bitreq::post(harness.gateway_url())
        .with_header("content-type", req.content_type)
        .with_body(req.body)
        .send()
        .unwrap();
    assert_eq!(gateway_res.status_code, 200);

    let response = ctx.decapsulate(gateway_res.as_bytes()).unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-type"), Some(&b"text/plain"[..]));
    assert_eq!(response.body(), b"POST /echo?x=1 hello");
}

/// Round trip through the `wasm-bindgen` API, with `bitreq` in place of
/// `fetch`.
#[cfg(feature = "wasm")]
#[test]
fn e2e_wasm_bindgen_api() {
    use ohttp_client::WasmOhttpClient;

    let harness = TestHarness::start();

    let keys_res = bitreq::get(harness.gateway_url()).send().unwrap();
    assert_eq!(keys_res.status_code, 200);

    let client = WasmOhttpClient::new(
        harness.relay_url(),
        harness.target_url(),
        keys_res.as_bytes(),
    )
    .unwrap();

    let encapsulated = client
        .encapsulate("POST", "/echo")
        .header("content-type", "text/plain")
        .param("x", "1")
        .body(b"hello".to_vec())
        .build()
        .unwrap();

    let outer_res = bitreq::post(encapsulated.url())
        .with_header("content-type", encapsulated.content_type())
        .with_body(encapsulated.body())
        .send()
        .unwrap();
    assert_eq!(
        outer_res.status_code,
        200,
        "relay says: {:?}",
        outer_res.as_str()
    );

    let response = encapsulated.decapsulate(outer_res.as_bytes()).unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.header("content-type"),
        Some(b"text/plain".to_vec())
    );
    assert_eq!(response.body(), b"POST /echo?x=1 hello");
}
