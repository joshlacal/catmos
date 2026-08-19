use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

pub const DEFAULT_ATPROTO_PROXY_DID: &str = "did:web:chat.catbird.blue#atproto_chat";

pub fn atproto_proxy_header_value() -> String {
    std::env::var("ATPROTO_PROXY_HEADER")
        .or_else(|_| std::env::var("ATPROTO_PROXY_DID"))
        .unwrap_or_else(|_| DEFAULT_ATPROTO_PROXY_DID.to_string())
}

pub fn with_mls_proxy_header(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    request.header("atproto-proxy", atproto_proxy_header_value())
}

pub fn mls_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&atproto_proxy_header_value()) {
        headers.insert(HeaderName::from_static("atproto-proxy"), value);
    }
    headers
}
