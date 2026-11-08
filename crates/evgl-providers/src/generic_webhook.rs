use async_trait::async_trait;
use evgl_domain::{
    DeliveryMode, EventDraft, ProviderCapabilities, ProviderKind, Publication, PublicationStatus,
};
use evgl_provider_sdk::{OAuthStart, ProviderAdapter, ProviderError, PublishContext, TokenSet};
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use serde_json::{json, Value};
use sha2::Sha256;
use std::{future::Future, net::{IpAddr, SocketAddr}, time::Duration};

const MAX_WEBHOOK_REQUEST_BYTES: usize = 512 * 1024;
const MAX_WEBHOOK_RESPONSE_BYTES: usize = 64 * 1024;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
use url::Url;

type HmacSha256 = Hmac<Sha256>;

#[derive(Default)]
pub struct GenericWebhookAdapter;

#[async_trait]
impl ProviderAdapter for GenericWebhookAdapter {
    fn kind(&self) -> ProviderKind {
        ProviderKind::GenericWebhook
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            provider: self.kind(),
            delivery_mode: DeliveryMode::SignedWebhook,
            oauth: false,
            create: true,
            update: false,
            delete: false,
            publish: true,
            webhooks: false,
            requires_manual_step: false,
            notes: vec![
                "The destination defines the downstream platform behavior.".into(),
                "The v1 adapter emits event.publish; update and delete messages are not implemented yet.".into(),
            ],
        }
    }

    fn authorization_url(
        &self,
        _state: &str,
        _pkce_challenge: Option<&str>,
    ) -> Result<OAuthStart, ProviderError> {
        Err(ProviderError::Unsupported(
            "generic webhooks use a configured URL and secret",
        ))
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _pkce_verifier: Option<&str>,
    ) -> Result<TokenSet, ProviderError> {
        Err(ProviderError::Unsupported(
            "generic webhooks use a configured URL and secret",
        ))
    }

    async fn publish(
        &self,
        tokens: &TokenSet,
        event: &EventDraft,
        context: &PublishContext,
    ) -> Result<Publication, ProviderError> {
        let endpoint = context
            .account_metadata
            .get("endpoint")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::Configuration("approved webhook endpoint is required".into())
            })?;
        let endpoint = Url::parse(endpoint)?;
        validate_endpoint(&endpoint)?;
        if tokens.access_token.expose_secret().len() < 32 {
            return Err(ProviderError::Configuration(
                "webhook signing secret must contain at least 32 characters".into(),
            ));
        }
        let payload = serde_json::to_vec(&json!({
            "type": "event.publish",
            "event": event,
            "options": context.target_options
        }))?;
        // Bound outbound work before signing or attempting DNS/network I/O.
        validate_payload_size(payload.len())?;
        let mut mac = HmacSha256::new_from_slice(tokens.access_token.expose_secret().as_bytes())
            .map_err(|_| ProviderError::Configuration("invalid webhook secret".into()))?;
        mac.update(&payload);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        // Resolve, validate, and pin the destination at each delivery.
        // Never reuse a connection pool after the DNS decision.
        let http = guarded_client_for_endpoint(&endpoint).await?;
        let response = http
            .post(endpoint)
            .header("content-type", "application/json")
            .header("x-evgl-signature", signature)
            .body(payload)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            // Do not propagate arbitrary remote HTML or secret-like text into
            // user-facing errors or logs. The status code is sufficient here.
            return Err(remote_status_error(status));
        }
        let mut response = response;
        let body = read_response_limited(&mut response).await?;
        let receipt = if body.trim().is_empty() {
            json!({ "status": status.as_u16() })
        } else {
            serde_json::from_str(&body).map_err(|error| {
                ProviderError::InvalidResponse(format!(
                    "successful webhook response was not JSON: {error}",
                ))
            })?
        };
        Ok(Publication {
            provider: self.kind(),
            status: PublicationStatus::Published,
            external_id: receipt.get("id").and_then(Value::as_str).map(str::to_owned),
            external_url: receipt
                .get("url")
                .and_then(Value::as_str)
                .and_then(|value| Url::parse(value).ok()),
            receipt,
            action: None,
        })
    }
}

fn validate_payload_size(size: usize) -> Result<(), ProviderError> {
    if size > MAX_WEBHOOK_REQUEST_BYTES {
        return Err(ProviderError::Configuration(
            "webhook request payload exceeds the configured size limit".into(),
        ));
    }
    Ok(())
}

fn remote_status_error(status: reqwest::StatusCode) -> ProviderError {
    ProviderError::Remote {
        status: status.as_u16(),
        body: "remote response body withheld".into(),
    };
}

fn append_bounded(buffer: &mut Vec<u8>, chunk: &[u8]) -> Result<(), ProviderError> {
    if chunk.len() > MAX_WEBHOOK_RESPONSE_BYTES.saturating_sub(buffer.len()) {
        return Err(ProviderError::InvalidResponse(
            "webhook response exceeded 64 KiB limit".into(),
        ));
    }
    buffer.extend_from_slice(chunk);
    Ok(())
}

async fn read_response_limited(response: &mut reqwest::Response) -> Result<String, ProviderError> {
    if response.content_length().is_some_and(|len| len > MAX_WEBHOOK_RESPONSE_BYTES as u64) {
        return Err(ProviderError::InvalidResponse(
            "webhook response Content-Length exceeds 64 KiB".into(),
        ));
    }
    // Check *actual decoded bytes* per chunk; a lying Content-Length header
    // must not bypass the cap or cause unbounded allocation.
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_bounded(&mut body, &chunk)?;
    }
    String::from_utf8(body).map_err(|_| {
        ProviderError::InvalidResponse("webhook response must be UTF-8".into())
    });
}

async fn lookup_before_deadline<F, T>(
    lookup: F,
    duration: Duration,
) -> Result<T, ProviderError>
where
    F: Future<Output = std::io::Result<T>>,
{
    tokio::time::timeout(duration, lookup)
        .await
        .map_err(|_| ProviderError::Configuration("webhook DNS lookup timed out".into()))?
        .map_err(|_| ProviderError::Configuration("webhook DNS lookup failed".into()));
}

fn validate_endpoint(endpoint: &Url) -> Result<(), ProviderError> {
    if endpoint.scheme() != "https" {
        return Err(ProviderError::Configuration(
            "webhook endpoint must use HTTPS".into(),
        ));
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(ProviderError::Configuration(
            "webhook endpoint cannot contain userinfo credentials".into(),
        ));
    }
    let host = endpoint.host().ok_or_else(|| {
        ProviderError::Configuration("webhook endpoint must include a host".into())
    })?;
    match host {
        url::Host::Domain(domain) => {
            let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
            if normalized.is_empty()
                || normalized == "localhost"
                || normalized.ends_with(".localhost")
                || normalized == "local"
                || normalized.ends_with(".local")
                || normalized == "internal"
                || normalized.ends_with(".internal")
            {
                return Err(ProviderError::Configuration(
                    "webhook endpoint cannot target a local hostname".into(),
                ));
            }
        }
        url::Host::Ipv4(ip) => {
            if !public_address(IpAddr::V4(ip)) {
                return Err(ProviderError::Configuration(
                    "webhook endpoint cannot target a non-public address".into(),
                ));
            }
        }
        url::Host::Ipv6(ip) => {
            if !public_address(IpAddr::V6(ip)) {
                return Err(ProviderError::Configuration(
                    "webhook endpoint cannot target a non-public address".into(),
                ));
            }
        }
    }
    Ok(())
}

fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    || o[0] == 0
                    || o[0] >= 240
                    || (o[0] == 100 && (64..=127).contains(&o[1]))
                    || (o[0] == 198 && (18..=19).contains(&o[1]))
                    || (o[0] == 192 && o[1] == 0 && o[2] == 0)
            )
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return public_address(IpAddr::V4(mapped));
            }
            // Permit global-unicast candidates only. Exclude documentation,
            // Teredo and 6to4 tunnels, which can encapsulate private IPv4.
            let s = v6.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] == 0 || s[1] == 0x0db8))
                && s[0] != 0x2002
        }
    }
}

fn validate_addresses(addrs: &[SocketAddr]) -> Result<(), ProviderError> {
    if addrs.is_empty() || addrs.len() > 32 || addrs.iter().any(|a| !public_address(a.ip())) {
        return Err(ProviderError::Configuration(
            "webhook DNS must resolve exclusively to public addresses".into(),
        ));
    }
    Ok(())
}

async fn guarded_client_for_endpoint(endpoint: &Url) -> Result<reqwest::Client, ProviderError> {
    validate_endpoint(endpoint)?;
    let port = endpoint.port_or_known_default().ok_or_else(|| {
        ProviderError::Configuration("webhook endpoint needs a valid TLS port".into())
    })?;

    // The hostname stays in the URL for TLS certificate verification/SNI,
    // but the actual socket destinations are pinned to this vetted answer.
    // A new client on every delivery avoids stale, unvalidated pooled sockets.
    let hostname = match endpoint.host().ok_or_else(|| {
        ProviderError::Configuration("webhook host is required".into())
    })? {
        url::Host::Domain(name) => Some(name.to_owned()),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => None,
    };
    let addrs: Vec<SocketAddr> = if let Some(name) = hostname.as_deref() {
        lookup_before_deadline(tokio::net::lookup_host((name, port)), DNS_TIMEOUT)
            .await?
            .take(33)
            .collect()
    } else {
        match endpoint.host() {
            Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
            Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
            _ => return Err(ProviderError::Configuration(
                "webhook IP endpoint is invalid".into(),
            )),
        }
    };
    client_for_resolved(hostname.as_deref(), &addrs)
}

fn client_for_resolved(
    hostname: Option<&str>,
    addrs: &[SocketAddr],
) -> Result<reqwest::Client, ProviderError> {
    validate_addresses(addrs)?;

    // Proxies would bypass the connection pin and allow proxy-mediated SSRF.
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15));
    let builder = if let Some(name) = hostname {
        builder.resolve_to_addrs(name, addrs)
    } else {
        builder
    };
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::{
        append_bounded, client_for_resolved, guarded_client_for_endpoint, lookup_before_deadline,
        public_address, read_response_limited, remote_status_error, validate_addresses,
        validate_endpoint, validate_payload_size, MAX_WEBHOOK_REQUEST_BYTES,
        MAX_WEBHOOK_RESPONSE_BYTES,
    };
    use std::{future::pending, io::{Read, Write}, net::{IpAddr, SocketAddr, TcpListener}, thread, time::Duration};
    use url::Url;

    #[test]
    fn rejects_local_webhook_targets() {
        for value in [
            "http://events.example.com/hook",
            "https://localhost/hook",
            "https://localhost./hook",
            "https://sub.localhost./hook",
            "https://service.internal./hook",
            "https://printer.local/hook",
            "https://admin:password@events.example.com/hook",
            "https://127.0.0.1/hook",
            "https://127.1/hook",
            "https://10.0.0.1/hook",
            "https://169.254.169.254/metadata",
            "https://100.64.0.1/hook",
            "https://198.18.0.1/hook",
            "https://224.0.0.1/hook",
            "https://240.0.0.1/hook",
            "https://[::1]/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://[fe80::1]/hook",
            "https://[2001:db8::1]/hook",
            "https://[2002:c0a8:0101::]/hook",
        ] {
            assert!(
                validate_endpoint(&Url::parse(value).unwrap()).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn accepts_public_https_targets() {
        for value in [
            "https://events.example.com/hooks/evgl",
            "https://events.example.com:8443/hooks/evgl",
            "https://8.8.8.8/hooks/evgl",
            "https://[2606:4700:4700::1111]/hooks/evgl",
        ] {
            assert!(
                validate_endpoint(&Url::parse(value).unwrap()).is_ok(),
                "{value}"
            );
        }
    }

    #[test]
    fn denies_rebinding_and_mixed_dns_answers() {
        let safe = "1.1.1.1:443".parse::<SocketAddr>().unwrap();
        let private = "10.0.0.42:443".parse::<SocketAddr>().unwrap();
        let metadata = "169.254.169.254:443".parse::<SocketAddr>().unwrap();
        assert!(validate_addresses(&[safe, private]).is_err());
        assert!(validate_addresses(&[safe, metadata]).is_err());
        assert!(validate_addresses(&[private]).is_err());
        // Preflight must not discard a private answer and keep the public one.
        assert!(client_for_resolved(Some("events.example.com"), &[safe, private]).is_err());
    }

    #[test]
    fn dns_must_have_one_to_thirty_two_public_answers() {
        let safe = "1.1.1.1:443".parse::<SocketAddr>().unwrap();
        assert!(validate_addresses(&[]).is_err());
        assert!(validate_addresses(&vec![safe; 33]).is_err());
        assert!(validate_addresses(&[safe]).is_ok());
        assert!(client_for_resolved(Some("events.example.com"), &[safe]).is_ok());
        assert!(client_for_resolved(None, &[safe]).is_ok());
    }

    #[test]
    fn rejects_private_ipv4_embedded_in_ipv6() {
        for literal in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "2001:db8::1",
            "2002:c0a8:101::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
        ] {
            let ip = literal.parse::<IpAddr>().unwrap();
            assert!(!public_address(ip), "{literal}");
        }
        assert!(public_address("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn denies_reserved_ipv4_routes_that_look_routable() {
        for literal in [
            "0.0.0.1",
            "100.64.1.1",
            "100.127.255.254",
            "198.18.0.1",
            "198.19.255.1",
            "192.0.0.8",
            "224.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public_address(literal.parse().unwrap()), "{literal}");
        }
        assert!(public_address("8.8.8.8".parse().unwrap()));
        assert!(public_address("1.1.1.1".parse().unwrap()));
    }
    #[test]
    fn bounds_response_chunks_without_allocating_beyond_limit() {
        let mut body = Vec::new();
        assert!(append_bounded(&mut body, &vec![b'a'; MAX_WEBHOOK_RESPONSE_BYTES - 1]).is_ok());
        assert!(append_bounded(&mut body, b"b").is_ok());
        assert_eq!(body.len(), MAX_WEBHOOK_RESPONSE_BYTES);
        let result = append_bounded(&mut body, b"must-not-be-appended");
        assert!(result.is_err());
        assert_eq!(body.len(), MAX_WEBHOOK_RESPONSE_BYTES);
        let err = result.err().unwrap().to_string();
        assert!(err.contains("64 KiB"));
        assert!(!err.contains("must-not-be-appended"));
        assert!(append_bounded(&mut Vec::new(), &[1_u8; 0]).is_ok());
        assert!(append_bounded(&mut Vec::new(), &vec![b'x'; MAX_WEBHOOK_RESPONSE_BYTES + 1]).is_err());
    }

    #[test]
    fn request_size_boundary_fails_closed() {
        assert!(validate_payload_size(0).is_ok());
        assert!(validate_payload_size(MAX_WEBHOOK_REQUEST_BYTES).is_ok());
        assert!(validate_payload_size(MAX_WEBHOOK_REQUEST_BYTES + 1).is_err());
        assert!(validate_payload_size(usize::MAX).is_err());
    }

    #[test]
    fn remote_failure_does_not_echo_untrusted_error_body() {
        let err = remote_status_error(reqwest::StatusCode::BAD_GATEWAY);
        let display = err.to_string();
        assert!(display.contains("502"));
        assert!(display.contains("withheld"));
        assert!(!display.contains("secret"));
    }

    #[test]
    fn dns_lookup_has_a_real_timeout_and_redacts_failures() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("Tokio runtime is available");
        runtime.block_on(async {
            let result = lookup_before_deadline(
                pending::<std::io::Result<()>>(),
                Duration::from_millis(1),
            )
            .await;
            assert!(result.is_err());
            assert!(result.err().unwrap().to_string().contains("timed out"));

            let ok = lookup_before_deadline(
                async { Ok::<_, std::io::Error>(42_u8) },
                Duration::from_secs(1),
            ).await;
            assert_eq!(ok.unwrap(), 42);

            let io_error = lookup_before_deadline(
                async { Err::<(), _>(std::io::Error::other("canary-secret")) },
                Duration::from_secs(1),
            ).await.err().unwrap().to_string();
            assert!(io_error.contains("DNS lookup failed"));
            assert!(!io_error.contains("canary-secret"));
        });
    }

    #[test]
    fn real_local_dns_is_rejected_without_attempting_https_connection() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime is available");
        runtime.block_on(async {
            // This exercises the operating system's actual localhost resolver,
            // not merely a fabricated array of IP addresses.
            let candidates = lookup_before_deadline(
                tokio::net::lookup_host(("localhost", 443)),
                Duration::from_secs(3),
            ).await.expect("localhost is resolvable on CI");
            let addrs: Vec<_> = candidates.collect();
            assert!(!addrs.is_empty());
            assert!(validate_addresses(&addrs).is_err());

            // The production guarded path also fails for the IP literal.
            let direct = guarded_client_for_endpoint(
                &Url::parse("https://127.0.0.1/internal").unwrap(),
            ).await;
            assert!(direct.is_err());
        });
    }

    // A real loopback HTTP socket exercises reqwest response framing and the
    // production receipt reader, without granting the production egress guard
    // permission to contact loopback.
    fn serve_one_local_response(wire: Vec<u8>) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut request = [0_u8; 512];
            let _ = socket.read(&mut request);
            // A client that fails closed may drop the connection while sending.
            // This is expected and must not make the test flaky.
            let _ = socket.write_all(&wire);
        });
        (addr, server)
    }

    #[test]
    fn live_loopback_chunked_body_overflow_is_rejected() {
        let mut wire = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n",
            MAX_WEBHOOK_RESPONSE_BYTES + 1
        ).into_bytes();
        wire.extend(vec![b'x'; MAX_WEBHOOK_RESPONSE_BYTES + 1]);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        let (addr, server) = serve_one_local_response(wire);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let mut response = client.get(format!("http://{addr}/")).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let result = read_response_limited(&mut response).await;
            assert!(result.is_err());
            assert!(result.err().unwrap().to_string().contains("64 KiB"));
        });
        server.join().unwrap();
    }

    #[test]
    fn live_loopback_receipts_respect_declared_and_actual_limits() {
        let payload = br#"{"id":"synthetic-receipt"}"#;
        let mut success = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        ).into_bytes();
        success.extend_from_slice(payload);
        let (addr, server) = serve_one_local_response(success);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let mut response = client.get(format!("http://{addr}/")).send().await.unwrap();
            let body = read_response_limited(&mut response).await.unwrap();
            assert_eq!(body, r#"{"id":"synthetic-receipt"}"#);
        });
        server.join().unwrap();

        let oversized_header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_WEBHOOK_RESPONSE_BYTES + 1
        ).into_bytes();
        let (addr, server) = serve_one_local_response(oversized_header);
        runtime.block_on(async {
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let mut response = client.get(format!("http://{addr}/")).send().await.unwrap();
            let result = read_response_limited(&mut response).await;
            assert!(result.is_err());
            assert!(result.err().unwrap().to_string().contains("Content-Length"));
        });
        server.join().unwrap();
    }

}
