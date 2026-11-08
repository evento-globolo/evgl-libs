use async_trait::async_trait;
use evgl_domain::{
    DeliveryMode, EventDraft, ProviderCapabilities, ProviderKind, Publication, PublicationStatus,
};
use evgl_provider_sdk::{OAuthStart, ProviderAdapter, ProviderError, PublishContext, TokenSet};
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use serde_json::{json, Value};
use sha2::Sha256;
use std::{net::{IpAddr, SocketAddr}, time::Duration};
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
        let body = response.text().await?;
        if !status.is_success() {
            return Err(ProviderError::Remote {
                status: status.as_u16(),
                body,
            });
        }
        let receipt = if body.trim().is_empty() {
            json!({ "status": status.as_u16() })
        } else {
            serde_json::from_str(&body).map_err(|error| {
                ProviderError::InvalidResponse(format!(
                    "successful webhook response was not JSON: {error}; body={body}",
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
        tokio::net::lookup_host((name, port))
            .await
            .map_err(|error| ProviderError::Configuration(format!(
                "webhook hostname DNS lookup failed: {error}"
            )))?
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
    validate_addresses(&addrs)?;

    // Proxies would bypass the connection pin and allow proxy-mediated SSRF.
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15));
    let builder = if let Some(name) = hostname.as_deref() {
        builder.resolve_to_addrs(name, &addrs)
    } else {
        builder
    };
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::validate_endpoint;
    use url::Url;

    #[test]
    fn rejects_local_webhook_targets() {
        for value in [
            "http://events.example.com",
            "https://localhost/hook",
            "https://127.0.0.1/hook",
            "https://10.0.0.1/hook",
            "https://[::1]/hook",
        ] {
            assert!(
                validate_endpoint(&Url::parse(value).unwrap()).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn accepts_public_https_targets() {
        assert!(
            validate_endpoint(&Url::parse("https://events.example.com/hooks/evgl").unwrap(),)
                .is_ok()
        );
    }
}
