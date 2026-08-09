use async_trait::async_trait;
use evgl_domain::{
    DeliveryMode, EventDraft, ProviderCapabilities, ProviderKind, Publication,
    PublicationStatus,
};
use evgl_provider_sdk::{
    OAuthStart, ProviderAdapter, ProviderError, PublishContext, TokenSet,
};
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use serde_json::{json, Value};
use sha2::Sha256;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

pub struct GenericWebhookAdapter {
    http: reqwest::Client,
}

impl Default for GenericWebhookAdapter {
    fn default() -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("static reqwest client configuration is valid");
        Self { http }
    }
}

#[async_trait]
impl ProviderAdapter for GenericWebhookAdapter {
    fn kind(&self) -> ProviderKind { ProviderKind::GenericWebhook }

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
        Err(ProviderError::Unsupported("generic webhooks use a configured URL and secret"))
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _pkce_verifier: Option<&str>,
    ) -> Result<TokenSet, ProviderError> {
        Err(ProviderError::Unsupported("generic webhooks use a configured URL and secret"))
    }

    async fn publish(
        &self,
        tokens: &TokenSet,
        event: &EventDraft,
        context: &PublishContext,
    ) -> Result<Publication, ProviderError> {
        let endpoint = context.account_metadata.get("endpoint").and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Configuration("approved webhook endpoint is required".into()))?;
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
        let response = self.http.post(endpoint)
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
            external_url: receipt.get("url").and_then(Value::as_str)
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
    let host = endpoint.host_str().ok_or_else(|| {
        ProviderError::Configuration("webhook endpoint must include a host".into())
    })?;
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err(ProviderError::Configuration(
            "webhook endpoint cannot target localhost".into(),
        ));
    }
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        let blocked = match address {
            std::net::IpAddr::V4(address) => {
                address.is_private()
                    || address.is_loopback()
                    || address.is_link_local()
                    || address.is_broadcast()
                    || address.is_documentation()
                    || address.is_unspecified()
            }
            std::net::IpAddr::V6(address) => {
                address.is_loopback()
                    || address.is_unspecified()
                    || address.is_unique_local()
                    || address.is_unicast_link_local()
            }
        };
        if blocked {
            return Err(ProviderError::Configuration(
                "webhook endpoint cannot target a private or local address".into(),
            ));
        }
    }
    Ok(())
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
            assert!(validate_endpoint(&Url::parse(value).unwrap()).is_err(), "{value}");
        }
    }

    #[test]
    fn accepts_public_https_targets() {
        assert!(validate_endpoint(
            &Url::parse("https://events.example.com/hooks/evgl").unwrap(),
        )
        .is_ok());
    }
}
