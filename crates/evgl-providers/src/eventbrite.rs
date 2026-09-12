use async_trait::async_trait;
use chrono::{Duration, Utc};
use evgl_domain::{
    DeliveryMode, EventDraft, ProviderCapabilities, ProviderKind, Publication,
    PublicationStatus,
};
use evgl_provider_sdk::{
    checked_json, OAuthClient, OAuthStart, ProviderAccount, ProviderAdapter,
    ProviderError, PublishContext, TokenSet,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use url::Url;

pub struct EventbriteAdapter {
    http: reqwest::Client,
    oauth: OAuthClient,
    api_base: Url,
}

impl EventbriteAdapter {
    pub fn new(oauth: OAuthClient) -> Result<Self, ProviderError> {
        Ok(Self {
            http: reqwest::Client::new(),
            oauth,
            api_base: Url::parse("https://www.eventbriteapi.com/v3/")?,
        })
    }

    pub fn with_api_base(mut self, api_base: Url) -> Self {
        self.api_base = api_base;
        self
    }
}

#[async_trait]
impl ProviderAdapter for EventbriteAdapter {
    fn kind(&self) -> ProviderKind { ProviderKind::Eventbrite }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            provider: self.kind(),
            delivery_mode: DeliveryMode::NativeEvent,
            oauth: true,
            create: true,
            update: false,
            delete: false,
            publish: true,
            webhooks: true,
            requires_manual_step: false,
            notes: vec![
                "Creation requires an Eventbrite organization.".into(),
                "A ticket class is created before publishing.".into(),
                "The v1 adapter publishes new events; remote update and delete are not implemented yet.".into(),
            ],
        }
    }

    fn authorization_url(
        &self,
        state: &str,
        _pkce_challenge: Option<&str>,
    ) -> Result<OAuthStart, ProviderError> {
        let mut url = Url::parse("https://www.eventbrite.com/oauth/authorize")?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.oauth.client_id)
            .append_pair("redirect_uri", self.oauth.redirect_uri.as_str())
            .append_pair("state", state);
        Ok(OAuthStart { authorization_url: url, state: state.into(), uses_pkce: false })
    }

    async fn exchange_code(
        &self,
        code: &str,
        _pkce_verifier: Option<&str>,
    ) -> Result<TokenSet, ProviderError> {
        let response = self.http.post("https://www.eventbrite.com/oauth/token")
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", self.oauth.client_id.as_str()),
                ("client_secret", self.oauth.client_secret.expose_secret()),
                ("code", code),
                ("redirect_uri", self.oauth.redirect_uri.as_str()),
            ])
            .send().await?;
        let body = checked_json(response).await?;
        let access = body.get("access_token").and_then(Value::as_str)
            .ok_or_else(|| ProviderError::InvalidResponse("missing access_token".into()))?;
        Ok(TokenSet {
            access_token: SecretString::from(access.to_owned()),
            refresh_token: body.get("refresh_token").and_then(Value::as_str)
                .map(|value| SecretString::from(value.to_owned())),
            expires_at: body.get("expires_in").and_then(Value::as_i64)
                .map(|seconds| Utc::now() + Duration::seconds(seconds)),
            scopes: vec![],
            provider_data: body,
        })
    }

    async fn resolve_accounts(
        &self,
        tokens: &TokenSet,
    ) -> Result<Vec<ProviderAccount>, ProviderError> {
        let url = self.api_base.join("users/me/organizations/")?;
        let body = checked_json(self.http.get(url)
            .bearer_auth(tokens.access_token.expose_secret())
            .send().await?).await?;
        let organizations = body.get("organizations").and_then(Value::as_array)
            .ok_or_else(|| ProviderError::InvalidResponse("missing organizations".into()))?;
        let accounts = organizations.iter().filter_map(|org| {
            let id = org.get("id")?.as_str()?.to_owned();
            Some(ProviderAccount {
                account_key: id,
                display_name: org.get("name").and_then(Value::as_str).unwrap_or("Eventbrite organization").to_owned(),
                token_override: Some(tokens.clone()),
                metadata: org.clone(),
            })
        }).collect::<Vec<_>>();
        if accounts.is_empty() {
            return Err(ProviderError::InvalidResponse(
                "the authorized user has no Eventbrite organizations".into(),
            ));
        }
        Ok(accounts)
    }

    async fn publish(
        &self,
        tokens: &TokenSet,
        event: &EventDraft,
        context: &PublishContext,
    ) -> Result<Publication, ProviderError> {
        event.validate().map_err(|error| ProviderError::Configuration(error.to_string()))?;
        let currency = context.target_options.get("currency").and_then(Value::as_str).unwrap_or("USD");
        let ticket_name = context.target_options.get("ticket_name").and_then(Value::as_str)
            .unwrap_or("General Admission");
        let quantity = context.target_options.get("quantity_total").and_then(Value::as_u64).unwrap_or(100);
        let free = context.target_options.get("free").and_then(Value::as_bool).unwrap_or(true);
        let organization_id = if context.account_key == "default" {
            context.target_options.get("organization_id").and_then(Value::as_str)
                .ok_or_else(|| ProviderError::Configuration("organization_id is required".into()))?
        } else {
            context.account_key.as_str()
        };

        let create_url = self.api_base.join(&format!("organizations/{organization_id}/events/"))?;
        let event_body = json!({
            "event": {
                "name": { "html": event.title },
                "summary": event.summary,
                "start": { "utc": event.starts_at.to_rfc3339(), "timezone": event.timezone },
                "end": { "utc": event.ends_at.to_rfc3339(), "timezone": event.timezone },
                "currency": currency,
                "online_event": event.online_url.is_some()
            }
        });
        let created = checked_json(self.http.post(create_url)
            .bearer_auth(tokens.access_token.expose_secret())
            .json(&event_body).send().await?).await?;
        let event_id = created.get("id").and_then(Value::as_str)
            .ok_or_else(|| ProviderError::InvalidResponse("created event has no id".into()))?
            .to_owned();

        let ticket_url = self.api_base.join(&format!("events/{event_id}/ticket_classes/"))?;
        let mut ticket = json!({
            "name": ticket_name,
            "quantity_total": quantity,
            "free": free
        });
        if !free {
            let amount = context.target_options.get("cost_minor").and_then(Value::as_u64)
                .ok_or_else(|| ProviderError::Configuration("paid tickets require cost_minor".into()))?;
            ticket["cost"] = Value::String(format!("{currency},{amount}"));
        }
        let ticket_receipt = checked_json(self.http.post(ticket_url)
            .bearer_auth(tokens.access_token.expose_secret())
            .json(&json!({ "ticket_class": ticket })).send().await?).await?;

        let publish_url = self.api_base.join(&format!("events/{event_id}/publish/"))?;
        let publish_receipt = checked_json(self.http.post(publish_url)
            .bearer_auth(tokens.access_token.expose_secret())
            .send().await?).await?;
        let external_url = created.get("url").and_then(Value::as_str)
            .and_then(|value| Url::parse(value).ok());

        Ok(Publication {
            provider: self.kind(),
            status: PublicationStatus::Published,
            external_id: Some(event_id),
            external_url,
            receipt: json!({
                "event": created,
                "ticket_class": ticket_receipt,
                "publish": publish_receipt
            }),
            action: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_oauth_client() -> OAuthClient {
        OAuthClient {
            client_id: "test-client".to_owned(),
            client_secret: SecretString::from("test-secret".to_owned()),
            redirect_uri: Url::parse("https://app.example.test/oauth/callback")
                .expect("valid redirect URL"),
        }
    }

    #[test]
    fn publish_endpoint_preserves_the_v3_api_prefix() {
        let adapter = EventbriteAdapter::new(test_oauth_client()).expect("valid adapter");
        let endpoint = adapter
            .api_base
            .join("events/123/publish/")
            .expect("valid publish endpoint");

        assert_eq!(
            endpoint.as_str(),
            "https://www.eventbriteapi.com/v3/events/123/publish/"
        );
    }
}
