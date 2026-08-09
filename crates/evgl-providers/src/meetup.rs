use async_trait::async_trait;
use chrono::{Duration, Utc};
use evgl_domain::{
    DeliveryMode, EventDraft, ProviderCapabilities, ProviderKind, Publication,
    PublicationStatus,
};
use evgl_provider_sdk::{
    checked_json, OAuthClient, OAuthStart, ProviderAdapter, ProviderError,
    PublishContext, TokenSet,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use url::Url;

pub struct MeetupAdapter {
    http: reqwest::Client,
    oauth: OAuthClient,
    graph_url: Url,
}

impl MeetupAdapter {
    pub fn new(oauth: OAuthClient) -> Result<Self, ProviderError> {
        Ok(Self {
            http: reqwest::Client::new(),
            oauth,
            graph_url: Url::parse("https://api.meetup.com/gql-ext")?,
        })
    }

    pub fn with_graph_url(mut self, graph_url: Url) -> Self {
        self.graph_url = graph_url;
        self
    }
}

#[async_trait]
impl ProviderAdapter for MeetupAdapter {
    fn kind(&self) -> ProviderKind { ProviderKind::Meetup }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            provider: self.kind(),
            delivery_mode: DeliveryMode::NativeEvent,
            oauth: true,
            create: true,
            update: false,
            delete: false,
            publish: true,
            webhooks: false,
            requires_manual_step: false,
            notes: vec![
                "OAuth consumer approval and applicable Meetup API access are required.".into(),
                "A target group URL name is required.".into(),
            ],
        }
    }

    fn authorization_url(
        &self,
        state: &str,
        pkce_challenge: Option<&str>,
    ) -> Result<OAuthStart, ProviderError> {
        let mut url = Url::parse("https://secure.meetup.com/oauth2/authorize")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("client_id", &self.oauth.client_id)
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", self.oauth.redirect_uri.as_str())
                .append_pair("state", state);
            if let Some(challenge) = pkce_challenge {
                query.append_pair("code_challenge", challenge)
                    .append_pair("code_challenge_method", "S256");
            }
        }
        Ok(OAuthStart {
            authorization_url: url,
            state: state.into(),
            uses_pkce: pkce_challenge.is_some(),
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<TokenSet, ProviderError> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("client_id", self.oauth.client_id.as_str()),
            ("client_secret", self.oauth.client_secret.expose_secret()),
            ("redirect_uri", self.oauth.redirect_uri.as_str()),
            ("code", code),
        ];
        if let Some(verifier) = pkce_verifier {
            form.push(("code_verifier", verifier));
        }
        let body = checked_json(self.http.post("https://secure.meetup.com/oauth2/access")
            .form(&form).send().await?).await?;
        let access = body.get("access_token").and_then(Value::as_str)
            .ok_or_else(|| ProviderError::InvalidResponse("missing access_token".into()))?;
        Ok(TokenSet {
            access_token: SecretString::from(access.to_owned()),
            refresh_token: body.get("refresh_token").and_then(Value::as_str)
                .map(|value| SecretString::from(value.to_owned())),
            expires_at: body.get("expires_in").and_then(Value::as_i64)
                .map(|seconds| Utc::now() + Duration::seconds(seconds)),
            scopes: body.get("scope").and_then(Value::as_str)
                .map(|scope| scope.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
            provider_data: body,
        })
    }

    async fn publish(
        &self,
        tokens: &TokenSet,
        event: &EventDraft,
        context: &PublishContext,
    ) -> Result<Publication, ProviderError> {
        event.validate().map_err(|error| ProviderError::Configuration(error.to_string()))?;
        let group = context.target_options.get("group_urlname").and_then(Value::as_str)
            .or_else(|| context.account_metadata.get("group_urlname").and_then(Value::as_str))
            .ok_or_else(|| ProviderError::Configuration("group_urlname is required".into()))?;
        let publish_status = context.target_options.get("publish_status").and_then(Value::as_str)
            .unwrap_or("PUBLISHED");
        let mutation = r#"
          mutation($input: CreateEventInput!) {
            createEvent(input: $input) {
              event { id eventUrl }
              errors { message code field }
            }
          }
        "#;
        let variables = json!({
            "input": {
                "groupUrlname": group,
                "title": event.title,
                "description": event.description_html,
                "startDateTime": event.starts_at.to_rfc3339(),
                "duration": event.duration_minutes() * 60_000,
                "publishStatus": publish_status,
                "venueId": context.target_options.get("venue_id").cloned()
            }
        });
        let body = checked_json(self.http.post(self.graph_url.clone())
            .bearer_auth(tokens.access_token.expose_secret())
            .json(&json!({ "query": mutation, "variables": variables }))
            .send().await?).await?;
        if let Some(errors) = body.pointer("/data/createEvent/errors").and_then(Value::as_array) {
            if !errors.is_empty() {
                return Err(ProviderError::Remote { status: 422, body: errors.to_string() });
            }
        }
        let created = body.pointer("/data/createEvent/event")
            .ok_or_else(|| ProviderError::InvalidResponse("missing createEvent.event".into()))?;
        let external_id = created.get("id").and_then(Value::as_str).map(str::to_owned);
        let external_url = created.get("eventUrl").and_then(Value::as_str)
            .and_then(|value| Url::parse(value).ok());
        Ok(Publication {
            provider: self.kind(),
            status: PublicationStatus::Published,
            external_id,
            external_url,
            receipt: body,
            action: None,
        })
    }
}
