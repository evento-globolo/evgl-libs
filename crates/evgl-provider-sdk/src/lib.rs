use async_trait::async_trait;
use chrono::{DateTime, Utc};
use evgl_domain::{EventDraft, ProviderCapabilities, ProviderKind, Publication};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

#[derive(Clone)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: SecretString,
    pub redirect_uri: Url,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthStart {
    pub authorization_url: Url,
    pub state: String,
    pub uses_pkce: bool,
}

#[derive(Clone)]
pub struct TokenSet {
    pub access_token: SecretString,
    pub refresh_token: Option<SecretString>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub provider_data: Value,
}

#[derive(Clone)]
pub struct ProviderAccount {
    pub account_key: String,
    pub display_name: String,
    pub token_override: Option<TokenSet>,
    pub metadata: Value,
}

#[derive(Debug, Clone)]
pub struct PublishContext {
    pub account_key: String,
    pub account_metadata: Value,
    pub target_options: Value,
}

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn kind(&self) -> ProviderKind;
    fn capabilities(&self) -> ProviderCapabilities;

    fn authorization_url(
        &self,
        state: &str,
        pkce_challenge: Option<&str>,
    ) -> Result<OAuthStart, ProviderError>;

    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<TokenSet, ProviderError>;

    async fn refresh(&self, tokens: &TokenSet) -> Result<TokenSet, ProviderError> {
        let _ = tokens;
        Err(ProviderError::Unsupported("refresh is not implemented"))
    }

    async fn resolve_accounts(
        &self,
        tokens: &TokenSet,
    ) -> Result<Vec<ProviderAccount>, ProviderError> {
        Ok(vec![ProviderAccount {
            account_key: "default".into(),
            display_name: self.kind().to_string(),
            token_override: Some(tokens.clone()),
            metadata: Value::Null,
        }])
    }

    async fn publish(
        &self,
        tokens: &TokenSet,
        event: &EventDraft,
        context: &PublishContext,
    ) -> Result<Publication, ProviderError>;
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("{0} does not support this operation")]
    Unsupported(&'static str),
    #[error("provider configuration is invalid: {0}")]
    Configuration(String),
    #[error("provider rejected the request ({status}): {body}")]
    Remote { status: u16, body: String },
    #[error("provider response was invalid: {0}")]
    InvalidResponse(String),
    #[error("network request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("URL construction failed: {0}")]
    Url(#[from] url::ParseError),
    #[error("serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub async fn checked_json(response: reqwest::Response) -> Result<Value, ProviderError> {
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return Err(ProviderError::Remote { status: status.as_u16(), body: text });
    }
    serde_json::from_str(&text).map_err(|error| {
        ProviderError::InvalidResponse(format!("{error}; body={text}"))
    })
}
