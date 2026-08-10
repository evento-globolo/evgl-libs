use async_trait::async_trait;
use chrono::{Duration, Utc};
use evgl_domain::{
    DeliveryMode, EventDraft, ProviderCapabilities, ProviderKind, Publication, PublicationStatus,
};
use evgl_provider_sdk::{
    checked_json, OAuthClient, OAuthStart, ProviderAccount, ProviderAdapter, ProviderError,
    PublishContext, TokenSet,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use url::Url;

pub struct MetaFacebookPageAdapter {
    http: reqwest::Client,
    oauth: OAuthClient,
    graph_version: String,
}

impl MetaFacebookPageAdapter {
    pub fn new(oauth: OAuthClient, graph_version: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            oauth,
            graph_version: graph_version.into(),
        }
    }

    fn graph(&self, path: &str) -> Result<Url, ProviderError> {
        {
            let version = self.graph_version.trim_start_matches('v');
            Ok(Url::parse(&format!(
                "https://graph.facebook.com/v{version}/{path}"
            ))?)
        }
    }
}

#[async_trait]
impl ProviderAdapter for MetaFacebookPageAdapter {
    fn kind(&self) -> ProviderKind {
        ProviderKind::MetaFacebookPage
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            provider: self.kind(),
            delivery_mode: DeliveryMode::DistributionPost,
            oauth: true,
            create: true,
            update: false,
            delete: false,
            publish: true,
            webhooks: true,
            requires_manual_step: false,
            notes: vec![
                "Creates a Facebook Page post linking to the canonical event.".into(),
                "Does not claim to create a native Facebook Event object.".into(),
                "Requires approved Page permissions and a Page task that permits content creation."
                    .into(),
            ],
        }
    }

    fn authorization_url(
        &self,
        state: &str,
        _pkce_challenge: Option<&str>,
    ) -> Result<OAuthStart, ProviderError> {
        let mut url = Url::parse(&format!(
            "https://www.facebook.com/{}/dialog/oauth",
            self.graph_version
        ))?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.oauth.client_id)
            .append_pair("redirect_uri", self.oauth.redirect_uri.as_str())
            .append_pair("state", state)
            .append_pair("response_type", "code")
            .append_pair(
                "scope",
                "pages_show_list,pages_read_engagement,pages_manage_posts",
            );
        Ok(OAuthStart {
            authorization_url: url,
            state: state.into(),
            uses_pkce: false,
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        _pkce_verifier: Option<&str>,
    ) -> Result<TokenSet, ProviderError> {
        let url = self.graph("oauth/access_token")?;
        let body = checked_json(
            self.http
                .get(url)
                .query(&[
                    ("client_id", self.oauth.client_id.as_str()),
                    ("client_secret", self.oauth.client_secret.expose_secret()),
                    ("redirect_uri", self.oauth.redirect_uri.as_str()),
                    ("code", code),
                ])
                .send()
                .await?,
        )
        .await?;
        let access = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::InvalidResponse("missing access_token".into()))?;
        Ok(TokenSet {
            access_token: SecretString::from(access.to_owned()),
            refresh_token: None,
            expires_at: body
                .get("expires_in")
                .and_then(Value::as_i64)
                .map(|seconds| Utc::now() + Duration::seconds(seconds)),
            scopes: vec![
                "pages_show_list".into(),
                "pages_read_engagement".into(),
                "pages_manage_posts".into(),
            ],
            provider_data: body,
        })
    }

    async fn resolve_accounts(
        &self,
        tokens: &TokenSet,
    ) -> Result<Vec<ProviderAccount>, ProviderError> {
        let url = self.graph("me/accounts")?;
        let body = checked_json(
            self.http
                .get(url)
                .bearer_auth(tokens.access_token.expose_secret())
                .query(&[("fields", "id,name,access_token,tasks")])
                .send()
                .await?,
        )
        .await?;
        let pages = body
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| ProviderError::InvalidResponse("missing Page account data".into()))?;
        let accounts = pages
            .iter()
            .filter_map(|page| {
                let id = page.get("id")?.as_str()?.to_owned();
                let token = page.get("access_token")?.as_str()?.to_owned();
                Some(ProviderAccount {
                    account_key: id,
                    display_name: page
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("Facebook Page")
                        .to_owned(),
                    token_override: Some(TokenSet {
                        access_token: SecretString::from(token),
                        refresh_token: None,
                        expires_at: tokens.expires_at,
                        scopes: tokens.scopes.clone(),
                        provider_data: page.clone(),
                    }),
                    metadata: page.clone(),
                })
            })
            .collect::<Vec<_>>();
        if accounts.is_empty() {
            return Err(ProviderError::InvalidResponse(
                "the authorized user has no Page with a usable Page access token".into(),
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
        event
            .validate()
            .map_err(|error| ProviderError::Configuration(error.to_string()))?;
        let page_id = if context.account_key == "default" {
            context
                .target_options
                .get("page_id")
                .and_then(Value::as_str)
                .ok_or_else(|| ProviderError::Configuration("page_id is required".into()))?
        } else {
            context.account_key.as_str()
        };
        let url = self.graph(&format!("{page_id}/feed"))?;
        let message = context
            .target_options
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "{}\n\n{}\n\nStarts {}",
                    event.title, event.summary, event.starts_at
                )
            });
        let body = checked_json(
            self.http
                .post(url)
                .bearer_auth(tokens.access_token.expose_secret())
                .form(&[
                    ("message", message.as_str()),
                    ("link", event.canonical_url.as_str()),
                ])
                .send()
                .await?,
        )
        .await?;
        let id = body.get("id").and_then(Value::as_str).map(str::to_owned);
        Ok(Publication {
            provider: self.kind(),
            status: PublicationStatus::Published,
            external_id: id,
            external_url: None,
            receipt: json!({ "page_post": body, "canonical_url": event.canonical_url }),
            action: None,
        })
    }
}
