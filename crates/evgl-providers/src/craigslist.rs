use async_trait::async_trait;
use evgl_domain::{
    DeliveryMode, EventDraft, ManualAction, ProviderCapabilities, ProviderKind, Publication,
    PublicationStatus,
};
use evgl_provider_sdk::{OAuthStart, ProviderAdapter, ProviderError, PublishContext, TokenSet};
use std::collections::BTreeMap;
use url::Url;

#[derive(Default)]
pub struct CraigslistAdapter;

#[async_trait]
impl ProviderAdapter for CraigslistAdapter {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Craigslist
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            provider: self.kind(),
            delivery_mode: DeliveryMode::ManualHandoff,
            oauth: false,
            create: false,
            update: false,
            delete: false,
            publish: false,
            webhooks: false,
            requires_manual_step: true,
            notes: vec![
                "General automated posting is disabled by policy.".into(),
                "Evento Globolo prepares copy and opens the official posting flow for the user."
                    .into(),
            ],
        }
    }

    fn authorization_url(
        &self,
        _state: &str,
        _pkce_challenge: Option<&str>,
    ) -> Result<OAuthStart, ProviderError> {
        Err(ProviderError::Unsupported(
            "Craigslist has no general OAuth event-posting flow",
        ))
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _pkce_verifier: Option<&str>,
    ) -> Result<TokenSet, ProviderError> {
        Err(ProviderError::Unsupported(
            "Craigslist has no general OAuth event-posting flow",
        ))
    }

    async fn publish(
        &self,
        _tokens: &TokenSet,
        event: &EventDraft,
        context: &PublishContext,
    ) -> Result<Publication, ProviderError> {
        let destination = context
            .target_options
            .get("posting_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("https://www.craigslist.org/about/sites");
        let mut fields = BTreeMap::new();
        fields.insert("title".into(), event.title.clone());
        fields.insert(
            "body".into(),
            format!(
                "{}\n\n{}\n\nDetails and updates: {}",
                event.summary, event.description_html, event.canonical_url
            ),
        );
        fields.insert("start".into(), event.starts_at.to_rfc3339());
        fields.insert("end".into(), event.ends_at.to_rfc3339());
        Ok(Publication {
            provider: self.kind(),
            status: PublicationStatus::ActionRequired,
            external_id: None,
            external_url: None,
            receipt: serde_json::json!({ "automation_performed": false }),
            action: Some(ManualAction {
                heading: "Complete the Craigslist post".into(),
                instructions: "Review the prepared fields, choose the correct local site and category, and submit the post yourself.".into(),
                destination_url: Url::parse(destination)?,
                prepared_fields: fields,
            }),
        })
    }
}
