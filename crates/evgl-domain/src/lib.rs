use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, str::FromStr};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Eventbrite,
    Meetup,
    MetaFacebookPage,
    Craigslist,
    GenericWebhook,
}

impl ProviderKind {
    pub const ALL: [Self; 5] = [
        Self::Eventbrite,
        Self::Meetup,
        Self::MetaFacebookPage,
        Self::Craigslist,
        Self::GenericWebhook,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eventbrite => "eventbrite",
            Self::Meetup => "meetup",
            Self::MetaFacebookPage => "meta_facebook_page",
            Self::Craigslist => "craigslist",
            Self::GenericWebhook => "generic_webhook",
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderKind {
    type Err = DomainError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "eventbrite" => Ok(Self::Eventbrite),
            "meetup" => Ok(Self::Meetup),
            "meta" | "facebook" | "meta_facebook_page" => Ok(Self::MetaFacebookPage),
            "craigslist" => Ok(Self::Craigslist),
            "generic_webhook" | "webhook" => Ok(Self::GenericWebhook),
            other => Err(DomainError::UnknownProvider(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    NativeEvent,
    DistributionPost,
    SignedWebhook,
    ManualHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub provider: ProviderKind,
    pub delivery_mode: DeliveryMode,
    pub oauth: bool,
    pub create: bool,
    pub update: bool,
    pub delete: bool,
    pub publish: bool,
    pub webhooks: bool,
    pub requires_manual_step: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Venue {
    pub name: Option<String>,
    pub address_line_1: Option<String>,
    pub address_line_2: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventDraft {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub summary: String,
    pub description_html: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub timezone: String,
    pub canonical_url: Url,
    pub online_url: Option<Url>,
    pub venue: Option<Venue>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

impl EventDraft {
    pub fn validate(&self) -> Result<(), DomainError> {
        let title_len = self.title.trim().chars().count();
        if !(1..=200).contains(&title_len) {
            return Err(DomainError::InvalidEvent(
                "title must contain 1..=200 characters",
            ));
        }
        if self.summary.chars().count() > 280 {
            return Err(DomainError::InvalidEvent(
                "summary cannot exceed 280 characters",
            ));
        }
        if self.ends_at <= self.starts_at {
            return Err(DomainError::InvalidEvent("ends_at must be after starts_at"));
        }
        if self.timezone.trim().is_empty() {
            return Err(DomainError::InvalidEvent("timezone cannot be empty"));
        }
        Ok(())
    }

    pub fn duration_minutes(&self) -> i64 {
        (self.ends_at - self.starts_at).num_minutes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishTarget {
    pub provider: ProviderKind,
    pub connection_id: Uuid,
    #[serde(default)]
    pub options: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossPostRequest {
    pub event_id: Uuid,
    pub targets: Vec<PublishTarget>,
    pub idempotency_key: String,
}

impl CrossPostRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.targets.is_empty() {
            return Err(DomainError::InvalidCrossPost(
                "at least one target is required",
            ));
        }
        if self.idempotency_key.trim().is_empty() || self.idempotency_key.len() > 200 {
            return Err(DomainError::InvalidCrossPost(
                "idempotency_key must contain 1..=200 characters",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    Queued,
    Running,
    Published,
    ActionRequired,
    Retrying,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publication {
    pub provider: ProviderKind,
    pub status: PublicationStatus,
    pub external_id: Option<String>,
    pub external_url: Option<Url>,
    pub receipt: Value,
    pub action: Option<ManualAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualAction {
    pub heading: String,
    pub instructions: String,
    pub destination_url: Url,
    pub prepared_fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobUpdate {
    pub job_id: Uuid,
    pub event_id: Uuid,
    pub provider: Option<ProviderKind>,
    pub status: PublicationStatus,
    pub attempt: u32,
    pub message: String,
    pub occurred_at: DateTime<Utc>,
    pub publication: Option<Publication>,
}

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("unknown provider: {0}")]
    UnknownProvider(String),
    #[error("invalid event: {0}")]
    InvalidEvent(&'static str),
    #[error("invalid cross-post request: {0}")]
    InvalidCrossPost(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_parse_to_meta_page() {
        assert_eq!(
            "facebook".parse::<ProviderKind>().unwrap(),
            ProviderKind::MetaFacebookPage
        );
    }
    #[test]
    fn all_provider_names_are_stable() {
        let names: Vec<_> = ProviderKind::ALL
            .into_iter()
            .map(ProviderKind::as_str)
            .collect();
        assert_eq!(
            names,
            vec![
                "eventbrite",
                "meetup",
                "meta_facebook_page",
                "craigslist",
                "generic_webhook"
            ]
        );
    }
}
