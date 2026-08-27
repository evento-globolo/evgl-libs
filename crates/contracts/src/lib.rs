//! Stable contracts for Evento Globolo.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Actor {
    pub id: String,
    pub tenant_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEnvelope {
    pub id: String,
    pub kind: String,
    pub occurred_at: String,
    pub actor: Option<Actor>,
}

impl EventEnvelope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.trim().is_empty() { return Err("event id is required"); }
        if !valid_kind(&self.kind) { return Err("event kind must be lowercase and namespaced"); }
        if self.occurred_at.trim().is_empty() { return Err("occurred_at is required"); }
        Ok(())
    }
}

pub fn valid_kind(value: &str) -> bool {
    fn allowed(ch: char) -> bool { ch == '.' || ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-' }
    matches!(value.chars().next(), Some(first) if first == '.' || first.is_ascii_lowercase())
        && value.chars().all(allowed)
        && value.contains('.')
}

pub const PRODUCT: &str = "evento-globolo";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_namespaced_kinds() {
        assert!(valid_kind("case.created"));
        assert!(!valid_kind("CaseCreated"));
        assert!(!valid_kind("created"));
        assert!(!valid_kind("1case.created"));
    }
}
