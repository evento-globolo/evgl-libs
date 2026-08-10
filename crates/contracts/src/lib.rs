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
        if self.id.trim().is_empty() {
            return Err("event id is required");
        }
        if !valid_kind(&self.kind) {
            return Err("event kind must be lowercase and namespaced");
        }
        if self.occurred_at.trim().is_empty() {
            return Err("occurred_at is required");
        }
        Ok(())
    }
}

pub fn valid_kind(value: &str) -> bool {
    let mut saw_dot = false;
    if value.is_empty() {
        return false;
    }
    for (index, ch) in value.chars().enumerate() {
        if ch == '.' {
            saw_dot = true;
            continue;
        }
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-') {
            return false;
        }
        if index == 0 && !ch.is_ascii_lowercase() {
            return false;
        }
    }
    saw_dot
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
    }
}
