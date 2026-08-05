use evgl_contracts::EventEnvelope;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Priority { Low, Normal, High, Urgent }

pub fn classify(severity: &str) -> Priority {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" | "p0" | "sev0" | "sev1" => Priority::Urgent,
        "high" | "p1" | "sev2" => Priority::High,
        "medium" | "p2" | "warn" | "warning" => Priority::Normal,
        _ => Priority::Low,
    }
}

pub fn partition(event: &EventEnvelope, partitions: u64) -> Result<u64, &'static str> {
    if partitions == 0 { return Err("partitions must be non-zero"); }
    let hash = event.id.bytes().fold(1469598103934665603_u64, |acc, byte| (acc ^ u64::from(byte)).wrapping_mul(1099511628211));
    Ok(hash % partitions)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_severity() { assert_eq!(classify("sev1"), Priority::Urgent); }
}
