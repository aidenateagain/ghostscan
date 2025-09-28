use crate::ScanOutcome;
use std::fs;

pub fn run() -> ScanOutcome {
    let enabled = match fs::read_to_string("/proc/sys/kernel/audit_enabled") {
        Ok(value) => value.trim().to_string(),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(format!("failed to read audit_enabled: {err}"));
        }
    };

    let mut findings = Vec::new();
    if enabled == "0" {
        findings.push("enabled=0".to_string());
    }

    if let Ok(content) = fs::read_to_string("/proc/net/audit") {
        for line in content.lines() {
            for token in line.split_whitespace() {
                if let Some(rest) = token.strip_prefix("lost=") {
                    if rest != "0" {
                        findings.push(format!("lost_events={}", rest));
                    }
                }
                if let Some(rest) = token.strip_prefix("backlog=") {
                    if let Ok(value) = rest.parse::<u64>() {
                        if value < 8 {
                            findings.push("backlog_limit_tiny=true".to_string());
                        }
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        Ok(Some(findings.join(", ")))
    }
}
