wit_bindgen::generate!({
    path: "wit/v0",
    world: "tool-plugin",
    features: ["plugins-wit-v0"],
});

use std::collections::HashMap;

use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

struct ReferencePlugin;

const PLUGIN_NAME: &str = "zeroclaw-reference-plugin";
const PLUGIN_VERSION: &str = "0.1.0";
const TOOL_NAME: &str = "redact";
const DEFAULT_REPLACEMENT: &str = "[REDACTED]";

#[derive(serde::Deserialize)]
struct ExecuteArgs {
    text: String,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

struct RedactConfig {
    replacement: String,
    redact_emails: bool,
    patterns: Vec<String>,
}

impl RedactConfig {
    fn from_section(section: &HashMap<String, String>) -> Self {
        let replacement = section
            .get("replacement")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_REPLACEMENT.to_string());
        let redact_emails = section
            .get("redact_emails")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        let patterns = section
            .get("patterns")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Self {
            replacement,
            redact_emails,
            patterns,
        }
    }
}

impl PluginInfo for ReferencePlugin {
    fn plugin_name() -> String {
        PLUGIN_NAME.to_string()
    }

    fn plugin_version() -> String {
        PLUGIN_VERSION.to_string()
    }
}

impl Tool for ReferencePlugin {
    fn name() -> String {
        TOOL_NAME.to_string()
    }

    fn description() -> String {
        "Redact secrets and PII from text before it reaches a log, channel, or model. \
         Masks emails, bearer/API tokens, and any operator-configured literal patterns. \
         Reference implementation of the wit/v0 tool-plugin world; the redaction policy is \
         read from this plugin's own jailed config section."
            .to_string()
    }

    fn parameters_schema() -> String {
        serde_json::json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to redact."
                }
            },
            "required": ["text"]
        })
        .to_string()
    }

    fn execute(args: String) -> Result<ToolResult, String> {
        let parsed: ExecuteArgs = match serde_json::from_str(&args) {
            Ok(a) => a,
            Err(e) => {
                emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments", None);
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("invalid arguments: {e}")),
                });
            }
        };

        let cfg = RedactConfig::from_section(&parsed.config);
        let (output, count) = redact(&parsed.text, &cfg);

        emit(
            PluginAction::Complete,
            PluginOutcome::Success,
            "redacted input",
            Some(count),
        );

        Ok(ToolResult {
            success: true,
            output,
            error: None,
        })
    }
}

/// Apply email masking, bearer/API-token masking, and configured literal
/// patterns. Returns the scrubbed text and the number of redactions made.
/// The matched secret values are never logged or returned in the count attrs.
fn redact(text: &str, cfg: &RedactConfig) -> (String, usize) {
    let mut out = text.to_string();
    let mut count = 0usize;

    if cfg.redact_emails {
        let (replaced, n) = mask_emails(&out, &cfg.replacement);
        out = replaced;
        count += n;
    }

    let (replaced, n) = mask_tokens(&out, &cfg.replacement);
    out = replaced;
    count += n;

    for pat in &cfg.patterns {
        let occurrences = out.matches(pat.as_str()).count();
        if occurrences > 0 {
            out = out.replace(pat.as_str(), &cfg.replacement);
            count += occurrences;
        }
    }

    (out, count)
}

/// Mask substrings that look like an email address. Hand-rolled so the plugin
/// stays dependency-light and the reference build is trivially reproducible.
fn mask_emails(text: &str, replacement: &str) -> (String, usize) {
    let mut result = String::with_capacity(text.len());
    let mut count = 0usize;
    for token in split_keep_delims(text) {
        if is_email(token) {
            result.push_str(replacement);
            count += 1;
        } else {
            result.push_str(token);
        }
    }
    (result, count)
}

/// Mask tokens that look like a high-entropy credential: an alphanumeric run of
/// length >= 20 containing at least one digit and one letter, or anything with
/// a recognized secret prefix.
fn mask_tokens(text: &str, replacement: &str) -> (String, usize) {
    let mut result = String::with_capacity(text.len());
    let mut count = 0usize;
    for token in split_keep_delims(text) {
        if is_secret_token(token) {
            result.push_str(replacement);
            count += 1;
        } else {
            result.push_str(token);
        }
    }
    (result, count)
}

fn is_email(token: &str) -> bool {
    let at = match token.find('@') {
        Some(i) => i,
        None => return false,
    };
    let (local, domain_with_at) = token.split_at(at);
    let domain = &domain_with_at[1..];
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && local.chars().all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
}

fn is_secret_token(token: &str) -> bool {
    const PREFIXES: [&str; 4] = ["sk-", "ghp_", "AKIA", "xoxb-"];
    if PREFIXES.iter().any(|p| token.starts_with(p)) && token.len() >= 8 {
        return true;
    }
    if token.len() >= 20 {
        let alnum = token.chars().all(|c| c.is_ascii_alphanumeric());
        let has_digit = token.chars().any(|c| c.is_ascii_digit());
        let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
        return alnum && has_digit && has_alpha;
    }
    false
}

/// Split into alternating word / delimiter chunks, preserving every character
/// so the rejoined output is byte-identical except at redacted spans.
fn split_keep_delims(text: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut in_word = false;
    for (i, c) in text.char_indices() {
        let is_word = c.is_ascii_alphanumeric() || "@._%+-".contains(c);
        if i == 0 {
            in_word = is_word;
            continue;
        }
        if is_word != in_word {
            chunks.push(&text[start..i]);
            start = i;
            in_word = is_word;
        }
    }
    if start < text.len() {
        chunks.push(&text[start..]);
    }
    chunks
}

fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, redactions: Option<usize>) {
    let attrs = redactions.map(|n| format!("{{\"redactions\":{n}}}"));
    log_record(
        LogLevel::Info,
        &PluginEvent {
            function_name: "zeroclaw_reference_plugin::tool::execute".to_string(),
            action,
            outcome: Some(outcome),
            duration_ms: None,
            attrs,
            message: message.to_string(),
        },
    );
}

export!(ReferencePlugin);
