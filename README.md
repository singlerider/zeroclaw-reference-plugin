# zeroclaw-reference-plugin

The canonical reference ZeroClaw WASM plugin. It implements the `tool-plugin`
world from `wit/v0` and builds to a `wasm32-wasip2` component. Copy this as the
starting point for a real tool plugin.

## What it does

A `redact` tool: it scrubs secrets and PII from text before that text reaches a
log, a channel, or a model. It masks email addresses, high-entropy credentials
and known token prefixes (`sk-`, `ghp_`, `AKIA`, `xoxb-`), and any literal
patterns the operator configures.

The redaction policy is read entirely from this plugin's own jailed config
section, demonstrating the three things every config-aware plugin needs:

1. **Its own config section.** The operator configures the plugin under its name.
   The host resolves that section and hands the plugin a flat `string -> string`
   map.
2. **Serde of that config.** `execute` deserializes the injected `__config` key
   into a typed `RedactConfig`.
3. **Config jail.** A plugin only receives its section when its manifest grants
   the `config_read` permission. Without the grant the host withholds the
   section entirely, the plugin sees an empty map, and it falls back to defaults.
   A plugin can never read the global config or another plugin's section.

## Config

| Key | Default | Meaning |
|---|---|---|
| `replacement` | `[REDACTED]` | Mask string substituted for each match. |
| `redact_emails` | `true` | Mask email-shaped substrings. |
| `patterns` | (empty) | Comma-separated literal patterns to also mask. |

## Build

```bash
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

The component lands at
`target/wasm32-wasip2/release/zeroclaw_reference_plugin.wasm`. Ship it alongside
`manifest.toml`.

## Install

Place the built `.wasm` (renamed to match `wasm_path` in the manifest) and
`manifest.toml` together in the plugins directory. The manifest declares the
`tool` capability and requests the `config_read` permission so the host injects
the config section.
