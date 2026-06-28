# zeroclaw-reference-plugin

The canonical reference ZeroClaw WASM plugin. It implements the `tool-plugin`
world from `wit/v0` and compiles to a `wasm32-wasip2` component. Copy it as the
starting point for a real tool plugin.

## What it does

A `redact` tool. It scrubs secrets and PII out of text before that text reaches
a log, a channel, or a model: email addresses, high-entropy credentials, known
token prefixes (`sk-`, `ghp_`, `AKIA`, `xoxb-`), and any literal patterns the
operator configures.

The redaction policy comes entirely from the plugin's own config section, which
makes this the reference for the three things every config-aware plugin must do:

1. **Own a config section.** The operator configures the plugin by name in
   `config.toml`; the host resolves that one section and hands the plugin a flat
   `string -> string` map.
2. **Deserialize that config.** `execute` reads the injected `__config` object
   out of its arguments and parses it into a typed `RedactConfig`.
3. **Stay jailed.** The host only injects the section when the manifest requests
   the `config_read` permission. Without it the plugin receives an empty map and
   falls back to defaults. A plugin can never read the global config or another
   plugin's section.

## Config keys

These live in the plugin's config section (see Install below), not in the
manifest.

| Key | Default | Meaning |
|---|---|---|
| `replacement` | `[REDACTED]` | String substituted for each match. |
| `redact_emails` | `true` | Mask email-shaped substrings. |
| `patterns` | (empty) | Comma-separated literal patterns to also mask. |

## Build

```bash
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

The component lands at `target/wasm32-wasip2/release/zeroclaw_reference_plugin.wasm`.

## Install

The host scans the plugins directory, which defaults to `~/.zeroclaw/plugins`
(it follows `ZEROCLAW_CONFIG_DIR` if set, and `[plugins].plugins_dir` overrides
it). Each plugin lives in its own subdirectory named after the plugin, holding
the manifest and the `.wasm` named to match the manifest's `wasm_path`:

```
~/.zeroclaw/plugins/
└── zeroclaw-reference-plugin/
    ├── manifest.toml
    └── reference-plugin.wasm
```

So, from a fresh build:

```bash
DEST=~/.zeroclaw/plugins/zeroclaw-reference-plugin
mkdir -p "$DEST"
cp manifest.toml "$DEST/"
cp target/wasm32-wasip2/release/zeroclaw_reference_plugin.wasm \
   "$DEST/reference-plugin.wasm"
```

Then enable the plugin system and give this plugin its config section in
`~/.zeroclaw/config.toml`. The entry's `name` must match the plugin's name, and
`config_read` in the manifest is what lets the host inject the `config` block:

```toml
[plugins]
enabled = true
auto_discover = true

[[plugins.entries]]
name = "zeroclaw-reference-plugin"

[plugins.entries.config]
replacement = "[REDACTED]"
redact_emails = "true"
patterns = "internal-codename, project-zeus"
```

With `auto_discover = true` the host loads it on startup and the `redact` tool
becomes available to the agent. Calling it with `{"text": "..."}` returns the
scrubbed text.

## Layout

```
.
├── Cargo.toml          cdylib targeting wasm32-wasip2
├── manifest.toml       name, wasm_path, capabilities=[tool], permissions=[config_read]
├── src/lib.rs          the tool-plugin world implementation
└── wit/v0/             the four WIT files the tool-plugin world needs
```
