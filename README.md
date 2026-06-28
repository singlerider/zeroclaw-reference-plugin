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

## Test and reproduce

There are two layers, and you can run both from a clean checkout.

### 1. Logic tests (host, no wasm toolchain needed)

The redaction core lives in `src/redact.rs` with no wit-bindgen dependency, so
it compiles and tests natively. `src/lib.rs` is the thin wit glue that the wasm
component build uses; it calls the exact same `redact` function the tests cover.

```bash
cargo test
```

Expected: 7 passing tests covering email masking, token-prefix masking,
high-entropy runs, configured replacement and patterns, the email-disable
toggle, the empty-config (unprivileged jail) fallback, and clean pass-through.

### 2. End-to-end through the real ZeroClaw host

This proves the built component loads and runs inside the wasmtime
component-model host, with config injected through the host's jailed config
path. The host-side test lives in the ZeroClaw repo and loads this component as
a committed fixture.

```bash
# build the component from this repo
cargo build --release --target wasm32-wasip2

# in a checkout of zeroclaw-labs/zeroclaw on the wasm-component-host branch,
# drop this build in as the test fixture, then run the e2e test
cp target/wasm32-wasip2/release/zeroclaw_reference_plugin.wasm \
   <zeroclaw>/crates/zeroclaw-plugins/tests/fixtures/reference-plugin.wasm

cd <zeroclaw>
cargo test -p zeroclaw-plugins \
  --no-default-features --features plugins-wasm-cranelift \
  --test reference_plugin_e2e
```

`reference_plugin_e2e` seeds a throwaway `ZEROCLAW_CONFIG_DIR` with the install
layout below, loads the real `Config`, discovers this plugin through the real
`PluginHost`, resolves this plugin's own config section through the real loader,
and executes `redact` live, asserting that an email, a configured pattern, and a
token are all masked with the config-driven replacement.

### Toolchain

The committed fixture in the ZeroClaw repo was built with:

```
rustc 1.95.0 (59807616e 2026-04-14)
wit-bindgen 0.46
cargo build --release --target wasm32-wasip2
```

A release build (`lto`, `strip`) is not guaranteed bit-for-bit reproducible
across toolchain versions, so verify by behavior (the e2e test above), not by
hash. If you want to refresh the fixture, rebuild here and copy it over as
shown; the host tests will confirm it still satisfies the contract.

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
├── Cargo.toml          cdylib (component) + rlib (native tests), wasm32-wasip2
├── manifest.toml       name, wasm_path, capabilities=[tool], permissions=[config_read]
├── src/
│   ├── lib.rs          wit glue: the tool-plugin world, wasm-only
│   └── redact.rs       pure redaction core, host-testable
├── tests/redact.rs     native integration tests for the core
└── wit/v0/             the four WIT files the tool-plugin world needs
```
