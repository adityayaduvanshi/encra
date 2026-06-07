# encra (CLI)

[![npm](https://img.shields.io/npm/v/encra?color=22c55e)](https://www.npmjs.com/package/encra)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)

**The developer CLI for [Encra](https://encra.dev)** — Signal-grade end-to-end encryption for any app. Scaffold a project, generate keys, and verify connectivity in seconds.

## Usage

No install needed — run it with `npx`:

```bash
npx encra init      # Detect your framework, write .env.example + a starter component
npx encra keygen    # Generate an X25519 key pair + safety-number fingerprint
npx encra ping      # Verify the server is reachable and your API key is valid
```

Or install globally:

```bash
npm install -g encra
encra init
```

## Commands

| Command | What it does |
|---|---|
| `encra init` | Detects Next.js / React / React Native / Node, then writes a `.env.example` and a ready-to-edit starter component wired to the right Encra package. |
| `encra keygen` | Generates a test X25519 key pair and prints its fingerprint — handy for experiments and debugging. |
| `encra ping` | Health-checks the Encra server and validates your API key. |

## Get an API key

Sign up free at [encra.dev](https://encra.dev) — no credit card required — then drop the key into your `.env`.

## Docs & license

Full docs at [encra.dev/docs](https://encra.dev/docs). Built on [`@encra/core`](https://www.npmjs.com/package/@encra/core). Licensed **Apache-2.0**.
