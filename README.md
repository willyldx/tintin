# Tintin

Tintin is your girlfriend and engineer. It allows you to control Codex and other coding agents (WIP) via Telegram or Slack. 

## Setup

- Make sure [npm](https://dev.to/ms314006/how-to-install-npm-through-nvm-node-version-manager-5gif) and [Codex](https://github.com/openai/codex?tab=readme-ov-file#quickstart) is available, and Codex has been logged in (either via API from environment or ChatGPT UI). 

- Run `npm i -g @fuzzland/tintin`. 

- Create `config.toml` by copying [example config]():
  - Set your projects. For example:
    ```
    [[projects]]
    id = "tintin"
    name = "tintin"
    path = "/home/ubuntu/tintin"
    ```
  - Set `[telegram]` and/or `[slack]` secrets (supports `env:VAR`).
  - Set `[db].url` (SQLite/Postgres/MySQL supported).
  - Optional: set `[security].*` allowlists.

- Run `tintin start`. 

### Telegram (this repo)

- `config.toml` in this repo is pre-wired to allow only chat `-3626196086` and the `tintin` project path `/home/c/tintin`.
- Set required env vars:
  - `TELEGRAM_TOKEN`
  - `TELEGRAM_WEBHOOK_SECRET`
- Set `telegram.public_base_url` in `config.toml` to your HTTPS base URL (or set the webhook manually). On startup the daemon will call `setWebhook` when `public_base_url` is non-empty.
- For polling (no webhook), set `telegram.mode = "poll"` and optionally tune `telegram.poll_timeout_seconds` (defaults to 30).
- For session continuation (messages in reply-threads/topics without @mentions), disable Telegram bot privacy mode via BotFather (`/setprivacy` → Disable).

## Migrations

```bash
bun run migrate --config config.toml
```

Or run the daemon with `BOT_AUTO_MIGRATE=1` to migrate on startup.

## Run

```bash
./tintin start --config config.toml
# or: bun run tintin -- start --config config.toml
# or: tintin start --config config.toml (after bun link / npm link)
```

- Health check: `GET /healthz`
- Stop: `tintin stop --config config.toml`
- Logs: `tintin log --config config.toml`
- Status: `tintin status --config config.toml`

## Chat flows

- Telegram: mention the bot or send `/codex` → choose project → optional custom path → prompt → session is created (topics preferred; reply-thread fallback).
- Slack: mention the bot → pick project (select) → modal for prompt (and custom path if needed) → session thread is created.
- List sessions:
  - Telegram: `/sessions` (or `/codex sessions`, or `@bot sessions`; add `page 2` for older sessions, `active` to filter)
  - Slack: mention the bot with “sessions” (e.g. `@bot sessions`; add `page 2` or `active`)
- Messages posted into a session while Codex is still running are queued and automatically resumed when the current run exits.

This project was created using `bun init` in bun v1.3.4.
