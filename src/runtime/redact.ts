const PRIVATE_KEY_BLOCK =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const SLACK_TOKEN = /xox[baprs]-[A-Za-z0-9-]{10,}/g;
const TELEGRAM_TOKEN = /\b\d{5,}:[A-Za-z0-9_-]{20,}\b/g;
const OPENAI_KEY = /\bsk-[A-Za-z0-9]{20,}\b/g;
const AWS_ACCESS_KEY = /\bAKIA[0-9A-Z]{16}\b/g;

export function redactText(input: string): string {
  return input
    .replaceAll(PRIVATE_KEY_BLOCK, "[REDACTED PRIVATE KEY]")
    .replaceAll(SLACK_TOKEN, "[REDACTED SLACK TOKEN]")
    .replaceAll(TELEGRAM_TOKEN, "[REDACTED TELEGRAM TOKEN]")
    .replaceAll(OPENAI_KEY, "[REDACTED OPENAI KEY]")
    .replaceAll(AWS_ACCESS_KEY, "[REDACTED AWS ACCESS KEY]");
}

