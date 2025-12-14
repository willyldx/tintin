import { createHmac } from "node:crypto";
import { RateLimiter, chunkText, nowMs, timingSafeEqualString } from "../util.js";
import type { Logger } from "../log.js";
import type { SlackSection } from "../config.js";
import { redactText } from "../redact.js";

export function verifySlackSignature(opts: {
  signingSecret: string;
  timestampHeader: string | null;
  signatureHeader: string | null;
  body: string;
}): boolean {
  const ts = opts.timestampHeader ? Number(opts.timestampHeader) : NaN;
  if (!Number.isFinite(ts)) return false;
  const ageSeconds = Math.abs(Math.floor(nowMs() / 1000) - ts);
  if (ageSeconds > 60 * 5) return false;

  if (!opts.signatureHeader) return false;
  const base = `v0:${opts.timestampHeader}:${opts.body}`;
  const digest = createHmac("sha256", opts.signingSecret).update(base).digest("hex");
  const expected = `v0=${digest}`;
  return timingSafeEqualString(expected, opts.signatureHeader);
}

export class SlackClient {
  private readonly limiter: RateLimiter;
  private readonly maxChars: number;

  constructor(
    private readonly config: SlackSection,
    private readonly logger: Logger,
  ) {
    this.limiter = new RateLimiter(config.rate_limit_msgs_per_sec);
    this.maxChars = config.max_chars;
  }

  async postMessage(opts: { channel: string; text: string; thread_ts?: string; blocks?: unknown[] }) {
    const redacted = redactText(opts.text);
    const chunks = chunkText(redacted, this.maxChars);
    let firstTs: string | null = null;
    for (let i = 0; i < chunks.length; i++) {
      await this.limiter.waitTurn();
      const res = await this.api<{ ok: boolean; ts?: string }>("chat.postMessage", {
        channel: opts.channel,
        text: chunks[i],
        thread_ts: opts.thread_ts,
        blocks: i === 0 ? opts.blocks : undefined,
        unfurl_links: false,
        unfurl_media: false,
      });
      if (i === 0 && res.ts) firstTs = res.ts;
    }
    return firstTs;
  }

  async updateMessage(opts: { channel: string; ts: string; text: string; blocks?: unknown[] }) {
    await this.limiter.waitTurn();
    await this.api("chat.update", {
      channel: opts.channel,
      ts: opts.ts,
      text: redactText(opts.text),
      blocks: opts.blocks,
    });
  }

  async postEphemeral(opts: { channel: string; user: string; text: string; thread_ts?: string; blocks?: unknown[] }) {
    const redacted = redactText(opts.text);
    const chunks = chunkText(redacted, this.maxChars);
    for (let i = 0; i < chunks.length; i++) {
      await this.limiter.waitTurn();
      await this.api("chat.postEphemeral", {
        channel: opts.channel,
        user: opts.user,
        text: chunks[i],
        thread_ts: opts.thread_ts,
        blocks: i === 0 ? opts.blocks : undefined,
      });
    }
  }

  async openModal(trigger_id: string, view: unknown) {
    await this.limiter.waitTurn();
    await this.api("views.open", { trigger_id, view });
  }

  private async api<T>(method: string, body: unknown): Promise<T> {
    const res = await fetch(`https://slack.com/api/${method}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.config.bot_token}`,
        "content-type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as { ok: boolean; error?: string } & T;
    if (!json.ok) {
      const error = json.error ?? "unknown_error";
      this.logger.error(`Slack API ${method} error: ${error}`);
      throw new Error(`Slack API ${method} error: ${error}`);
    }
    return json as T;
  }
}
