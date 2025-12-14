import { RateLimiter, chunkText } from "../util.js";
import type { Logger } from "../log.js";
import type { ProjectEntry, TelegramSection } from "../config.js";
import { redactText } from "../redact.js";

class TelegramApiError extends Error {
  constructor(
    readonly errorCode: number,
    readonly description: string,
  ) {
    super(`Telegram API error (${errorCode}): ${description}`);
  }
}

export interface TelegramUpdate {
  update_id: number;
  message?: TelegramMessage;
  edited_message?: TelegramMessage;
  channel_post?: TelegramMessage;
  edited_channel_post?: TelegramMessage;
  callback_query?: TelegramCallbackQuery;
}

export interface TelegramUser {
  id: number;
  username?: string;
  first_name?: string;
  last_name?: string;
}

export interface TelegramChat {
  id: number;
  type: "private" | "group" | "supergroup" | "channel";
  title?: string;
  is_forum?: boolean;
}

export interface TelegramMessageEntity {
  type: string;
  offset: number;
  length: number;
  custom_emoji_id?: string;
}

export interface TelegramMessage {
  message_id: number;
  date: number;
  chat: TelegramChat;
  from?: TelegramUser;
  sender_chat?: TelegramChat;
  text?: string;
  entities?: TelegramMessageEntity[];
  reply_to_message?: TelegramMessage;
  message_thread_id?: number;
  is_topic_message?: boolean;
}

export interface TelegramCallbackQuery {
  id: string;
  from: TelegramUser;
  message?: TelegramMessage;
  data?: string;
}

type TelegramApiResponse<T> = { ok: true; result: T } | { ok: false; error_code: number; description: string };

export class TelegramClient {
  private readonly token: string;
  private readonly baseUrl: string;
  private readonly limiter: RateLimiter;
  private readonly maxChars: number;
  private readonly defaultParseMode = "Markdown" as const;
  private username: string | null = null;

  constructor(
    private readonly config: TelegramSection,
    private readonly logger: Logger,
  ) {
    this.token = config.token;
    this.baseUrl = `https://api.telegram.org/bot${this.token}`;
    this.limiter = new RateLimiter(config.rate_limit_msgs_per_sec);
    this.maxChars = config.max_chars;
  }

  get botUsername(): string | null {
    return this.username;
  }

  async init(): Promise<void> {
    const me = await this.api<{ username?: string }>("getMe", {});
    this.username = me.username ?? null;

    if (this.config.public_base_url) {
      const url = `${this.config.public_base_url}${this.config.webhook_path}`;
      this.logger.info(`Telegram: setting webhook to ${url}`);
      try {
        await this.api("setWebhook", {
          url,
          secret_token: this.config.webhook_secret_token,
          allowed_updates: ["message", "edited_message", "channel_post", "edited_channel_post", "callback_query"],
        });
      } catch (e) {
        this.logger.warn(`Telegram: setWebhook failed (continuing without webhook)`, e);
      }
    }
  }

  async answerCallbackQuery(id: string, text?: string) {
    await this.api("answerCallbackQuery", text ? { callback_query_id: id, text } : { callback_query_id: id });
  }

  async sendMessage(opts: {
    chatId: number | string;
    text: string;
    messageThreadId?: number;
    replyToMessageId?: number;
    replyMarkup?: unknown;
  }) {
    const redacted = redactText(opts.text);
    const chunks = chunkText(redacted, this.maxChars);
    for (let i = 0; i < chunks.length; i++) {
      await this.limiter.waitTurn();
      await this.sendMessageWithFallback({
        chat_id: opts.chatId,
        text: chunks[i],
        message_thread_id: opts.messageThreadId,
        reply_to_message_id: opts.replyToMessageId,
        reply_markup: i === 0 ? opts.replyMarkup : undefined,
        disable_web_page_preview: true,
        parse_mode: this.defaultParseMode,
      });
    }
  }

  async sendMessageSingle(opts: {
    chatId: number | string;
    text: string;
    messageThreadId?: number;
    replyToMessageId?: number;
    replyMarkup?: unknown;
    entities?: TelegramMessageEntity[];
    parseMode?: "MarkdownV2" | "Markdown" | "HTML";
  }): Promise<TelegramMessage> {
    const redacted = redactText(opts.text);
    if (opts.entities && redacted !== opts.text) {
      throw new Error("sendMessageSingle cannot apply entities when redaction changes the text");
    }
    const parseMode = opts.parseMode ?? this.defaultParseMode;
    if (redacted.length > this.maxChars) throw new Error("sendMessageSingle text exceeds max_chars");
    await this.limiter.waitTurn();
    return this.sendMessageWithFallback({
      chat_id: opts.chatId,
      text: redacted,
      message_thread_id: opts.messageThreadId,
      reply_to_message_id: opts.replyToMessageId,
      reply_markup: opts.replyMarkup,
      entities: opts.entities,
      parse_mode: parseMode,
      disable_web_page_preview: true,
    });
  }

  async sendMessageStrict(opts: {
    chatId: number | string;
    text: string;
    messageThreadId?: number;
    replyToMessageId?: number;
    replyMarkup?: unknown;
    entities?: TelegramMessageEntity[];
  }) {
    const redacted = redactText(opts.text);
    const chunks = chunkText(redacted, this.maxChars);
    if (opts.entities) throw new Error("sendMessageStrict does not support entities (use sendMessageSingleStrict)");
    for (let i = 0; i < chunks.length; i++) {
      await this.limiter.waitTurn();
      await this.api("sendMessage", {
        chat_id: opts.chatId,
        text: chunks[i],
        message_thread_id: opts.messageThreadId,
        reply_to_message_id: opts.replyToMessageId,
        reply_markup: i === 0 ? opts.replyMarkup : undefined,
        disable_web_page_preview: true,
        parse_mode: this.defaultParseMode,
      });
    }
  }

  async sendMessageSingleStrict(opts: {
    chatId: number | string;
    text: string;
    messageThreadId?: number;
    replyToMessageId?: number;
    replyMarkup?: unknown;
    entities?: TelegramMessageEntity[];
    parseMode?: "MarkdownV2" | "Markdown" | "HTML";
  }): Promise<TelegramMessage> {
    const redacted = redactText(opts.text);
    if (opts.entities && redacted !== opts.text) {
      throw new Error("sendMessageSingleStrict cannot apply entities when redaction changes the text");
    }
    const parseMode = opts.parseMode ?? this.defaultParseMode;
    if (redacted.length > this.maxChars) throw new Error("sendMessageSingleStrict text exceeds max_chars");
    await this.limiter.waitTurn();
    return this.api("sendMessage", {
      chat_id: opts.chatId,
      text: redacted,
      message_thread_id: opts.messageThreadId,
      reply_to_message_id: opts.replyToMessageId,
      reply_markup: opts.replyMarkup,
      entities: opts.entities,
      parse_mode: parseMode,
      disable_web_page_preview: true,
    });
  }

  async createForumTopic(chatId: number | string, name: string, iconCustomEmojiId?: string): Promise<number> {
    const res = await this.api<{ message_thread_id: number }>("createForumTopic", {
      chat_id: chatId,
      name,
      icon_custom_emoji_id: iconCustomEmojiId,
    });
    return res.message_thread_id;
  }

  async getForumTopicIconStickers(): Promise<Array<{ emoji?: string; custom_emoji_id?: string }>> {
    return this.api("getForumTopicIconStickers", {});
  }

  async editForumTopic(chatId: number | string, messageThreadId: number, name: string): Promise<void> {
    await this.api("editForumTopic", { chat_id: chatId, message_thread_id: messageThreadId, name });
  }

  async pinChatMessage(chatId: number | string, messageId: number, disableNotification = true): Promise<void> {
    await this.limiter.waitTurn();
    await this.api("pinChatMessage", {
      chat_id: chatId,
      message_id: messageId,
      disable_notification: disableNotification,
    });
  }

  async getChatMember(chatId: number | string, userId: number | string): Promise<{ status: string }> {
    return this.api("getChatMember", { chat_id: chatId, user_id: userId });
  }

  projectKeyboard(projects: ProjectEntry[]) {
    return {
      inline_keyboard: projects.map((p) => [{ text: p.name, callback_data: `proj:${p.id}` }]),
    };
  }

  isMentionOrCommand(message: TelegramMessage): boolean {
    const text = message.text ?? "";
    if (text.startsWith("/codex")) return true;
    const username = this.username;
    if (!username) return false;
    if (text.includes(`@${username}`)) return true;
    return false;
  }

  private async api<T>(method: string, payload: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}/${method}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const json = (await res.json()) as TelegramApiResponse<T>;
    if (!json.ok) {
      throw new TelegramApiError(json.error_code, json.description);
    }
    return json.result;
  }

  private async sendMessageWithFallback(payload: Record<string, unknown>): Promise<TelegramMessage> {
    const attempts = buildSendMessageAttempts(payload);
    let lastErr: unknown = null;

    for (const [idx, attempt] of attempts.entries()) {
      try {
        return await this.api("sendMessage", attempt);
      } catch (e) {
        lastErr = e;
        if (e instanceof TelegramApiError) {
          const chatId = attempt.chat_id;
          const threadId = attempt.message_thread_id;
          const replyId = attempt.reply_to_message_id;
          this.logger.debug(
            `Telegram sendMessage attempt ${idx + 1}/${attempts.length} failed chat=${String(chatId)} thread=${String(
              threadId ?? "-",
            )} reply=${String(replyId ?? "-")}: ${e.description}`,
          );
        } else {
          this.logger.debug(`Telegram sendMessage attempt ${idx + 1}/${attempts.length} failed: ${String(e)}`);
        }
      }
    }

    throw lastErr;
  }
}

function buildSendMessageAttempts(payload: Record<string, unknown>): Record<string, unknown>[] {
  const hasThread = payload.message_thread_id !== undefined && payload.message_thread_id !== null;
  const hasReply = payload.reply_to_message_id !== undefined && payload.reply_to_message_id !== null;

  const base: Record<string, unknown>[] = [payload];

  if (hasReply) base.push({ ...payload, reply_to_message_id: undefined });
  if (hasThread) base.push({ ...payload, message_thread_id: undefined });
  if (hasThread || hasReply) base.push({ ...payload, message_thread_id: undefined, reply_to_message_id: undefined });

  // For Markdown/HTML parsing failures, retry without parse_mode and/or entities.
  const attempts: Record<string, unknown>[] = [];
  for (const a of base) {
    attempts.push(a);
    if (a.parse_mode !== undefined) attempts.push({ ...a, parse_mode: undefined });
    if (a.entities !== undefined) attempts.push({ ...a, entities: undefined });
    if (a.parse_mode !== undefined && a.entities !== undefined) attempts.push({ ...a, parse_mode: undefined, entities: undefined });
  }

  const seen = new Set<string>();
  const out: Record<string, unknown>[] = [];
  for (const a of attempts) {
    const key = `${String(a.chat_id)}|${String(a.message_thread_id ?? "-")}|${String(a.reply_to_message_id ?? "-")}|${String(
      a.parse_mode ?? "-",
    )}|${a.entities !== undefined ? "ent" : "-"}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out;
}
