import type { AppConfig } from "./config.js";
import type { Db } from "./db.js";
import type { Logger } from "./log.js";
import { sleep, TaskQueue } from "./util.js";
import { TelegramClient } from "./platform/telegram.js";
import { SlackClient, verifySlackSignature } from "./platform/slack.js";
import { BotController } from "./controller2.js";
import { JsonlStreamer } from "./streamer.js";
import { SessionManager } from "./sessionManager.js";
import type { SendToSessionFn } from "./messaging.js";
import type { TelegramMessage } from "./platform/telegram.js";

export interface BotServiceDeps {
  config: AppConfig;
  db: Db;
  logger: Logger;
}

export async function createBotService(deps: BotServiceDeps) {
  const { config, db, logger } = deps;

  const queue = new TaskQueue(16);
  const firstMessageSent = new Set<string>();
  const firstMessageSending = new Set<string>();
  const lastTelegramMessageId = new Map<string, number>();
  const lastSlackMessage = new Map<string, { ts: string; text: string }>();

  const telegram = config.telegram ? new TelegramClient(config.telegram, logger) : null;
  const slack = config.slack ? new SlackClient(config.slack, logger) : null;

  if (telegram) await telegram.init();

  const isFencedCodeBlock = (text: string): boolean => {
    const t = text.trim();
    return t.startsWith("```") && t.endsWith("```");
  };

  const buildTelegramInlineKeyboard = (opts: { sessionId: string; includeKill: boolean; includeReview: boolean }) => {
    const row: Array<{ text: string; callback_data: string }> = [];
    if (opts.includeKill) row.push({ text: "Stop", callback_data: `kill:${opts.sessionId}` });
    if (opts.includeReview) row.push({ text: "Review", callback_data: `review:${opts.sessionId}` });
    return row.length > 0 ? { inline_keyboard: [row] } : undefined;
  };

  const buildSlackButtons = (opts: { sessionId: string; includeKill: boolean; includeReview: boolean }) => {
    const elements: any[] = [];
    if (opts.includeKill) {
      elements.push({
        type: "button",
        text: { type: "plain_text", text: "Stop" },
        style: "danger",
        action_id: "kill_session",
        value: opts.sessionId,
      });
    }
    if (opts.includeReview) {
      elements.push({
        type: "button",
        text: { type: "plain_text", text: "Review" },
        action_id: "review_session",
        value: opts.sessionId,
      });
    }
    return elements.length > 0 ? [{ type: "actions", elements }] : undefined;
  };

  const attachReviewButtonToLastMessage = async (sessionId: string, session: { platform: string; chat_id: string }) => {
    if (session.platform === "telegram") {
      if (!telegram) return false;
      const chatId = Number(session.chat_id);
      const messageId = lastTelegramMessageId.get(sessionId);
      if (!messageId || Number.isNaN(chatId)) return false;
      try {
        await telegram.editMessageReplyMarkup({
          chatId,
          messageId,
          replyMarkup: buildTelegramInlineKeyboard({ sessionId, includeKill: false, includeReview: true }),
          priority: "user",
        });
        return true;
      } catch {
        return false;
      }
    }

    if (session.platform === "slack") {
      if (!slack) return false;
      const channel = session.chat_id;
      const last = lastSlackMessage.get(sessionId);
      if (!last) return false;
      try {
        await slack.updateMessage({
          channel,
          ts: last.ts,
          text: last.text,
          blocks: buildSlackButtons({ sessionId, includeKill: false, includeReview: true }),
        });
        return true;
      } catch {
        return false;
      }
    }

    return false;
  };

  const sendToSession: SendToSessionFn = async (sessionId, message) => {
    const session = await db.selectFrom("sessions").selectAll().where("id", "=", sessionId).executeTakeFirst();
    if (!session) return;
    const text = message.text;
    const isFinal = message.final === true;
    const isFirst = !firstMessageSent.has(sessionId) && !firstMessageSending.has(sessionId);
    const claimedFirst = isFirst;
    if (claimedFirst) firstMessageSending.add(sessionId);
    const includeKillButton =
      isFirst &&
      !isFinal &&
      (session.status === "starting" || session.status === "running") &&
      !(session.platform === "telegram" && config.telegram?.use_topics);
    const includeReviewButton = false;

    let messageSent = false;
    try {
      if (isFinal && text.trim().length === 0) {
        const updated = await attachReviewButtonToLastMessage(sessionId, session);
        if (updated) return;

        const fallbackText = "Session complete.";
        if (session.platform === "telegram") {
          if (!telegram) return;
          const chatId = Number(session.chat_id);
          const space = Number(session.space_id);
          if (Number.isNaN(chatId) || Number.isNaN(space)) return;
          const replyMarkup = buildTelegramInlineKeyboard({ sessionId, includeKill: false, includeReview: true });
          const priority = "user" as const;
          try {
            if (config.telegram?.use_topics) {
              try {
                const sent = await telegram.sendMessageSingleStrict({ chatId, messageThreadId: space, text: fallbackText, replyMarkup, priority });
                lastTelegramMessageId.set(sessionId, sent.message_id);
              } catch {
                const sent = await telegram.sendMessageSingleStrict({ chatId, replyToMessageId: space, text: fallbackText, replyMarkup, priority });
                lastTelegramMessageId.set(sessionId, sent.message_id);
              }
            } else {
              const sent = await telegram.sendMessageSingleStrict({ chatId, replyToMessageId: space, text: fallbackText, replyMarkup, priority });
              lastTelegramMessageId.set(sessionId, sent.message_id);
            }
            messageSent = true;
          } catch {
            // Ignore fallback failures.
          }
        } else if (session.platform === "slack") {
          if (!slack) return;
          const channel = session.chat_id;
          const threadTs = config.slack?.session_mode === "thread" ? session.space_id : undefined;
          try {
            const posted = await slack.postMessageDetailed({
              channel,
              thread_ts: threadTs,
              text: fallbackText,
              blocks: buildSlackButtons({ sessionId, includeKill: false, includeReview: true }),
              blocksOnLastChunk: false,
            });
            if (posted.lastTs && posted.lastText !== null) {
              lastSlackMessage.set(sessionId, { ts: posted.lastTs, text: posted.lastText });
            }
            messageSent = true;
          } catch {
            // Ignore fallback failures.
          }
        }
        return;
      }

      if (session.platform === "telegram") {
        if (!telegram) return;
        const chatId = Number(session.chat_id);
        const space = Number(session.space_id);
        if (Number.isNaN(chatId) || Number.isNaN(space)) return;
        const priority = message.priority ?? "background";
        const replyMarkup = buildTelegramInlineKeyboard({
          sessionId,
          includeKill: includeKillButton,
          includeReview: includeReviewButton,
        });

        if (isFencedCodeBlock(text)) {
          const parseMode = "Markdown" as const;
          let sent: TelegramMessage | null = null;
          if (config.telegram?.use_topics) {
            try {
              sent = await telegram.sendMessageSingleStrict({ chatId, messageThreadId: space, text, parseMode, replyMarkup, priority });
            } catch {
              try {
                sent = await telegram.sendMessageSingleStrict({ chatId, replyToMessageId: space, text, parseMode, replyMarkup, priority });
              } catch {
                sent = await telegram.sendMessageSingleStrict({ chatId, text, parseMode, replyMarkup, priority });
              }
            }
          } else {
            try {
              sent = await telegram.sendMessageSingleStrict({ chatId, replyToMessageId: space, text, parseMode, replyMarkup, priority });
            } catch {
              sent = await telegram.sendMessageSingleStrict({ chatId, text, parseMode, replyMarkup, priority });
            }
          }
          if (sent) lastTelegramMessageId.set(sessionId, sent.message_id);
          messageSent = true;
          if (isFinal) await attachReviewButtonToLastMessage(sessionId, session);
          return;
        }

        let sent: TelegramMessage | null = null;
        if (config.telegram?.use_topics) {
          try {
            sent = await telegram.sendMessageStrict({ chatId, messageThreadId: space, text, replyMarkup, priority });
          } catch {
            try {
              sent = await telegram.sendMessageStrict({ chatId, replyToMessageId: space, text, replyMarkup, priority });
            } catch {
              sent = await telegram.sendMessage({ chatId, text, replyMarkup, priority });
            }
          }
        } else {
          try {
            sent = await telegram.sendMessageStrict({ chatId, replyToMessageId: space, text, replyMarkup, priority });
          } catch {
            sent = await telegram.sendMessage({ chatId, text, replyMarkup, priority });
          }
        }
        if (sent) lastTelegramMessageId.set(sessionId, sent.message_id);
        messageSent = true;
        if (isFinal) await attachReviewButtonToLastMessage(sessionId, session);
        return;
      }

      if (session.platform === "slack") {
        if (!slack) return;
        const channel = session.chat_id;
        const threadTs = config.slack?.session_mode === "thread" ? session.space_id : undefined;
        const blocks = buildSlackButtons({
          sessionId,
          includeKill: includeKillButton,
          includeReview: includeReviewButton,
        });
        const posted = await slack.postMessageDetailed({ channel, thread_ts: threadTs, text, blocks, blocksOnLastChunk: false });
        if (posted.lastTs && posted.lastText !== null) {
          lastSlackMessage.set(sessionId, { ts: posted.lastTs, text: posted.lastText });
        }
        messageSent = true;
        if (isFinal) await attachReviewButtonToLastMessage(sessionId, session);
      }
    } finally {
      if (claimedFirst) {
        firstMessageSending.delete(sessionId);
        if (messageSent) firstMessageSent.add(sessionId);
      }
    }
  };

  const streamer = new JsonlStreamer(config, db, logger, sendToSession);
  streamer.start();

  const sessionManager = new SessionManager(config, db, logger, sendToSession, async (id) => streamer.drainSession(id));
  await sessionManager.reconcileStaleSessions();
  const controller = new BotController(config, db, logger, sessionManager, telegram, slack, sendToSession);

  if (telegram && config.telegram?.mode === "poll") {
    logger.info(
      `Telegram polling enabled (timeout=${config.telegram.poll_timeout_seconds}s rate=${config.telegram.rate_limit_msgs_per_sec} msg/s)`,
    );
    let offset: number | undefined;
    (async () => {
      while (true) {
        try {
          const updates = await telegram.getUpdates({ offset });
          for (const update of updates) {
            offset = update.update_id + 1;
            queue.enqueue(async () => {
              try {
                await controller.handleTelegramUpdate(update);
              } catch (e) {
                logger.error("Telegram poll handler error", e);
              }
            });
          }
        } catch (e) {
          logger.error("Telegram poll error", e);
          await sleep(1000);
        }
      }
    })().catch(() => {});
  }

  const server = Bun.serve({
    port: config.bot.port,
    hostname: config.bot.host,
    async fetch(req) {
      const url = new URL(req.url);
      const pathname = url.pathname;

      if (req.method === "GET" && pathname === "/healthz") return new Response("ok");

      // Telegram webhook
      if (telegram && config.telegram?.mode === "webhook" && req.method === "POST" && pathname === config.telegram?.webhook_path) {
        const secretHeader = req.headers.get("x-telegram-bot-api-secret-token");
        if (!secretHeader) {
          logger.warn("Telegram webhook unauthorized (missing secret header)");
          return new Response("unauthorized", { status: 401 });
        }
        if (secretHeader !== config.telegram?.webhook_secret_token) {
          logger.warn("Telegram webhook unauthorized (bad secret header)");
          return new Response("unauthorized", { status: 401 });
        }
        const bodyText = await req.text();
        let body: any;
        try {
          body = JSON.parse(bodyText);
        } catch {
          logger.warn("Telegram webhook bad JSON");
          return new Response("bad request", { status: 400 });
        }
        const updateId = typeof body?.update_id === "number" ? body.update_id : "?";
        const keys = body && typeof body === "object" ? Object.keys(body).filter((k) => k !== "update_id").join(",") : "-";
        logger.debug(`[tg] webhook update_id=${updateId} keys=${keys}`);
        queue.enqueue(async () => {
          try {
            await controller.handleTelegramUpdate(body as any);
          } catch (e) {
            logger.error("Telegram update handler error", e);
          }
        });
        return new Response("ok");
      }

      // Slack Events API
      if (slack && req.method === "POST" && pathname === config.slack?.events_path) {
        const bodyText = await req.text();
        const ok = verifySlackSignature({
          signingSecret: config.slack!.signing_secret,
          timestampHeader: req.headers.get("x-slack-request-timestamp"),
          signatureHeader: req.headers.get("x-slack-signature"),
          body: bodyText,
        });
        if (!ok) {
          logger.warn("Slack events unauthorized (bad signature)");
          return new Response("unauthorized", { status: 401 });
        }
        const body = JSON.parse(bodyText) as any;
        if (body.type === "url_verification" && typeof body.challenge === "string") {
          return Response.json({ challenge: body.challenge });
        }
        const evType = body?.event?.type ?? body?.type ?? "?";
        logger.debug(`[slack] events type=${String(evType)}`);
        queue.enqueue(async () => {
          try {
            await controller.handleSlackEvent(body);
          } catch (e) {
            logger.error("Slack event handler error", e);
          }
        });
        return new Response("ok");
      }

      // Slack Interactivity
      if (slack && req.method === "POST" && pathname === config.slack?.interactions_path) {
        const bodyText = await req.text();
        const ok = verifySlackSignature({
          signingSecret: config.slack!.signing_secret,
          timestampHeader: req.headers.get("x-slack-request-timestamp"),
          signatureHeader: req.headers.get("x-slack-signature"),
          body: bodyText,
        });
        if (!ok) {
          logger.warn("Slack interactions unauthorized (bad signature)");
          return new Response("unauthorized", { status: 401 });
        }
        const params = new URLSearchParams(bodyText);
        const payloadRaw = params.get("payload");
        if (!payloadRaw) return new Response("bad request", { status: 400 });
        const payload = JSON.parse(payloadRaw) as any;

        // Respond quickly; do real work async.
        logger.debug(`[slack] interaction type=${String(payload?.type ?? "?")}`);
        queue.enqueue(async () => {
          try {
            await controller.handleSlackInteraction(payload);
          } catch (e) {
            logger.error("Slack interaction handler error", e);
          }
        });

        if (payload.type === "view_submission") {
          return Response.json({ response_action: "clear" });
        }
        return new Response("");
      }

      return new Response("not found", { status: 404 });
    },
  });

  return {
    async start() {
      logger.info(`Listening on http://${config.bot.host}:${config.bot.port}`);
    },
  };
}
