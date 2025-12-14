import type { AppConfig } from "./config.js";
import type { Db } from "./db.js";
import type { Logger } from "./log.js";
import { TaskQueue } from "./util.js";
import { TelegramClient } from "./platform/telegram.js";
import { SlackClient, verifySlackSignature } from "./platform/slack.js";
import { BotController } from "./controller2.js";
import { JsonlStreamer } from "./streamer.js";
import { SessionManager } from "./sessionManager.js";

export interface BotServiceDeps {
  config: AppConfig;
  db: Db;
  logger: Logger;
}

export async function createBotService(deps: BotServiceDeps) {
  const { config, db, logger } = deps;

  const queue = new TaskQueue(16);

  const telegram = config.telegram ? new TelegramClient(config.telegram, logger) : null;
  const slack = config.slack ? new SlackClient(config.slack, logger) : null;

  if (telegram) await telegram.init();

  const isFencedCodeBlock = (text: string): boolean => {
    const t = text.trim();
    return t.startsWith("```") && t.endsWith("```");
  };

  const sendToSession = async (sessionId: string, text: string) => {
    const session = await db.selectFrom("sessions").selectAll().where("id", "=", sessionId).executeTakeFirst();
    if (!session) return;

    if (session.platform === "telegram") {
      if (!telegram) return;
      const chatId = Number(session.chat_id);
      const space = Number(session.space_id);
      if (Number.isNaN(chatId) || Number.isNaN(space)) return;

      if (isFencedCodeBlock(text)) {
        const parseMode = "Markdown" as const;
        if (config.telegram?.use_topics) {
          try {
            await telegram.sendMessageSingleStrict({ chatId, messageThreadId: space, text, parseMode });
          } catch {
            try {
              await telegram.sendMessageSingleStrict({ chatId, replyToMessageId: space, text, parseMode });
            } catch {
              await telegram.sendMessageSingleStrict({ chatId, text, parseMode });
            }
          }
        } else {
          try {
            await telegram.sendMessageSingleStrict({ chatId, replyToMessageId: space, text, parseMode });
          } catch {
            await telegram.sendMessageSingleStrict({ chatId, text, parseMode });
          }
        }
        return;
      }

      if (config.telegram?.use_topics) {
        try {
          await telegram.sendMessageStrict({ chatId, messageThreadId: space, text });
        } catch {
          try {
            await telegram.sendMessageStrict({ chatId, replyToMessageId: space, text });
          } catch {
            await telegram.sendMessage({ chatId, text });
          }
        }
      } else {
        try {
          await telegram.sendMessageStrict({ chatId, replyToMessageId: space, text });
        } catch {
          await telegram.sendMessage({ chatId, text });
        }
      }
      return;
    }

    if (session.platform === "slack") {
      if (!slack) return;
      const channel = session.chat_id;
      const threadTs = config.slack?.session_mode === "thread" ? session.space_id : undefined;
      await slack.postMessage({ channel, thread_ts: threadTs, text });
    }
  };

  const streamer = new JsonlStreamer(config, db, logger, sendToSession);
  streamer.start();

  const sessionManager = new SessionManager(config, db, logger, sendToSession, async (id) => streamer.drainSession(id));
  await sessionManager.reconcileStaleSessions();
  const controller = new BotController(config, db, logger, sessionManager, telegram, slack, sendToSession);

  const server = Bun.serve({
    port: config.bot.port,
    hostname: config.bot.host,
    async fetch(req) {
      const url = new URL(req.url);
      const pathname = url.pathname;

      if (req.method === "GET" && pathname === "/healthz") return new Response("ok");

      // Telegram webhook
      if (telegram && req.method === "POST" && pathname === config.telegram?.webhook_path) {
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
