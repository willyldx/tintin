import { mkdir } from "node:fs/promises";
import process from "node:process";
import { loadConfig } from "./runtime/config.js";
import { createDatabase } from "./runtime/db.js";
import { runMigrations } from "./runtime/migrations.js";
import { createBotService } from "./runtime/service.js";
import { createLogger } from "./runtime/log.js";

function parseArgs(argv: string[]) {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a) continue;
    if (a === "--config") {
      const v = argv[i + 1];
      if (!v) throw new Error("--config requires a value");
      args.set("config", v);
      i++;
      continue;
    }
    if (a.startsWith("--config=")) {
      args.set("config", a.slice("--config=".length));
      continue;
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const configPath = args.get("config") ?? process.env.CONFIG_PATH ?? "./config.toml";

const config = await loadConfig(configPath);
const logger = createLogger(config.bot.log_level);

await mkdir(config.bot.data_dir, { recursive: true });

const db = await createDatabase(config, logger);

if (process.env.BOT_AUTO_MIGRATE === "1" || process.env.BOT_AUTO_MIGRATE === "true") {
  logger.info("Running migrations (BOT_AUTO_MIGRATE enabled)");
  await runMigrations(db, logger);
}

const service = await createBotService({ config, db, logger });
await service.start();

const shutdown = async (signal: string) => {
  logger.info(`Shutting down (${signal})`);
  await db.destroy();
  process.exit(0);
};

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
