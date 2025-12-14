import process from "node:process";
import { loadConfig } from "./runtime/config.js";
import { createDatabase } from "./runtime/db.js";
import { runMigrations } from "./runtime/migrations.js";
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
const db = await createDatabase(config, logger);

await runMigrations(db, logger);
logger.info("Migrations complete");
await db.destroy();

