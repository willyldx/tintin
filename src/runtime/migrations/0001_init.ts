import type { Kysely } from "kysely";

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .createTable("sessions")
    .addColumn("id", "varchar(36)", (c) => c.primaryKey())
    .addColumn("platform", "varchar(16)", (c) => c.notNull())
    .addColumn("workspace_id", "varchar(128)")
    .addColumn("chat_id", "varchar(128)", (c) => c.notNull())
    .addColumn("space_id", "varchar(128)", (c) => c.notNull())
    .addColumn("created_by_user_id", "varchar(128)", (c) => c.notNull())
    .addColumn("project_id", "varchar(128)", (c) => c.notNull())
    .addColumn("project_path_resolved", "text", (c) => c.notNull())
    .addColumn("codex_session_id", "varchar(128)")
    .addColumn("codex_cwd", "text", (c) => c.notNull())
    .addColumn("status", "varchar(16)", (c) => c.notNull())
    .addColumn("pid", "integer")
    .addColumn("exit_code", "integer")
    .addColumn("started_at", "bigint")
    .addColumn("finished_at", "bigint")
    .addColumn("created_at", "bigint", (c) => c.notNull())
    .addColumn("updated_at", "bigint", (c) => c.notNull())
    .addColumn("last_user_message_at", "bigint")
    .addUniqueConstraint("sessions_space_unique", ["platform", "chat_id", "space_id"])
    .execute();

  await db.schema
    .createTable("session_stream_offsets")
    .addColumn("id", "varchar(36)", (c) => c.primaryKey())
    .addColumn("session_id", "varchar(36)", (c) => c.notNull().references("sessions.id").onDelete("cascade"))
    .addColumn("jsonl_path", "text", (c) => c.notNull())
    .addColumn("byte_offset", "bigint", (c) => c.notNull())
    .addColumn("updated_at", "bigint", (c) => c.notNull())
    .addUniqueConstraint("session_stream_offsets_unique", ["session_id", "jsonl_path"])
    .execute();

  await db.schema
    .createTable("wizard_states")
    .addColumn("id", "varchar(36)", (c) => c.primaryKey())
    .addColumn("platform", "varchar(16)", (c) => c.notNull())
    .addColumn("chat_id", "varchar(128)", (c) => c.notNull())
    .addColumn("user_id", "varchar(128)", (c) => c.notNull())
    .addColumn("state", "varchar(32)", (c) => c.notNull())
    .addColumn("project_id", "varchar(128)")
    .addColumn("custom_path_candidate", "text")
    .addColumn("created_at", "bigint", (c) => c.notNull())
    .addColumn("updated_at", "bigint", (c) => c.notNull())
    .addUniqueConstraint("wizard_states_unique", ["platform", "chat_id", "user_id"])
    .execute();

  await db.schema
    .createTable("audit_events")
    .addColumn("id", "varchar(36)", (c) => c.primaryKey())
    .addColumn("session_id", "varchar(36)", (c) => c.references("sessions.id").onDelete("set null"))
    .addColumn("kind", "varchar(64)", (c) => c.notNull())
    .addColumn("payload_json", "text", (c) => c.notNull())
    .addColumn("created_at", "bigint", (c) => c.notNull())
    .execute();

  await db.schema.createIndex("sessions_status_idx").on("sessions").column("status").execute();
  await db.schema
    .createIndex("session_stream_offsets_session_idx")
    .on("session_stream_offsets")
    .column("session_id")
    .execute();
  await db.schema.createIndex("wizard_states_chat_idx").on("wizard_states").columns(["platform", "chat_id"]).execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropTable("audit_events").ifExists().execute();
  await db.schema.dropTable("wizard_states").ifExists().execute();
  await db.schema.dropTable("session_stream_offsets").ifExists().execute();
  await db.schema.dropTable("sessions").ifExists().execute();
}

