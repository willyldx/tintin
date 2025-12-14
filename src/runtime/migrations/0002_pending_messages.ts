import type { Kysely } from "kysely";

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .createTable("session_pending_messages")
    .addColumn("id", "varchar(36)", (c) => c.primaryKey())
    .addColumn("session_id", "varchar(36)", (c) => c.notNull().references("sessions.id").onDelete("cascade"))
    .addColumn("user_id", "varchar(128)", (c) => c.notNull())
    .addColumn("message_text", "text", (c) => c.notNull())
    .addColumn("created_at", "bigint", (c) => c.notNull())
    .addColumn("consumed_at", "bigint")
    .execute();

  await db.schema
    .createIndex("session_pending_messages_session_idx")
    .on("session_pending_messages")
    .column("session_id")
    .execute();

  await db.schema
    .createIndex("session_pending_messages_consumed_idx")
    .on("session_pending_messages")
    .column("consumed_at")
    .execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropTable("session_pending_messages").ifExists().execute();
}

