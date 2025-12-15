import type { Kysely } from "kysely";

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema.alterTable("sessions").addColumn("space_emoji", "varchar(32)").execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.alterTable("sessions").dropColumn("space_emoji").execute();
}
