import { prisma } from "../lib/prisma";

type StoreWithoutOrganization = {
  id: string;
  code: string;
  name: string;
};

type StoreOrganizationColumn = {
  exists: boolean;
  isNullable: boolean | null;
};

const nullableTenantMigration = "20260604103000_auth_multitenant_outbox_hardening";
const hardeningTenantMigration = "20260610120000_auth_production_hardening";

async function getStoreOrganizationColumn(): Promise<StoreOrganizationColumn> {
  const result = await prisma.$queryRaw<
    Array<{ exists: boolean; isNullable: "YES" | "NO" | null }>
  >`
    SELECT
      EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'Store'
          AND column_name = 'organizationId'
      ) AS "exists",
      (
        SELECT is_nullable
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'Store'
          AND column_name = 'organizationId'
      ) AS "isNullable"
  `;

  const column = result[0];

  return {
    exists: column?.exists === true,
    isNullable:
      column?.isNullable === null ? null : column?.isNullable === "YES",
  };
}

function printNullableMigrationPlan() {
  console.error(
    [
      "Tenant migration preflight failed: Store.organizationId does not exist yet.",
      "",
      "Required production sequence for an existing database:",
      `1. Apply only ${nullableTenantMigration}, which adds Store.organizationId as nullable.`,
      "2. Run npm run tenant:backfill-stores with STORE_ORGANIZATION_BACKFILL_MAP.",
      "3. Rerun npm run tenant:preflight until it passes.",
      `4. Then run npx prisma migrate deploy so ${hardeningTenantMigration} can make the column NOT NULL safely.`,
      "",
      "If all migrations are already bundled in this release, apply the nullable migration in a controlled maintenance step, then mark it as applied:",
      `npx prisma db execute --file prisma/migrations/${nullableTenantMigration}/migration.sql`,
      `npx prisma migrate resolve --applied ${nullableTenantMigration}`,
    ].join("\n")
  );
}

async function main() {
  const column = await getStoreOrganizationColumn();

  if (!column.exists) {
    printNullableMigrationPlan();
    process.exitCode = 1;
    return;
  }

  const stores = await prisma.$queryRaw<StoreWithoutOrganization[]>`
    SELECT "id", "code", "name"
    FROM "Store"
    WHERE "organizationId" IS NULL
    ORDER BY "createdAt" ASC
  `;

  if (stores.length === 0) {
    const stage = column.isNullable
      ? "ready for NOT NULL hardening"
      : "already hardened";
    console.log(
      `Tenant migration preflight passed: every Store has organizationId (${stage}).`
    );
    return;
  }

  console.error(
    "Tenant migration preflight failed: backfill Store.organizationId before migrate deploy.",
    stores
  );
  process.exitCode = 1;
}

main().finally(async () => {
  await prisma.$disconnect();
});
