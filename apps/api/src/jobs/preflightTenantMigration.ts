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

type PrismaClientLike = typeof prisma;

export const nullableTenantMigration =
  "20260604103000_auth_multitenant_outbox_hardening";
export const hardeningTenantMigration =
  "20260610120000_auth_production_hardening";

export type TenantPreflightResult =
  | {
      ok: true;
      stage: "ready_for_hardening" | "already_hardened";
      storesWithoutOrganization: [];
    }
  | {
      ok: false;
      reason: "missing_store_organization_column";
      storesWithoutOrganization: [];
    }
  | {
      ok: false;
      reason: "stores_without_organization";
      storesWithoutOrganization: StoreWithoutOrganization[];
    };

export async function getStoreOrganizationColumn(
  client: PrismaClientLike = prisma
): Promise<StoreOrganizationColumn> {
  const result = await client.$queryRaw<
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

export function nullableMigrationPlan() {
  return [
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
  ].join("\n");
}

export async function findStoresWithoutOrganization(
  client: PrismaClientLike = prisma
) {
  return client.$queryRaw<StoreWithoutOrganization[]>`
    SELECT "id", "code", "name"
    FROM "Store"
    WHERE "organizationId" IS NULL
    ORDER BY "createdAt" ASC
  `;
}

export async function runTenantPreflight(
  client: PrismaClientLike = prisma
): Promise<TenantPreflightResult> {
  const column = await getStoreOrganizationColumn(client);

  if (!column.exists) {
    return {
      ok: false,
      reason: "missing_store_organization_column",
      storesWithoutOrganization: [],
    };
  }

  const stores = await findStoresWithoutOrganization(client);

  if (stores.length === 0) {
    return {
      ok: true,
      stage: column.isNullable
        ? "ready_for_hardening"
        : "already_hardened",
      storesWithoutOrganization: [],
    };
  }

  return {
    ok: false,
    reason: "stores_without_organization",
    storesWithoutOrganization: stores,
  };
}

async function main() {
  const result = await runTenantPreflight();

  if (result.ok) {
    const stage = result.stage === "ready_for_hardening"
      ? "ready for NOT NULL hardening"
      : "already hardened";
    console.log(`Tenant migration preflight passed: every Store has organizationId (${stage}).`);
    return;
  }

  if (result.reason === "missing_store_organization_column") {
    console.error(nullableMigrationPlan());
    process.exitCode = 1;
    return;
  }

  console.error("Tenant migration preflight failed: backfill Store.organizationId before migrate deploy.");
  console.error(JSON.stringify(result.storesWithoutOrganization, null, 2));
  process.exitCode = 1;
}

if (require.main === module) {
  main().finally(async () => {
    await prisma.$disconnect();
  });
}
