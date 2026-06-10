import { prisma } from "../lib/prisma";

type StoreWithoutOrganization = {
  id: string;
  code: string;
  name: string;
};

async function hasStoreOrganizationColumn() {
  const result = await prisma.$queryRaw<Array<{ exists: boolean }>>`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'Store'
        AND column_name = 'organizationId'
    ) AS "exists"
  `;

  return result[0]?.exists === true;
}

async function main() {
  if (!(await hasStoreOrganizationColumn())) {
    console.error(
      "Tenant migration preflight cannot run: Store.organizationId does not exist yet. Apply the multitenant migration that adds the column before running this preflight."
    );
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
    console.log("Tenant migration preflight passed: every Store has organizationId.");
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
