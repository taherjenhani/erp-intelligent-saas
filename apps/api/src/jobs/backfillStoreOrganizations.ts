import { prisma } from "../lib/prisma";

type BackfillMap = Record<string, string>;

function parseBackfillMap() {
  const raw = process.env.STORE_ORGANIZATION_BACKFILL_MAP;

  if (!raw) {
    throw new Error(
      "STORE_ORGANIZATION_BACKFILL_MAP is required. Example: {\"storeCode\":\"organizationId\"}"
    );
  }

  const parsed = JSON.parse(raw) as unknown;

  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed)
  ) {
    throw new Error("STORE_ORGANIZATION_BACKFILL_MAP must be a JSON object");
  }

  return parsed as BackfillMap;
}

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
    throw new Error(
      "Store.organizationId does not exist yet. Apply the multitenant migration that adds the nullable column before running the backfill."
    );
  }

  const backfillMap = parseBackfillMap();
  let updated = 0;

  for (const [storeIdOrCode, organizationId] of Object.entries(backfillMap)) {
    const result = await prisma.$executeRaw`
      UPDATE "Store"
      SET "organizationId" = ${organizationId}
      WHERE ("id" = ${storeIdOrCode} OR "code" = ${storeIdOrCode})
        AND "organizationId" IS NULL
    `;

    updated += result;
  }

  const remaining = await prisma.$queryRaw<Array<{ count: bigint }>>`
    SELECT COUNT(*)::bigint AS count
    FROM "Store"
    WHERE "organizationId" IS NULL
  `;
  const remainingCount = Number(remaining[0]?.count ?? 0);

  console.log("Store organization backfill completed", {
    updated,
    remaining: remainingCount,
  });

  if (remainingCount > 0) {
    process.exitCode = 1;
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
