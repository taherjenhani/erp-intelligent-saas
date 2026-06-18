import { prisma } from "../lib/prisma";

type BackfillMap = Record<string, string>;

type StoreMatch = {
  id: string;
  code: string;
  name: string;
  organizationId: string | null;
};

type OrganizationMatch = {
  id: string;
  code: string;
  name: string;
};

const nullableTenantMigration = "20260604103000_auth_multitenant_outbox_hardening";

export function parseBackfillMapFromRaw(raw: string | undefined) {
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

  const backfillMap = parsed as BackfillMap;
  const entries = Object.entries(backfillMap);

  if (entries.length === 0) {
    throw new Error(
      "STORE_ORGANIZATION_BACKFILL_MAP must contain at least one store mapping"
    );
  }

  for (const [storeIdOrCode, organizationIdOrCode] of entries) {
    if (
      typeof storeIdOrCode !== "string" ||
      storeIdOrCode.trim().length === 0 ||
      typeof organizationIdOrCode !== "string" ||
      organizationIdOrCode.trim().length === 0
    ) {
      throw new Error(
        "STORE_ORGANIZATION_BACKFILL_MAP entries must be non-empty strings"
      );
    }
  }

  return backfillMap;
}

export function parseBackfillMap() {
  return parseBackfillMapFromRaw(process.env.STORE_ORGANIZATION_BACKFILL_MAP);
}

export async function hasStoreOrganizationColumn() {
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

export async function runStoreOrganizationBackfill(
  backfillMap: BackfillMap
) {
  if (!(await hasStoreOrganizationColumn())) {
    throw new Error(
      `Store.organizationId does not exist yet. Apply ${nullableTenantMigration} first because it adds the nullable tenant column required by this backfill.`
    );
  }

  let updated = 0;

  await prisma.$transaction(async (tx) => {
    for (const [storeIdOrCode, organizationIdOrCode] of Object.entries(
      backfillMap
    )) {
      const stores = await tx.$queryRaw<StoreMatch[]>`
        SELECT "id", "code", "name", "organizationId"
        FROM "Store"
        WHERE "id" = ${storeIdOrCode}
          OR "code" = ${storeIdOrCode}
      `;

      if (stores.length === 0) {
        throw new Error(`No Store matched backfill key "${storeIdOrCode}"`);
      }

      if (stores.length > 1) {
        throw new Error(
          `Backfill key "${storeIdOrCode}" matched multiple stores. Use unambiguous store ids.`
        );
      }

      const organizations = await tx.$queryRaw<OrganizationMatch[]>`
        SELECT "id", "code", "name"
        FROM "Organization"
        WHERE "id" = ${organizationIdOrCode}
          OR "code" = ${organizationIdOrCode}
      `;

      if (organizations.length === 0) {
        throw new Error(
          `No Organization matched backfill value "${organizationIdOrCode}" for store "${storeIdOrCode}"`
        );
      }

      if (organizations.length > 1) {
        throw new Error(
          `Backfill value "${organizationIdOrCode}" matched multiple organizations. Use unambiguous organization ids.`
        );
      }

      const [store] = stores;
      const [organization] = organizations;

      if (store.organizationId && store.organizationId !== organization.id) {
        throw new Error(
          `Store "${store.code}" already belongs to organization "${store.organizationId}". Refusing to reassign it to "${organization.id}".`
        );
      }

      if (store.organizationId === organization.id) {
        continue;
      }

      const result = await tx.$executeRaw`
        UPDATE "Store"
        SET "organizationId" = ${organization.id}
        WHERE "id" = ${store.id}
          AND "organizationId" IS NULL
      `;

      updated += result;
    }
  });

  const remaining = await prisma.$queryRaw<Array<{ count: bigint }>>`
    SELECT COUNT(*)::bigint AS count
    FROM "Store"
    WHERE "organizationId" IS NULL
  `;
  const remainingCount = Number(remaining[0]?.count ?? 0);

  return {
    updated,
    remaining: remainingCount,
  };
}

async function main() {
  const result = await runStoreOrganizationBackfill(parseBackfillMap());

  console.log("Store organization backfill completed", result);

  if (result.remaining > 0) {
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main()
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}
