import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import "../test/setup-env";

import {
  parseBackfillMapFromRaw,
} from "./backfillStoreOrganizations";
import {
  nullableMigrationPlan as preflightNullableMigrationPlan,
  nullableTenantMigration,
} from "./preflightTenantMigration";

test("tenant backfill map parser rejects missing and invalid input", () => {
  assert.throws(() => parseBackfillMapFromRaw(undefined));
  assert.throws(() => parseBackfillMapFromRaw(""));
  assert.throws(() => parseBackfillMapFromRaw("[]"));
  assert.throws(() => parseBackfillMapFromRaw("{}"));
  assert.throws(() => parseBackfillMapFromRaw('{"": "org"}'));
  assert.throws(() => parseBackfillMapFromRaw('{"store": ""}'));
});

test("tenant backfill map parser accepts store to organization mapping", () => {
  assert.deepEqual(
    parseBackfillMapFromRaw('{"STORE_CODE":"ORG_CODE"}'),
    {
      STORE_CODE: "ORG_CODE",
    }
  );
});

test("tenant preflight plan documents the nullable migration first", () => {
  const plan = preflightNullableMigrationPlan();

  assert.match(plan, new RegExp(nullableTenantMigration));
  assert.match(plan, /tenant:backfill-stores/);
  assert.match(plan, /tenant:preflight/);
  assert.match(plan, /prisma migrate deploy/);
});

test("tenant migration runbook documents required command order", () => {
  const runbook = readFileSync(
    "docs/runbooks/tenant-migration.md",
    "utf8"
  );
  const backfillIndex = runbook.indexOf("npm run tenant:backfill-stores");
  const preflightIndex = runbook.indexOf("npm run tenant:preflight");
  const migrateIndex = runbook.indexOf("npx prisma migrate deploy");

  assert.notEqual(backfillIndex, -1);
  assert.notEqual(preflightIndex, -1);
  assert.notEqual(migrateIndex, -1);
  assert.equal(backfillIndex < migrateIndex, true);
  assert.equal(preflightIndex < migrateIndex, true);
});
