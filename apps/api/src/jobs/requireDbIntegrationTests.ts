function fail(message: string) {
  console.error(
    [
      message,
      "Use NODE_ENV=test, RUN_DB_TESTS=true, and a disposable PostgreSQL DATABASE_URL.",
      "Never run auth integration tests against production data.",
    ].join("\n")
  );
  process.exit(1);
}

if (process.env.RUN_DB_TESTS !== "true") {
  fail("RUN_DB_TESTS=true is required for DB integration tests.");
}

if (process.env.NODE_ENV !== "test") {
  fail("NODE_ENV=test is required for DB integration tests.");
}

const databaseUrl = process.env.DATABASE_URL ?? "";
const allowNonTestDatabase = process.env.ALLOW_NON_TEST_DB_INTEGRATION === "true";
const looksLikeDisposableDatabase =
  /localhost|127\.0\.0\.1|::1/i.test(databaseUrl) || /test/i.test(databaseUrl);

if (!looksLikeDisposableDatabase && !allowNonTestDatabase) {
  fail(
    "DATABASE_URL does not look like a local or test database. Set ALLOW_NON_TEST_DB_INTEGRATION=true only for a disposable CI database."
  );
}
