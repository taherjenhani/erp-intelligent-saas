import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import "../test/setup-env";

import { authTokenTtlMs } from "../modules/auth/auth-token.service";
import { getTokenHashCandidates, hashToken, verifyToken } from "./token";

function hmacToken(token: string, secret: string) {
  return crypto
    .createHmac("sha256", secret)
    .update(token)
    .digest("hex");
}

test("token hash keyring verifies tokens signed with a previous key", async () => {
  const token = "a".repeat(128);
  const previousHash = hmacToken(
    token,
    "old_token_hash_secret_minimum_32_chars"
  );

  assert.equal(await verifyToken(token, previousHash), true);
});

test("new token hashes use the active token hash secret", async () => {
  const token = "b".repeat(128);
  const currentHash = await hashToken(token);
  const candidates = await getTokenHashCandidates(token);

  assert.equal(
    currentHash,
    hmacToken(token, "test_token_hash_secret_minimum_32_chars")
  );
  assert.equal(candidates.includes(currentHash), true);
});

test("auth token TTL is configured per token purpose", () => {
  assert.equal(
    authTokenTtlMs("EMAIL_VERIFICATION"),
    24 * 60 * 60 * 1000
  );
  assert.equal(authTokenTtlMs("PASSWORD_RESET"), 30 * 60 * 1000);
});
