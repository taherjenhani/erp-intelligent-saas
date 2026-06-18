import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import bcrypt from "bcrypt";
import "../test/setup-env";

import {
  activePasswordPepperKeyId,
  hashPassword,
  verifyPassword,
} from "./hash";

function passwordDigest(password: string, secret: string) {
  return crypto
    .createHmac("sha256", secret)
    .update(password)
    .digest("hex");
}

test("old password hash remains verifiable after pepper rotation", async () => {
  const password = "StrongPass1!";
  const oldSecret = "old_password_pepper_minimum_32_chars";
  const oldHash = await bcrypt.hash(passwordDigest(password, oldSecret), 4);

  assert.equal(await verifyPassword(password, oldHash, "old-pepper"), true);
  assert.equal(await verifyPassword("WrongPass1!", oldHash, "old-pepper"), false);
});

test("new password hashing uses the active pepper key id policy", async () => {
  const password = "StrongPass1!";
  const hash = await hashPassword(password);

  assert.equal(activePasswordPepperKeyId(), "test-pepper");
  assert.equal(await verifyPassword(password, hash, activePasswordPepperKeyId()), true);
});
