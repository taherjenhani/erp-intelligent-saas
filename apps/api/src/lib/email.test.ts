import assert from "node:assert/strict";
import test from "node:test";
import "../test/setup-env";

import {
  decryptEmailMessageFromStorage,
  encryptEmailMessageForStorage,
  SCRUBBED_EMAIL_BODY,
} from "./email";

test("email outbox encrypts sensitive body fields at rest", () => {
  const token = "a".repeat(128);
  const message = {
    messageId: "<test-message@example.com>",
    idempotencyKey: "test-idempotency-key",
    to: "user@example.com",
    subject: "Reset your password",
    text: `Reset token: ${token}`,
    html: `<p>Reset token: ${token}</p>`,
  };

  const encrypted = encryptEmailMessageForStorage(message);

  assert.match(encrypted.text, /^enc:v1:[A-Za-z0-9._:-]+:/);
  assert.match(encrypted.html, /^enc:v1:[A-Za-z0-9._:-]+:/);
  assert.equal(encrypted.encryptionKeyId, "test-email-key");
  assert.equal(encrypted.to, message.to);
  assert.equal(encrypted.subject, message.subject);
  assert.equal(encrypted.messageId, message.messageId);
  assert.equal(encrypted.text.includes(token), false);
  assert.equal(encrypted.html.includes(token), false);

  const decrypted = decryptEmailMessageFromStorage(encrypted);

  assert.deepEqual(decrypted, message);
});

test("email outbox scrub marker is non-sensitive", () => {
  assert.equal(SCRUBBED_EMAIL_BODY.includes("token"), false);
});
