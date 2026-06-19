import assert from "node:assert/strict";
import test from "node:test";
import "../test/setup-env";

import {
  decryptEmailMessageFromStorage,
  deliverEmailViaHttpProvider,
  deliverEmailViaResendProvider,
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

test("email outbox decrypts payloads encrypted with a previous key", () => {
  const message = {
    messageId: "<old-key-message@example.com>",
    idempotencyKey: "old-key-idempotency-key",
    to: "user@example.com",
    subject: "Legacy encrypted message",
    text: "legacy body",
    html: "<p>legacy body</p>",
  };

  const encrypted = encryptEmailMessageForStorage(message, "old-email-key");

  assert.equal(encrypted.encryptionKeyId, "old-email-key");
  assert.deepEqual(decryptEmailMessageFromStorage(encrypted), message);
});

test("Resend provider sends stable idempotency key", async () => {
  const originalFetch = globalThis.fetch;
  let capturedRequest: Request | null = null;

  globalThis.fetch = async (input, init) => {
    capturedRequest = new Request(input, init);

    return new Response(JSON.stringify({ id: "resend-email-id" }), {
      status: 200,
      headers: {
        "content-type": "application/json",
      },
    });
  };

  try {
    const result = await deliverEmailViaResendProvider({
      messageId: "<message-id@example.com>",
      idempotencyKey: "email-outbox-idempotency-key",
      to: "user@example.com",
      subject: "Verify email",
      text: "Verify email text",
      html: "<p>Verify email</p>",
    });

    assert.equal(result.providerMessageId, "resend-email-id");
    assert.ok(capturedRequest);
    assert.equal(
      capturedRequest.headers.get("Idempotency-Key"),
      "email-outbox-idempotency-key"
    );
    assert.equal(
      capturedRequest.headers.get("authorization"),
      "Bearer re_test_api_key_minimum_16"
    );

    const body = (await capturedRequest.json()) as {
      from: string;
      to: string[];
      subject: string;
      headers: Record<string, string>;
    };

    assert.deepEqual(body.to, ["user@example.com"]);
    assert.equal(body.subject, "Verify email");
    assert.equal(
      body.headers["X-ERP-Message-ID"],
      "<message-id@example.com>"
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("HTTP email provider sends configured idempotency key header", async () => {
  const originalFetch = globalThis.fetch;
  let capturedRequest: Request | null = null;

  globalThis.fetch = async (input, init) => {
    capturedRequest = new Request(input, init);

    return new Response(JSON.stringify({ providerMessageId: "http-email-id" }), {
      status: 200,
      headers: {
        "content-type": "application/json",
      },
    });
  };

  try {
    const result = await deliverEmailViaHttpProvider({
      messageId: "<message-id@example.com>",
      idempotencyKey: "email-outbox-idempotency-key",
      to: "user@example.com",
      subject: "Verify email",
      text: "Verify email text",
      html: "<p>Verify email</p>",
    });

    assert.equal(result.providerMessageId, "http-email-id");
    assert.ok(capturedRequest);
    assert.equal(
      capturedRequest.headers.get("Idempotency-Key"),
      "email-outbox-idempotency-key"
    );

    const body = (await capturedRequest.json()) as {
      idempotencyKey: string;
      messageId: string;
    };

    assert.equal(body.idempotencyKey, "email-outbox-idempotency-key");
    assert.equal(body.messageId, "<message-id@example.com>");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
