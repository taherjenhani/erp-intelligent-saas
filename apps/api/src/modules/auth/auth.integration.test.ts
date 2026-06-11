import assert from "node:assert/strict";
import test from "node:test";

import { buildApp } from "../../app";
import {
  decryptEmailMessageFromStorage,
  encryptLegacyEmailOutboxBatch,
  enqueueEmail,
  processQueuedEmail,
  rotateEmailOutboxEncryptionBatch,
  SCRUBBED_EMAIL_BODY,
} from "../../lib/email";
import { prisma } from "../../lib/prisma";
import { hashPassword } from "../../utils/hash";
import { loginUser } from "./auth.service";

function getCookieHeader(setCookie: string | string[] | undefined) {
  if (!setCookie) {
    return "";
  }

  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];

  return cookies
    .map((cookie) => cookie.split(";")[0])
    .join("; ");
}

async function getCsrf(app: ReturnType<typeof buildApp>) {
  const response = await app.inject({
    method: "GET",
    url: "/api/auth/csrf-token",
  });

  assert.equal(response.statusCode, 200);

  return {
    csrfToken: response.json().data.csrfToken as string,
    cookie: getCookieHeader(response.headers["set-cookie"]),
  };
}

test("auth routes register, verify, login and return /me", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const app = buildApp();
  const email = `auth-${Date.now()}@example.com`;
  const password = "StrongPass1!";

  try {
    await prisma.user.deleteMany({
      where: { email },
    });

    const registerCsrf = await getCsrf(app);
    const registerResponse = await app.inject({
      method: "POST",
      url: "/api/auth/register",
      headers: {
        cookie: registerCsrf.cookie,
        "x-csrf-token": registerCsrf.csrfToken,
      },
      payload: {
        firstName: "Auth",
        lastName: "Tester",
        email,
        password,
      },
    });

    assert.equal(registerResponse.statusCode, 201);

    const verificationToken =
      registerResponse.json().data.emailVerificationToken;
    assert.equal(typeof verificationToken, "string");

    const verifyCsrf = await getCsrf(app);
    const verifyResponse = await app.inject({
      method: "POST",
      url: "/api/auth/verify-email",
      headers: {
        cookie: verifyCsrf.cookie,
        "x-csrf-token": verifyCsrf.csrfToken,
      },
      payload: {
        token: verificationToken,
      },
    });

    assert.equal(verifyResponse.statusCode, 200);

    const loginCsrf = await getCsrf(app);
    const loginResponse = await app.inject({
      method: "POST",
      url: "/api/auth/login",
      headers: {
        cookie: loginCsrf.cookie,
        "x-csrf-token": loginCsrf.csrfToken,
      },
      payload: {
        email,
        password,
      },
    });

    assert.equal(loginResponse.statusCode, 200);

    const accessToken = loginResponse.json().data.accessToken;
    const meResponse = await app.inject({
      method: "GET",
      url: "/api/auth/me",
      headers: {
        authorization: `Bearer ${accessToken}`,
      },
    });

    assert.equal(meResponse.statusCode, 200);
    assert.equal(meResponse.json().data.email, email);

    const loginSecurityEvent = await prisma.securityEvent.findFirst({
      where: {
        type: "LOGIN_SUCCESS",
        user: {
          email,
        },
      },
    });

    assert.equal(Boolean(loginSecurityEvent), true);
  } finally {
    await prisma.emailOutbox.deleteMany({
      where: { to: email },
    });
    await prisma.securityEvent.deleteMany({
      where: {
        user: {
          email,
        },
      },
    });
    await prisma.user.deleteMany({
      where: { email },
    });
    await app.close();
    await prisma.$disconnect();
  }
});

test("password reset token cannot be reused", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const app = buildApp();
  const email = `reset-${Date.now()}@example.com`;
  const password = "StrongPass1!";

  try {
    await prisma.emailOutbox.deleteMany({
      where: { to: email },
    });
    await prisma.user.deleteMany({
      where: { email },
    });

    const registerCsrf = await getCsrf(app);
    const registerResponse = await app.inject({
      method: "POST",
      url: "/api/auth/register",
      headers: {
        cookie: registerCsrf.cookie,
        "x-csrf-token": registerCsrf.csrfToken,
      },
      payload: {
        firstName: "Reset",
        lastName: "Tester",
        email,
        password,
      },
    });

    assert.equal(registerResponse.statusCode, 201);

    const verificationToken =
      registerResponse.json().data.emailVerificationToken;

    const verifyCsrf = await getCsrf(app);
    const verifyResponse = await app.inject({
      method: "POST",
      url: "/api/auth/verify-email",
      headers: {
        cookie: verifyCsrf.cookie,
        "x-csrf-token": verifyCsrf.csrfToken,
      },
      payload: {
        token: verificationToken,
      },
    });

    assert.equal(verifyResponse.statusCode, 200);

    const forgotCsrf = await getCsrf(app);
    const forgotResponse = await app.inject({
      method: "POST",
      url: "/api/auth/forgot-password",
      headers: {
        cookie: forgotCsrf.cookie,
        "x-csrf-token": forgotCsrf.csrfToken,
      },
      payload: {
        email,
      },
    });

    assert.equal(forgotResponse.statusCode, 200);

    const resetToken = forgotResponse.json().data.resetToken;
    assert.equal(typeof resetToken, "string");

    const resetCsrf = await getCsrf(app);
    const resetResponse = await app.inject({
      method: "POST",
      url: "/api/auth/reset-password",
      headers: {
        cookie: resetCsrf.cookie,
        "x-csrf-token": resetCsrf.csrfToken,
      },
      payload: {
        token: resetToken,
        password: "NewStrongPass1!",
      },
    });

    assert.equal(resetResponse.statusCode, 200);

    const reusedResetCsrf = await getCsrf(app);
    const reusedResetResponse = await app.inject({
      method: "POST",
      url: "/api/auth/reset-password",
      headers: {
        cookie: reusedResetCsrf.cookie,
        "x-csrf-token": reusedResetCsrf.csrfToken,
      },
      payload: {
        token: resetToken,
        password: "AnotherStrongPass1!",
      },
    });

    assert.equal(reusedResetResponse.statusCode, 401);
    assert.equal(
      reusedResetResponse.json().code,
      "AUTH_INVALID_RESET_TOKEN"
    );

    const secondForgotCsrf = await getCsrf(app);
    const secondForgotResponse = await app.inject({
      method: "POST",
      url: "/api/auth/forgot-password",
      headers: {
        cookie: secondForgotCsrf.cookie,
        "x-csrf-token": secondForgotCsrf.csrfToken,
      },
      payload: {
        email,
      },
    });

    assert.equal(secondForgotResponse.statusCode, 200);

    const secondResetToken = secondForgotResponse.json().data.resetToken;
    const reusedOldPasswordCsrf = await getCsrf(app);
    const reusedOldPasswordResponse = await app.inject({
      method: "POST",
      url: "/api/auth/reset-password",
      headers: {
        cookie: reusedOldPasswordCsrf.cookie,
        "x-csrf-token": reusedOldPasswordCsrf.csrfToken,
      },
      payload: {
        token: secondResetToken,
        password,
      },
    });

    assert.equal(reusedOldPasswordResponse.statusCode, 400);
    assert.equal(
      reusedOldPasswordResponse.json().code,
      "AUTH_PASSWORD_REUSED"
    );
  } finally {
    await prisma.emailOutbox.deleteMany({
      where: { to: email },
    });
    await prisma.securityEvent.deleteMany({
      where: {
        user: {
          email,
        },
      },
    });
    await prisma.user.deleteMany({
      where: { email },
    });
    await app.close();
    await prisma.$disconnect();
  }
});

test("concurrent refresh requests are idempotent", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const app = buildApp();
  const email = `refresh-${Date.now()}@example.com`;
  const password = "StrongPass1!";

  try {
    await prisma.emailOutbox.deleteMany({
      where: { to: email },
    });
    await prisma.user.deleteMany({
      where: { email },
    });

    const registerCsrf = await getCsrf(app);
    const registerResponse = await app.inject({
      method: "POST",
      url: "/api/auth/register",
      headers: {
        cookie: registerCsrf.cookie,
        "x-csrf-token": registerCsrf.csrfToken,
      },
      payload: {
        firstName: "Refresh",
        lastName: "Tester",
        email,
        password,
      },
    });

    assert.equal(registerResponse.statusCode, 201);

    const verificationToken =
      registerResponse.json().data.emailVerificationToken;

    const verifyCsrf = await getCsrf(app);
    const verifyResponse = await app.inject({
      method: "POST",
      url: "/api/auth/verify-email",
      headers: {
        cookie: verifyCsrf.cookie,
        "x-csrf-token": verifyCsrf.csrfToken,
      },
      payload: {
        token: verificationToken,
      },
    });

    assert.equal(verifyResponse.statusCode, 200);

    const loginCsrf = await getCsrf(app);
    const loginResponse = await app.inject({
      method: "POST",
      url: "/api/auth/login",
      headers: {
        cookie: loginCsrf.cookie,
        "x-csrf-token": loginCsrf.csrfToken,
      },
      payload: {
        email,
        password,
      },
    });

    assert.equal(loginResponse.statusCode, 200);

    const refreshCookie = getCookieHeader(
      loginResponse.headers["set-cookie"]
    );
    const refreshCsrf = await getCsrf(app);
    const cookie = [refreshCookie, refreshCsrf.cookie]
      .filter(Boolean)
      .join("; ");
    const idempotencyKey = `refresh-${Date.now()}-key`;

    const refreshRequest = () =>
      app.inject({
        method: "POST",
        url: "/api/auth/refresh",
        headers: {
          cookie,
          "x-csrf-token": refreshCsrf.csrfToken,
          "idempotency-key": idempotencyKey,
        },
      });

    const [firstRefresh, secondRefresh] = await Promise.all([
      refreshRequest(),
      refreshRequest(),
    ]);

    assert.equal(firstRefresh.statusCode, 200);
    assert.equal(secondRefresh.statusCode, 200);
    assert.equal(
      typeof firstRefresh.json().data.accessToken,
      "string"
    );
    assert.equal(
      typeof secondRefresh.json().data.accessToken,
      "string"
    );
    assert.equal(
      getCookieHeader(firstRefresh.headers["set-cookie"]),
      getCookieHeader(secondRefresh.headers["set-cookie"])
    );
  } finally {
    await prisma.emailOutbox.deleteMany({
      where: { to: email },
    });
    await prisma.user.deleteMany({
      where: { email },
    });
    await app.close();
    await prisma.$disconnect();
  }
});

test("login lock blocks repeated invalid credentials and resets after success", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const email = `lock-${Date.now()}@example.com`;
  const ipAddress = `203.0.113.${Date.now() % 200}`;
  const password = "StrongPass1!";
  const context = {
    ipAddress,
    userAgent: "auth-integration-test",
  };

  try {
    await prisma.loginLock.deleteMany({
      where: {
        OR: [
          { identityKey: email },
          { identityKey: ipAddress },
        ],
      },
    });
    await prisma.loginAttempt.deleteMany({
      where: { email },
    });
    await prisma.user.deleteMany({
      where: { email },
    });

    await prisma.user.create({
      data: {
        firstName: "Lock",
        lastName: "Tester",
        email,
        password: await hashPassword(password),
        emailVerifiedAt: new Date(),
      },
    });

    for (let attempt = 0; attempt < 5; attempt += 1) {
      await assert.rejects(
        () =>
          loginUser(
            {
              email,
              password: "WrongStrongPass1!",
            },
            context
          ),
        (error: unknown) =>
          error instanceof Error &&
          "code" in error &&
          error.code === "AUTH_INVALID_CREDENTIALS"
      );
    }

    await assert.rejects(
      () =>
        loginUser(
          {
            email,
            password,
          },
          context
        ),
      (error: unknown) =>
        error instanceof Error &&
        "code" in error &&
        error.code === "AUTH_TOO_MANY_ATTEMPTS"
    );

    await prisma.loginLock.updateMany({
      where: {
        OR: [
          { identityKey: email },
          { identityKey: ipAddress },
        ],
      },
      data: {
        lockedUntil: null,
      },
    });

    await loginUser(
      {
        email,
        password,
      },
      context
    );

    const locks = await prisma.loginLock.findMany({
      where: {
        OR: [
          { identityKey: email },
          { identityKey: ipAddress },
        ],
      },
    });

    assert.equal(locks.every((lock) => lock.failedCount === 0), true);
    assert.equal(locks.every((lock) => lock.lockedUntil === null), true);
  } finally {
    await prisma.loginLock.deleteMany({
      where: {
        OR: [
          { identityKey: email },
          { identityKey: ipAddress },
        ],
      },
    });
    await prisma.loginAttempt.deleteMany({
      where: { email },
    });
    await prisma.user.deleteMany({
      where: { email },
    });
    await prisma.$disconnect();
  }
});

test("email outbox marks sent_unknown when sent state cannot be persisted", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const to = `sent-unknown-${Date.now()}@example.com`;
  const queued = await enqueueEmail(prisma, {
    to,
    subject: "Sent unknown test",
    text: "Body",
    html: "<p>Body</p>",
  });
  const originalUpdateMany = prisma.emailOutbox.updateMany.bind(
    prisma.emailOutbox
  );
  let updateManyCalls = 0;

  prisma.emailOutbox.updateMany = (async (args) => {
    updateManyCalls += 1;

    if (updateManyCalls === 2) {
      throw new Error("Simulated SENT persistence failure");
    }

    return originalUpdateMany(args);
  }) as typeof prisma.emailOutbox.updateMany;

  try {
    await processQueuedEmail(queued.id, "integration-test");

    const email = await prisma.emailOutbox.findUniqueOrThrow({
      where: { id: queued.id },
    });

    assert.equal(email.status, "SENT_UNKNOWN");
    assert.equal(email.lastErrorSource, "PERSISTENCE");
    assert.equal(email.providerMessageId, queued.messageId);
    assert.equal(email.sentUnknownAt instanceof Date, true);
  } finally {
    prisma.emailOutbox.updateMany = originalUpdateMany;
    await prisma.emailOutbox.deleteMany({
      where: { to },
    });
    await prisma.$disconnect();
  }
});

test("email outbox legacy encryption scrubs sent rows and rotates pending rows", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const sentTo = `legacy-sent-${Date.now()}@example.com`;
  const pendingTo = `legacy-pending-${Date.now()}@example.com`;
  const rotationTo = `rotation-${Date.now()}@example.com`;
  const secret = "legacy-token-value";

  try {
    await prisma.emailOutbox.create({
      data: {
        messageId: `<legacy-sent-${Date.now()}@example.com>`,
        idempotencyKey: `legacy-sent-${Date.now()}`,
        to: sentTo,
        subject: "Legacy sent",
        text: `sensitive ${secret}`,
        html: `<p>sensitive ${secret}</p>`,
        status: "SENT",
        sentAt: new Date(),
      },
    });
    await prisma.emailOutbox.create({
      data: {
        messageId: `<legacy-pending-${Date.now()}@example.com>`,
        idempotencyKey: `legacy-pending-${Date.now()}`,
        to: pendingTo,
        subject: "Legacy pending",
        text: `pending ${secret}`,
        html: `<p>pending ${secret}</p>`,
        status: "PENDING",
      },
    });
    const rotationQueued = await enqueueEmail(prisma, {
      to: rotationTo,
      subject: "Rotation",
      text: `rotate ${secret}`,
      html: `<p>rotate ${secret}</p>`,
    });

    await prisma.emailOutbox.update({
      where: { id: rotationQueued.id },
      data: {
        encryptionKeyId: "old-key",
      },
    });

    const legacyResult = await encryptLegacyEmailOutboxBatch(50);
    const rotationResult = await rotateEmailOutboxEncryptionBatch(50);

    assert.equal(legacyResult.scrubbedSent >= 1, true);
    assert.equal(legacyResult.encryptedPendingOrFailed >= 1, true);
    assert.equal(rotationResult.rotated >= 1, true);

    const sent = await prisma.emailOutbox.findFirstOrThrow({
      where: { to: sentTo },
    });
    const pending = await prisma.emailOutbox.findFirstOrThrow({
      where: { to: pendingTo },
    });
    const rotated = await prisma.emailOutbox.findUniqueOrThrow({
      where: { id: rotationQueued.id },
    });

    assert.equal(sent.text, SCRUBBED_EMAIL_BODY);
    assert.equal(sent.html, SCRUBBED_EMAIL_BODY);
    assert.equal(pending.text.includes(secret), false);
    assert.equal(pending.html.includes(secret), false);
    assert.equal(pending.encryptionKeyId, "local-dev");
    assert.equal(rotated.encryptionKeyId, "local-dev");
    assert.equal(
      decryptEmailMessageFromStorage(pending).text,
      `pending ${secret}`
    );
  } finally {
    await prisma.emailOutbox.deleteMany({
      where: {
        to: {
          in: [sentTo, pendingTo, rotationTo],
        },
      },
    });
    await prisma.$disconnect();
  }
});
