import assert from "node:assert/strict";
import test from "node:test";
import "../../test/setup-env";

import { buildApp } from "../../app";
import {
  activeEmailOutboxEncryptionKeyId,
  decryptEmailMessageFromStorage,
  encryptLegacyEmailOutboxBatch,
  enqueueEmail,
  processEmailOutbox,
  processQueuedEmail,
  rotateEmailOutboxEncryptionBatch,
  SCRUBBED_EMAIL_BODY,
} from "../../lib/email";
import { prisma } from "../../lib/prisma";
import { cleanupExpiredTokens } from "../../jobs/cleanupTokens";
import { runStoreOrganizationBackfill } from "../../jobs/backfillStoreOrganizations";
import { runTenantPreflight } from "../../jobs/preflightTenantMigration";
import { hashPassword } from "../../utils/hash";
import {
  loginUser,
  refreshSession,
  requestPasswordReset,
} from "./auth.service";

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
  const userAgent = "auth-integration-test";

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

    assert.equal(registerResponse.statusCode, 202);

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
        "user-agent": userAgent,
      },
      payload: {
        email,
        password,
      },
    });

    assert.equal(loginResponse.statusCode, 200);
    const loginSetCookie = loginResponse.headers["set-cookie"];
    const refreshSetCookie = Array.isArray(loginSetCookie)
      ? loginSetCookie.find((cookie) =>
          cookie.startsWith("refreshToken=")
        )
      : loginSetCookie;

    assert.equal(typeof refreshSetCookie, "string");
    assert.match(refreshSetCookie ?? "", /HttpOnly/i);
    assert.match(refreshSetCookie ?? "", /SameSite=Strict/i);
    assert.match(refreshSetCookie ?? "", /Path=\/api\/auth/i);

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

    const activeSession = await prisma.session.findFirstOrThrow({
      where: {
        user: {
          email,
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    assert.equal(activeSession.status, "ACTIVE");
    assert.equal(activeSession.deviceName, userAgent);
    assert.match(
      activeSession.deviceFingerprintHash ?? "",
      /^[a-f0-9]{64}$/
    );
    assert.equal(activeSession.lastUsedAt instanceof Date, true);
    assert.equal(activeSession.terminatedReason, null);

    const loginSecurityEvent = await prisma.securityEvent.findFirst({
      where: {
        type: "LOGIN_SUCCESS",
        user: {
          email,
        },
      },
    });

    assert.equal(Boolean(loginSecurityEvent), true);

    const refreshCookie = getCookieHeader(
      loginResponse.headers["set-cookie"]
    );
    const logoutCsrf = await getCsrf(app);
    const logoutCookie = [refreshCookie, logoutCsrf.cookie]
      .filter(Boolean)
      .join("; ");
    const logoutResponse = await app.inject({
      method: "POST",
      url: "/api/auth/logout",
      headers: {
        cookie: logoutCookie,
        "x-csrf-token": logoutCsrf.csrfToken,
        "user-agent": userAgent,
      },
    });

    assert.equal(logoutResponse.statusCode, 200);

    const loggedOutSession =
      await prisma.session.findUniqueOrThrow({
        where: {
          id: activeSession.id,
        },
      });

    assert.equal(loggedOutSession.status, "REVOKED");
    assert.equal(loggedOutSession.terminatedReason, "LOGOUT");
    assert.equal(loggedOutSession.terminatedBy, activeSession.userId);
    assert.equal(loggedOutSession.terminatedAt instanceof Date, true);
    assert.equal(loggedOutSession.revokedAt instanceof Date, true);
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

    assert.equal(registerResponse.statusCode, 202);

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

    assert.equal(registerResponse.statusCode, 202);

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

test("refresh grace is denied when historical session context is incomplete", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const email = `refresh-context-${Date.now()}@example.com`;
  const password = "StrongPass1!";

  try {
    await prisma.user.deleteMany({
      where: { email },
    });

    await prisma.user.create({
      data: {
        firstName: "Refresh",
        lastName: "Context",
        email,
        password: await hashPassword(password),
        emailVerifiedAt: new Date(),
      },
    });

    const login = await loginUser({
      email,
      password,
    });

    await refreshSession(login.refreshToken, {
      ipAddress: "203.0.113.10",
      userAgent: "strict-refresh-test",
    });

    await assert.rejects(
      () =>
        refreshSession(login.refreshToken, {
          ipAddress: "203.0.113.10",
          userAgent: "strict-refresh-test",
        }),
      (error: unknown) =>
        error instanceof Error &&
        "code" in error &&
        error.code === "AUTH_REFRESH_TOKEN_REUSED"
    );
  } finally {
    await prisma.user.deleteMany({
      where: { email },
    });
    await prisma.$disconnect();
  }
});

test("forgot password durable action limit blocks repeated email attempts", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const email = `forgot-limit-${Date.now()}@example.com`;

  try {
    await prisma.authActionRateLimit.deleteMany({
      where: {
        identityKey: email,
      },
    });

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const result = await requestPasswordReset({ email });
      assert.equal(result.resetToken, null);
    }

    await assert.rejects(
      () => requestPasswordReset({ email }),
      (error: unknown) =>
        error instanceof Error &&
        "code" in error &&
        error.code === "RATE_LIMIT_EXCEEDED"
    );
  } finally {
    await prisma.authActionRateLimit.deleteMany({
      where: {
        identityKey: email,
      },
    });
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
    assert.equal(
      pending.encryptionKeyId,
      activeEmailOutboxEncryptionKeyId()
    );
    assert.equal(
      rotated.encryptionKeyId,
      activeEmailOutboxEncryptionKeyId()
    );
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

test("email outbox does not blindly retry sent_unknown rows", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const to = `sent-unknown-no-retry-${Date.now()}@example.com`;

  try {
    await prisma.emailOutbox.create({
      data: {
        messageId: `<sent-unknown-no-retry-${Date.now()}@example.com>`,
        idempotencyKey: `sent-unknown-no-retry-${Date.now()}`,
        to,
        subject: "Sent unknown no retry",
        text: SCRUBBED_EMAIL_BODY,
        html: SCRUBBED_EMAIL_BODY,
        status: "SENT_UNKNOWN",
        sentUnknownAt: new Date(),
      },
    });

    await processEmailOutbox(50);
    const email = await prisma.emailOutbox.findFirstOrThrow({
      where: { to },
    });

    assert.equal(email.status, "SENT_UNKNOWN");
  } finally {
    await prisma.emailOutbox.deleteMany({
      where: { to },
    });
    await prisma.$disconnect();
  }
});

test("token cleanup expires sessions and removes stale auth state", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const email = `cleanup-${Date.now()}@example.com`;
  const now = new Date();
  const staleDate = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000);
  let userId: string | null = null;
  let sessionId: string | null = null;
  let authActionLimitId: string | null = null;
  const authTokenHash = `cleanup-auth-token-${Date.now()}`;
  const rotationPreviousId = `cleanup-prev-${Date.now()}`;

  try {
    const user = await prisma.user.create({
      data: {
        firstName: "Cleanup",
        lastName: "Tester",
        email,
        password: await hashPassword("StrongPass1!"),
        emailVerifiedAt: now,
      },
    });
    userId = user.id;

    const session = await prisma.session.create({
      data: {
        userId: user.id,
        status: "ACTIVE",
        expiresAt: new Date(now.getTime() - 60 * 1000),
      },
    });
    sessionId = session.id;

    await prisma.authToken.create({
      data: {
        tokenHash: authTokenHash,
        purpose: "PASSWORD_RESET",
        userId: user.id,
        expiresAt: new Date(now.getTime() - 60 * 1000),
      },
    });

    const rateLimit = await prisma.authActionRateLimit.create({
      data: {
        action: "FORGOT_PASSWORD",
        identityKey: email,
        attempts: 10,
        windowStartedAt: staleDate,
        lockedUntil: staleDate,
        updatedAt: staleDate,
      },
    });
    authActionLimitId = rateLimit.id;

    await prisma.refreshRotation.create({
      data: {
        previousRefreshTokenId: rotationPreviousId,
        rotatedRefreshTokenId: `cleanup-next-${Date.now()}`,
        sessionId: session.id,
        familyId: `cleanup-family-${Date.now()}`,
        contextHash: "cleanup-context",
        responseRefreshToken: "encrypted-refresh-token",
        idempotencyExpiresAt: new Date(now.getTime() - 60 * 1000),
      },
    });

    const result = await cleanupExpiredTokens();

    assert.equal(result.expiredSessions >= 1, true);
    assert.equal(result.authTokens >= 1, true);
    assert.equal(result.authActionRateLimits >= 1, true);
    assert.equal(result.refreshIdempotencyResponses >= 1, true);

    const expiredSession = await prisma.session.findUniqueOrThrow({
      where: { id: session.id },
    });
    const deletedAuthToken = await prisma.authToken.findUnique({
      where: { tokenHash: authTokenHash },
    });
    const deletedRateLimit =
      await prisma.authActionRateLimit.findUnique({
        where: { id: rateLimit.id },
      });
    const scrubbedRotation =
      await prisma.refreshRotation.findUniqueOrThrow({
        where: { previousRefreshTokenId: rotationPreviousId },
      });

    assert.equal(expiredSession.status, "EXPIRED");
    assert.equal(expiredSession.terminatedReason, "SESSION_EXPIRED");
    assert.equal(deletedAuthToken, null);
    assert.equal(deletedRateLimit, null);
    assert.equal(scrubbedRotation.responseRefreshToken, null);
  } finally {
    await prisma.refreshRotation.deleteMany({
      where: { previousRefreshTokenId: rotationPreviousId },
    });
    if (authActionLimitId) {
      await prisma.authActionRateLimit.deleteMany({
        where: { id: authActionLimitId },
      });
    }
    if (sessionId) {
      await prisma.session.deleteMany({
        where: { id: sessionId },
      });
    }
    if (userId) {
      await prisma.user.deleteMany({
        where: { id: userId },
      });
    }
    await prisma.$disconnect();
  }
});

test("ApiKey owner XOR constraint rejects ambiguous ownership", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const suffix = Date.now();
  const email = `apikey-xor-${suffix}@example.com`;
  let userId: string | null = null;
  let organizationId: string | null = null;

  try {
    const user = await prisma.user.create({
      data: {
        firstName: "Api",
        lastName: "Key",
        email,
        password: await hashPassword("StrongPass1!"),
        emailVerifiedAt: new Date(),
      },
    });
    userId = user.id;

    const organization = await prisma.organization.create({
      data: {
        name: "ApiKey XOR Organization",
        code: `APIKEY_XOR_${suffix}`,
      },
    });
    organizationId = organization.id;

    await assert.rejects(() =>
      prisma.apiKey.create({
        data: {
          userId: user.id,
          organizationId: organization.id,
          name: "Ambiguous key",
          keyHash: `ambiguous-${suffix}`,
          keyPrefix: "ambiguous",
        },
      })
    );
  } finally {
    await prisma.apiKey.deleteMany({
      where: {
        OR: [
          { userId: userId ?? undefined },
          { organizationId: organizationId ?? undefined },
        ],
      },
    });
    if (organizationId) {
      await prisma.organization.deleteMany({
        where: { id: organizationId },
      });
    }
    if (userId) {
      await prisma.user.deleteMany({
        where: { id: userId },
      });
    }
    await prisma.$disconnect();
  }
});

test("tenant preflight fails on null store organization and passes after backfill", async (t) => {
  if (process.env.RUN_DB_TESTS !== "true") {
    t.skip("Set RUN_DB_TESTS=true with a test DATABASE_URL");
    return;
  }

  const suffix = Date.now();
  const organizationCode = `TENANT_ORG_${suffix}`;
  const storeCode = `TENANT_STORE_${suffix}`;
  const storeId = `tenant_store_${suffix}`;
  let organizationId: string | null = null;

  try {
    await prisma.$executeRaw`
      ALTER TABLE "Store" ALTER COLUMN "organizationId" DROP NOT NULL
    `;

    const organization = await prisma.organization.create({
      data: {
        name: "Tenant Test Organization",
        code: organizationCode,
      },
    });
    organizationId = organization.id;

    await prisma.$executeRaw`
      INSERT INTO "Store" (
        "id",
        "name",
        "code",
        "isActive",
        "createdAt",
        "updatedAt"
      )
      VALUES (
        ${storeId},
        'Tenant Test Store',
        ${storeCode},
        true,
        NOW(),
        NOW()
      )
    `;

    const failedPreflight = await runTenantPreflight();

    assert.equal(failedPreflight.ok, false);
    if (failedPreflight.ok) {
      throw new Error("Tenant preflight unexpectedly passed");
    }

    assert.equal(
      failedPreflight.reason,
      "stores_without_organization"
    );

    await assert.rejects(() =>
      runStoreOrganizationBackfill({
        UNKNOWN_STORE: organizationCode,
      })
    );
    await assert.rejects(() =>
      runStoreOrganizationBackfill({
        [storeCode]: "UNKNOWN_ORGANIZATION",
      })
    );

    const backfillResult = await runStoreOrganizationBackfill({
      [storeCode]: organizationCode,
    });
    const passedPreflight = await runTenantPreflight();

    assert.equal(backfillResult.updated, 1);
    assert.equal(backfillResult.remaining, 0);
    assert.equal(passedPreflight.ok, true);
  } finally {
    await prisma.store.deleteMany({
      where: { code: storeCode },
    });

    if (organizationId) {
      await prisma.organization.deleteMany({
        where: { id: organizationId },
      });
    }

    await prisma.$executeRaw`
      ALTER TABLE "Store" ALTER COLUMN "organizationId" SET NOT NULL
    `;
    await prisma.$disconnect();
  }
});
