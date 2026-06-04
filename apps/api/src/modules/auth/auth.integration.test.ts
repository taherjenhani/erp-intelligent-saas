import assert from "node:assert/strict";
import test from "node:test";

import { buildApp } from "../../app";
import { prisma } from "../../lib/prisma";

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

    const refreshRequest = () =>
      app.inject({
        method: "POST",
        url: "/api/auth/refresh",
        headers: {
          cookie,
          "x-csrf-token": refreshCsrf.csrfToken,
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
