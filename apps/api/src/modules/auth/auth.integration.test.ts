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
    await prisma.user.deleteMany({
      where: { email },
    });
    await app.close();
    await prisma.$disconnect();
  }
});
