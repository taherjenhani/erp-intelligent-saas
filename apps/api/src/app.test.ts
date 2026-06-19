import assert from "node:assert/strict";
import test from "node:test";
import "./test/setup-env";

import { buildApp } from "./app";

test("GET / returns the API health message", async () => {
  const app = buildApp();

  try {
    const response = await app.inject({
      method: "GET",
      url: "/",
      headers: {
        "x-correlation-id": "corr-test-123",
      },
    });

    assert.equal(response.statusCode, 200);
    assert.equal(
      response.headers["x-correlation-id"],
      "corr-test-123"
    );
    assert.equal(typeof response.headers["x-request-id"], "string");
    assert.deepEqual(response.json(), {
      message: "ERP API running",
    });
  } finally {
    await app.close();
  }
});

test("GET / ignores unsafe correlation id headers", async () => {
  const app = buildApp();

  try {
    const response = await app.inject({
      method: "GET",
      url: "/",
      headers: {
        "x-correlation-id": "x".repeat(200),
      },
    });

    assert.equal(response.statusCode, 200);
    assert.notEqual(
      response.headers["x-correlation-id"],
      "x".repeat(200)
    );
    assert.equal(typeof response.headers["x-correlation-id"], "string");
  } finally {
    await app.close();
  }
});

test("GET /healthz returns liveness status", async () => {
  const app = buildApp();

  try {
    const response = await app.inject({
      method: "GET",
      url: "/healthz",
    });

    assert.equal(response.statusCode, 200);
    assert.equal(response.json().status, "ok");
    assert.equal(typeof response.json().timestamp, "string");
  } finally {
    await app.close();
  }
});

test("GET /.well-known/jwks.json is disabled unless RS256 is configured", async () => {
  const app = buildApp();

  try {
    const response = await app.inject({
      method: "GET",
      url: "/.well-known/jwks.json",
    });

    assert.equal(response.statusCode, 404);
    assert.equal(response.json().code, "JWKS_NOT_ENABLED");
  } finally {
    await app.close();
  }
});

test("POST /api/auth/login rejects missing CSRF token with structured error", async () => {
  const app = buildApp();

  try {
    const response = await app.inject({
      method: "POST",
      url: "/api/auth/login",
      payload: {
        email: "csrf@example.com",
        password: "StrongPass1!",
      },
    });

    assert.equal(response.statusCode, 403);
    assert.equal(response.json().success, false);
    assert.equal(response.json().code, "CSRF_INVALID");
    assert.equal(typeof response.json().correlationId, "string");
  } finally {
    await app.close();
  }
});

test("state-changing auth routes reject missing CSRF token", async () => {
  const app = buildApp();
  const routes = [
    {
      url: "/api/auth/register",
      payload: {
        firstName: "Csrf",
        lastName: "Tester",
        email: "csrf-register@example.com",
        password: "StrongPass1!",
      },
    },
    {
      url: "/api/auth/verify-email",
      payload: {
        token: "a".repeat(128),
      },
    },
    {
      url: "/api/auth/resend-verification",
      payload: {
        email: "csrf-resend@example.com",
      },
    },
    {
      url: "/api/auth/forgot-password",
      payload: {
        email: "csrf-forgot@example.com",
      },
    },
    {
      url: "/api/auth/reset-password",
      payload: {
        token: "a".repeat(128),
        password: "StrongPass1!",
      },
    },
    {
      url: "/api/auth/refresh",
      payload: {},
    },
    {
      url: "/api/auth/logout",
      payload: {},
    },
    {
      url: "/api/auth/logout-all",
      payload: {},
    },
    {
      url: "/api/auth/change-password",
      payload: {
        currentPassword: "StrongPass1!",
        newPassword: "NewStrongPass1!",
      },
    },
  ];

  try {
    for (const route of routes) {
      const response = await app.inject({
        method: "POST",
        url: route.url,
        payload: route.payload,
      });

      assert.equal(response.statusCode, 403, route.url);
      assert.equal(response.json().code, "CSRF_INVALID", route.url);
    }
  } finally {
    await app.close();
  }
});

test("MFA and API key routes are not exposed by default", async () => {
  const app = buildApp();

  try {
    const mfaResponse = await app.inject({
      method: "GET",
      url: "/api/auth/mfa",
    });
    const apiKeyResponse = await app.inject({
      method: "GET",
      url: "/api/auth/api-keys",
    });

    assert.equal(mfaResponse.statusCode, 404);
    assert.equal(apiKeyResponse.statusCode, 404);
  } finally {
    await app.close();
  }
});
