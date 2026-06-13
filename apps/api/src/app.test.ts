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
