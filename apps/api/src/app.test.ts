import assert from "node:assert/strict";
import test from "node:test";

import { buildApp } from "./app";

test("GET / returns the API health message", async () => {
  const app = buildApp();

  try {
    const response = await app.inject({
      method: "GET",
      url: "/",
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      message: "ERP API running",
    });
  } finally {
    await app.close();
  }
});
