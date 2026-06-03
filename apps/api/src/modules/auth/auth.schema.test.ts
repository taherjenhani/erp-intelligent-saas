import assert from "node:assert/strict";
import test from "node:test";

import {
  changePasswordSchema,
  registerSchema,
} from "./auth.schema";

test("registerSchema accepts a strong registration payload", () => {
  const parsed = registerSchema.parse({
    firstName: "Taher",
    lastName: "Jenhani",
    email: "TAHER@example.com",
    password: "StrongPass1!",
  });

  assert.equal(parsed.email, "taher@example.com");
});

test("registerSchema rejects weak passwords", () => {
  const result = registerSchema.safeParse({
    firstName: "Ta",
    lastName: "Je",
    email: "taher@example.com",
    password: "password",
  });

  assert.equal(result.success, false);
});

test("changePasswordSchema requires a different new password", () => {
  const result = changePasswordSchema.safeParse({
    currentPassword: "StrongPass1!",
    newPassword: "StrongPass1!",
  });

  assert.equal(result.success, false);
});
