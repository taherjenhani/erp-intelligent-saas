import assert from "node:assert/strict";
import test from "node:test";

import {
  changePasswordSchema,
  registerSchema,
  resetPasswordSchema,
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

test("auth schemas reject unknown fields", () => {
  const result = registerSchema.safeParse({
    firstName: "Taher",
    lastName: "Jenhani",
    email: "taher@example.com",
    password: "StrongPass1!",
    role: "SUPER_ADMIN",
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

test("resetPasswordSchema requires a 128-character hex token", () => {
  const result = resetPasswordSchema.safeParse({
    token: "a".repeat(128),
    password: "StrongPass1!",
  });

  assert.equal(result.success, true);

  const invalid = resetPasswordSchema.safeParse({
    token: "z".repeat(128),
    password: "StrongPass1!",
  });

  assert.equal(invalid.success, false);
});
