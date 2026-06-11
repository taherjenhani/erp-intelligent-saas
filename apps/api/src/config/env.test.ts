import assert from "node:assert/strict";
import test from "node:test";

import { parseEnv } from "./env";

const requiredEnv = {
  DATABASE_URL: "postgresql://postgres:postgres@localhost:5432/test",
  JWT_ACCESS_SECRET: "test_access_secret_minimum_32_characters",
  PASSWORD_PEPPER: "test_password_pepper_minimum_32_chars",
  TOKEN_HASH_SECRET: "test_token_hash_secret_minimum_32_chars",
  CSRF_SECRET: "test_csrf_secret_minimum_32_characters",
};

test("parseEnv parses boolean strings explicitly", () => {
  assert.equal(
    parseEnv({
      ...requiredEnv,
      EXPOSE_AUTH_TOKENS: "false",
    }).EXPOSE_AUTH_TOKENS,
    false
  );

  assert.equal(
    parseEnv({
      ...requiredEnv,
      NODE_ENV: "test",
      EXPOSE_AUTH_TOKENS: "true",
    }).EXPOSE_AUTH_TOKENS,
    true
  );
});

test("parseEnv allows exposed auth tokens only for strict local development", () => {
  assert.equal(
    parseEnv({
      ...requiredEnv,
      NODE_ENV: "development",
      APP_URL: "http://localhost:3000",
      CORS_ORIGIN: "http://localhost:3000,http://127.0.0.1:3000",
      EXPOSE_AUTH_TOKENS: "true",
    }).EXPOSE_AUTH_TOKENS,
    true
  );
});

test("parseEnv rejects exposed auth tokens outside test or local development", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      NODE_ENV: "development",
      APP_URL: "https://staging.example.com",
      CORS_ORIGIN: "https://staging.example.com",
      EXPOSE_AUTH_TOKENS: "true",
    })
  );
});

test("parseEnv requires separate password and token secrets", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      TOKEN_HASH_SECRET: requiredEnv.PASSWORD_PEPPER,
    })
  );
});

test("parseEnv requires separate refresh idempotency secret", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      REFRESH_IDEMPOTENCY_SECRET: requiredEnv.TOKEN_HASH_SECRET,
    })
  );
});

test("parseEnv rejects local CORS origins in production", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      NODE_ENV: "production",
      APP_URL: "https://app.example.com",
      CORS_ORIGIN: "http://localhost:3000",
      SMTP_HOST: "smtp.example.com",
      RATE_LIMIT_REDIS_URL: "redis://localhost:6379",
      EMAIL_OUTBOX_ENCRYPTION_KEY:
        "production_email_outbox_encryption_key_minimum_32_chars",
      CSRF_SECRET: "production_csrf_secret_minimum_32_chars",
      TOKEN_HASH_SECRET: "production_token_hash_secret_minimum_32_chars",
    })
  );
});

test("parseEnv requires explicit email outbox encryption key in production", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      NODE_ENV: "production",
      APP_URL: "https://app.example.com",
      CORS_ORIGIN: "https://app.example.com",
      SMTP_HOST: "smtp.example.com",
      RATE_LIMIT_REDIS_URL: "redis://localhost:6379",
      CSRF_SECRET: "production_csrf_secret_minimum_32_chars",
      TOKEN_HASH_SECRET: "production_token_hash_secret_minimum_32_chars",
    })
  );
});

test("parseEnv requires metrics token when metrics are enabled", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      METRICS_ENABLED: "true",
    })
  );
});

test("parseEnv validates email outbox keyring and active key id", () => {
  const parsed = parseEnv({
    ...requiredEnv,
    EMAIL_OUTBOX_ENCRYPTION_KEY_ID: "key-2026-06",
    EMAIL_OUTBOX_ENCRYPTION_KEY:
      "active_email_outbox_key_minimum_32_chars",
    EMAIL_OUTBOX_ENCRYPTION_KEYS: JSON.stringify({
      "key-2026-06": "active_email_outbox_key_minimum_32_chars",
      "key-2026-01": "previous_email_outbox_key_minimum_32_chars",
    }),
  });

  assert.equal(parsed.EMAIL_OUTBOX_ENCRYPTION_KEY_ID, "key-2026-06");
});

test("parseEnv validates password pepper keyring and active key id", () => {
  const parsed = parseEnv({
    ...requiredEnv,
    PASSWORD_PEPPER_KEY_ID: "pepper-2026-06",
    PASSWORD_PEPPER: "active_password_pepper_minimum_32_chars",
    PASSWORD_PEPPER_KEYS: JSON.stringify({
      "pepper-2026-06": "active_password_pepper_minimum_32_chars",
      "pepper-2026-01": "previous_password_pepper_minimum_32_chars",
    }),
  });

  assert.equal(parsed.PASSWORD_PEPPER_KEY_ID, "pepper-2026-06");
});

test("parseEnv requires active password pepper keyring secret to match PASSWORD_PEPPER", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      PASSWORD_PEPPER_KEY_ID: "pepper-2026-06",
      PASSWORD_PEPPER: "active_password_pepper_minimum_32_chars",
      PASSWORD_PEPPER_KEYS: JSON.stringify({
        "pepper-2026-06": "different_password_pepper_minimum_32_chars",
      }),
    })
  );
});

test("parseEnv requires outbox heartbeat lower than lock timeout", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      EMAIL_OUTBOX_LOCK_TIMEOUT_MS: "60000",
      EMAIL_OUTBOX_LOCK_HEARTBEAT_MS: "60000",
    })
  );
});

test("parseEnv requires email provider timeout lower than outbox lock timeout", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      EMAIL_OUTBOX_LOCK_TIMEOUT_MS: "60000",
      EMAIL_PROVIDER_TIMEOUT_MS: "60000",
    })
  );
});

test("parseEnv accepts HTTP email provider with idempotency key support", () => {
  const parsed = parseEnv({
    ...requiredEnv,
    EMAIL_PROVIDER: "http",
    EMAIL_HTTP_API_URL: "https://email-provider.example.com/send",
    EMAIL_HTTP_API_KEY: "email_provider_api_key_minimum_16",
    EMAIL_HTTP_IDEMPOTENCY_HEADER: "Idempotency-Key",
  });

  assert.equal(parsed.EMAIL_PROVIDER, "http");
  assert.equal(parsed.EMAIL_HTTP_IDEMPOTENCY_HEADER, "Idempotency-Key");
});

test("parseEnv limits refresh idempotency replay TTL", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      REFRESH_IDEMPOTENCY_TTL_MS: String(10 * 60 * 1000),
    })
  );
});

test("parseEnv requires explicit SMTP best-effort opt-in in production", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      NODE_ENV: "production",
      APP_URL: "https://app.example.com",
      CORS_ORIGIN: "https://app.example.com",
      SMTP_HOST: "smtp.example.com",
      RATE_LIMIT_REDIS_URL: "redis://localhost:6379",
      EMAIL_OUTBOX_ENCRYPTION_KEY:
        "production_email_outbox_encryption_key_minimum_32_chars",
      CSRF_SECRET: "production_csrf_secret_minimum_32_chars",
      TOKEN_HASH_SECRET: "production_token_hash_secret_minimum_32_chars",
    })
  );
});

test("parseEnv allows production HTTP email provider without SMTP best-effort", () => {
  const parsed = parseEnv({
    ...requiredEnv,
    NODE_ENV: "production",
    APP_URL: "https://app.example.com",
    CORS_ORIGIN: "https://app.example.com",
    EMAIL_PROVIDER: "http",
    EMAIL_HTTP_API_URL: "https://email-provider.example.com/send",
    EMAIL_HTTP_API_KEY: "email_provider_api_key_minimum_16",
    RATE_LIMIT_REDIS_URL: "redis://localhost:6379",
    EMAIL_OUTBOX_ENCRYPTION_KEY:
      "production_email_outbox_encryption_key_minimum_32_chars",
    CSRF_SECRET: "production_csrf_secret_minimum_32_chars",
    TOKEN_HASH_SECRET: "production_token_hash_secret_minimum_32_chars",
    REFRESH_IDEMPOTENCY_SECRET:
      "production_refresh_idempotency_secret_minimum_32_chars",
    TOKEN_CLEANUP_EXTERNAL_SCHEDULED: "true",
  });

  assert.equal(parsed.EMAIL_PROVIDER, "http");
});

test("parseEnv requires production token cleanup schedule", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      NODE_ENV: "production",
      APP_URL: "https://app.example.com",
      CORS_ORIGIN: "https://app.example.com",
      EMAIL_PROVIDER: "http",
      EMAIL_HTTP_API_URL: "https://email-provider.example.com/send",
      EMAIL_HTTP_API_KEY: "email_provider_api_key_minimum_16",
      RATE_LIMIT_REDIS_URL: "redis://localhost:6379",
      EMAIL_OUTBOX_ENCRYPTION_KEY:
        "production_email_outbox_encryption_key_minimum_32_chars",
      CSRF_SECRET: "production_csrf_secret_minimum_32_chars",
      TOKEN_HASH_SECRET: "production_token_hash_secret_minimum_32_chars",
      REFRESH_IDEMPOTENCY_SECRET:
        "production_refresh_idempotency_secret_minimum_32_chars",
    })
  );
});

test("parseEnv requires CSP when serving web content in production", () => {
  assert.throws(() =>
    parseEnv({
      ...requiredEnv,
      NODE_ENV: "production",
      APP_URL: "https://app.example.com",
      CORS_ORIGIN: "https://app.example.com",
      EMAIL_PROVIDER: "http",
      EMAIL_HTTP_API_URL: "https://email-provider.example.com/send",
      EMAIL_HTTP_API_KEY: "email_provider_api_key_minimum_16",
      RATE_LIMIT_REDIS_URL: "redis://localhost:6379",
      EMAIL_OUTBOX_ENCRYPTION_KEY:
        "production_email_outbox_encryption_key_minimum_32_chars",
      CSRF_SECRET: "production_csrf_secret_minimum_32_chars",
      TOKEN_HASH_SECRET: "production_token_hash_secret_minimum_32_chars",
      REFRESH_IDEMPOTENCY_SECRET:
        "production_refresh_idempotency_secret_minimum_32_chars",
      TOKEN_CLEANUP_EXTERNAL_SCHEDULED: "true",
      SERVE_WEB_CONTENT: "true",
    })
  );
});
