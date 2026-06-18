process.env.NODE_ENV ??= "test";
process.env.DATABASE_URL ??=
  "postgresql://postgres:postgres@localhost:5432/erp_saas_test";
process.env.JWT_ACCESS_SECRET ??=
  "test_access_secret_minimum_32_characters";
process.env.PASSWORD_PEPPER_KEY_ID ??= "test-pepper";
process.env.PASSWORD_PEPPER ??=
  "test_password_pepper_minimum_32_chars";
process.env.PASSWORD_PEPPER_KEYS ??= JSON.stringify({
  "test-pepper": "test_password_pepper_minimum_32_chars",
  "old-pepper": "old_password_pepper_minimum_32_chars",
});
process.env.TOKEN_HASH_SECRET_KEY_ID ??= "test-token-key";
process.env.TOKEN_HASH_SECRET ??=
  "test_token_hash_secret_minimum_32_chars";
process.env.TOKEN_HASH_SECRET_KEYS ??= JSON.stringify({
  "test-token-key": "test_token_hash_secret_minimum_32_chars",
  "old-token-key": "old_token_hash_secret_minimum_32_chars",
});
process.env.REFRESH_IDEMPOTENCY_SECRET ??=
  "test_refresh_idempotency_secret_minimum_32_chars";
process.env.CSRF_SECRET ??=
  "test_csrf_secret_minimum_32_characters";
process.env.EMAIL_OUTBOX_ENCRYPTION_KEY_ID ??= "test-email-key";
process.env.EMAIL_OUTBOX_ENCRYPTION_KEY ??=
  "test_email_outbox_encryption_key_minimum_32_chars";
process.env.EMAIL_OUTBOX_ENCRYPTION_KEYS ??= JSON.stringify({
  "test-email-key": "test_email_outbox_encryption_key_minimum_32_chars",
  "old-email-key": "old_email_outbox_encryption_key_minimum_32_chars",
});
process.env.EMAIL_HTTP_API_URL ??= "https://email-provider.example.com/send";
process.env.EMAIL_HTTP_API_KEY ??= "email_provider_api_key_minimum_16";
process.env.EMAIL_HTTP_IDEMPOTENCY_HEADER ??= "Idempotency-Key";
process.env.RESEND_API_KEY ??= "re_test_api_key_minimum_16";
