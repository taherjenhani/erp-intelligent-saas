process.env.NODE_ENV ??= "test";
process.env.DATABASE_URL ??=
  "postgresql://postgres:postgres@localhost:5432/erp_saas_test";
process.env.JWT_ACCESS_SECRET ??=
  "test_access_secret_minimum_32_characters";
process.env.PASSWORD_PEPPER_KEY_ID ??= "test-pepper";
process.env.PASSWORD_PEPPER ??=
  "test_password_pepper_minimum_32_chars";
process.env.TOKEN_HASH_SECRET ??=
  "test_token_hash_secret_minimum_32_chars";
process.env.REFRESH_IDEMPOTENCY_SECRET ??=
  "test_refresh_idempotency_secret_minimum_32_chars";
process.env.CSRF_SECRET ??=
  "test_csrf_secret_minimum_32_characters";
process.env.EMAIL_OUTBOX_ENCRYPTION_KEY_ID ??= "test-email-key";
process.env.EMAIL_OUTBOX_ENCRYPTION_KEY ??=
  "test_email_outbox_encryption_key_minimum_32_chars";
process.env.RESEND_API_KEY ??= "re_test_api_key_minimum_16";
