-- Persist short-lived refresh idempotency responses so a client retry with the
-- same Idempotency-Key can receive the same rotated refresh token.
ALTER TABLE "RefreshRotation"
  ADD COLUMN "idempotencyKeyHash" TEXT,
  ADD COLUMN "responseRefreshToken" TEXT,
  ADD COLUMN "idempotencyExpiresAt" TIMESTAMP(3);

CREATE INDEX "RefreshRotation_previousRefreshTokenId_idempotencyKeyHash_idx"
  ON "RefreshRotation"("previousRefreshTokenId", "idempotencyKeyHash");
CREATE INDEX "RefreshRotation_idempotencyExpiresAt_idx"
  ON "RefreshRotation"("idempotencyExpiresAt");
