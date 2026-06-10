-- Add explicit state for emails that were sent by SMTP but could not be
-- persisted as SENT. These rows must be reviewed before retrying.
ALTER TYPE "EmailStatus" ADD VALUE 'SENT_UNKNOWN';

-- Add login lock identities for progressive brute-force protection.
CREATE TYPE "LoginLockIdentityType" AS ENUM ('EMAIL', 'IP');

-- Email outbox operational hardening.
ALTER TABLE "EmailOutbox"
  ADD COLUMN "messageId" TEXT,
  ADD COLUMN "lastErrorSource" TEXT,
  ADD COLUMN "providerMessageId" TEXT,
  ADD COLUMN "encryptionKeyId" TEXT,
  ADD COLUMN "sentUnknownAt" TIMESTAMP(3),
  ADD COLUMN "encryptedAt" TIMESTAMP(3),
  ADD COLUMN "scrubbedAt" TIMESTAMP(3);

UPDATE "EmailOutbox"
SET "messageId" = '<legacy-' || "id" || '@outbox.local>'
WHERE "messageId" IS NULL;

ALTER TABLE "EmailOutbox" ALTER COLUMN "messageId" SET NOT NULL;

CREATE UNIQUE INDEX "EmailOutbox_messageId_key" ON "EmailOutbox"("messageId");
CREATE INDEX "EmailOutbox_encryptionKeyId_idx" ON "EmailOutbox"("encryptionKeyId");

-- Audit correlation IDs should be searchable without scanning JSON metadata.
ALTER TABLE "AuditLog" ADD COLUMN "correlationId" TEXT;

UPDATE "AuditLog"
SET "correlationId" = "metadata"::jsonb ->> 'correlationId'
WHERE "metadata" IS NOT NULL
  AND "metadata"::jsonb ? 'correlationId';

CREATE INDEX "AuditLog_correlationId_idx" ON "AuditLog"("correlationId");

-- Refresh rotation records make concurrent refresh handling observable and
-- allow the service to treat duplicate same-context replays without revoking
-- a legitimate token family.
CREATE TABLE "RefreshRotation" (
  "id" TEXT NOT NULL,
  "previousRefreshTokenId" TEXT NOT NULL,
  "rotatedRefreshTokenId" TEXT NOT NULL,
  "sessionId" TEXT NOT NULL,
  "familyId" TEXT NOT NULL,
  "contextHash" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "RefreshRotation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "RefreshRotation_previousRefreshTokenId_key"
  ON "RefreshRotation"("previousRefreshTokenId");
CREATE INDEX "RefreshRotation_familyId_idx" ON "RefreshRotation"("familyId");
CREATE INDEX "RefreshRotation_sessionId_idx" ON "RefreshRotation"("sessionId");
CREATE INDEX "RefreshRotation_contextHash_createdAt_idx"
  ON "RefreshRotation"("contextHash", "createdAt");

-- Atomic login lock state complements the append-only LoginAttempt audit trail.
CREATE TABLE "LoginLock" (
  "id" TEXT NOT NULL,
  "identityType" "LoginLockIdentityType" NOT NULL,
  "identityKey" TEXT NOT NULL,
  "failedCount" INTEGER NOT NULL DEFAULT 0,
  "lockedUntil" TIMESTAMP(3),
  "lastFailureAt" TIMESTAMP(3),
  "lastSuccessAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "LoginLock_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "LoginLock_identityType_identityKey_key"
  ON "LoginLock"("identityType", "identityKey");
CREATE INDEX "LoginLock_lockedUntil_idx" ON "LoginLock"("lockedUntil");
CREATE INDEX "LoginLock_identityType_lockedUntil_idx"
  ON "LoginLock"("identityType", "lockedUntil");
