-- Add explicit session lifecycle and device audit metadata.
CREATE TYPE "SessionTerminationReason" AS ENUM (
  'LOGOUT',
  'LOGOUT_ALL',
  'PASSWORD_RESET',
  'PASSWORD_CHANGED',
  'REFRESH_TOKEN_REUSE',
  'SESSION_EXPIRED',
  'ADMIN_REVOKED'
);

ALTER TABLE "Session"
ADD COLUMN "lastUsedAt" TIMESTAMP(3),
ADD COLUMN "terminatedAt" TIMESTAMP(3),
ADD COLUMN "terminatedBy" TEXT,
ADD COLUMN "terminatedReason" "SessionTerminationReason",
ADD COLUMN "deviceName" TEXT,
ADD COLUMN "deviceFingerprintHash" TEXT;

UPDATE "Session"
SET "lastUsedAt" = "createdAt"
WHERE "lastUsedAt" IS NULL;

CREATE INDEX "Session_lastUsedAt_idx" ON "Session"("lastUsedAt");
CREATE INDEX "Session_terminatedAt_idx" ON "Session"("terminatedAt");
CREATE INDEX "Session_deviceFingerprintHash_idx" ON "Session"("deviceFingerprintHash");
