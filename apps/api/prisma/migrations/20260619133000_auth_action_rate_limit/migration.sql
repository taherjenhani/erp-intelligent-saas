CREATE TYPE "AuthActionRateLimitAction" AS ENUM (
  'FORGOT_PASSWORD',
  'RESEND_VERIFICATION',
  'REGISTER_IP'
);

CREATE TABLE "AuthActionRateLimit" (
  "id" TEXT NOT NULL,
  "action" "AuthActionRateLimitAction" NOT NULL,
  "identityKey" TEXT NOT NULL,
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "windowStartedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lockedUntil" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "AuthActionRateLimit_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "AuthActionRateLimit_action_identityKey_key"
ON "AuthActionRateLimit"("action", "identityKey");

CREATE INDEX "AuthActionRateLimit_action_windowStartedAt_idx"
ON "AuthActionRateLimit"("action", "windowStartedAt");

CREATE INDEX "AuthActionRateLimit_lockedUntil_idx"
ON "AuthActionRateLimit"("lockedUntil");
