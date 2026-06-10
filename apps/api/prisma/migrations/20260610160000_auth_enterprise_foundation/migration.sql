-- Enterprise auth foundation: security events, API keys, MFA skeleton, and
-- password history for strong password reuse policies.
CREATE TYPE "SecurityEventType" AS ENUM (
  'REGISTER',
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'LOGOUT',
  'REFRESH_TOKEN',
  'TOKEN_REUSE_DETECTED',
  'ACCESS_DENIED',
  'EMAIL_VERIFICATION_REQUESTED',
  'EMAIL_VERIFIED',
  'PASSWORD_RESET_REQUESTED',
  'PASSWORD_RESET_COMPLETED',
  'PASSWORD_CHANGED',
  'ACCOUNT_LOCKOUT',
  'API_KEY_AUTHENTICATED',
  'MFA_CHALLENGE_CREATED',
  'MFA_CHALLENGE_VERIFIED'
);

CREATE TYPE "SecurityEventSeverity" AS ENUM (
  'INFO',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL'
);

CREATE TYPE "ApiKeyStatus" AS ENUM (
  'ACTIVE',
  'REVOKED',
  'EXPIRED'
);

CREATE TYPE "MfaFactorType" AS ENUM (
  'TOTP',
  'WEBAUTHN',
  'RECOVERY_CODE'
);

CREATE TYPE "MfaFactorStatus" AS ENUM (
  'PENDING',
  'ACTIVE',
  'DISABLED'
);

CREATE TYPE "MfaChallengeStatus" AS ENUM (
  'PENDING',
  'VERIFIED',
  'EXPIRED',
  'FAILED'
);

CREATE TABLE "PasswordHistory" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "passwordHash" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "PasswordHistory_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "SecurityEvent" (
  "id" TEXT NOT NULL,
  "userId" TEXT,
  "type" "SecurityEventType" NOT NULL,
  "severity" "SecurityEventSeverity" NOT NULL DEFAULT 'INFO',
  "ipAddress" TEXT,
  "userAgent" TEXT,
  "correlationId" TEXT,
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "SecurityEvent_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ApiKey" (
  "id" TEXT NOT NULL,
  "userId" TEXT,
  "organizationId" TEXT,
  "name" TEXT NOT NULL,
  "keyHash" TEXT NOT NULL,
  "keyPrefix" TEXT NOT NULL,
  "scopes" JSONB,
  "status" "ApiKeyStatus" NOT NULL DEFAULT 'ACTIVE',
  "lastUsedAt" TIMESTAMP(3),
  "expiresAt" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "ApiKey_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ApiKey_owner_check" CHECK (
    "userId" IS NOT NULL OR "organizationId" IS NOT NULL
  )
);

CREATE TABLE "MfaFactor" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "type" "MfaFactorType" NOT NULL,
  "status" "MfaFactorStatus" NOT NULL DEFAULT 'PENDING',
  "label" TEXT,
  "secretHash" TEXT,
  "publicKey" TEXT,
  "lastUsedAt" TIMESTAMP(3),
  "disabledAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "MfaFactor_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "MfaChallenge" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "factorId" TEXT,
  "type" "MfaFactorType" NOT NULL,
  "status" "MfaChallengeStatus" NOT NULL DEFAULT 'PENDING',
  "challengeHash" TEXT,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "verifiedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "MfaChallenge_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ApiKey_keyHash_key" ON "ApiKey"("keyHash");

CREATE INDEX "PasswordHistory_userId_createdAt_idx"
  ON "PasswordHistory"("userId", "createdAt");
CREATE INDEX "SecurityEvent_userId_idx" ON "SecurityEvent"("userId");
CREATE INDEX "SecurityEvent_type_idx" ON "SecurityEvent"("type");
CREATE INDEX "SecurityEvent_severity_idx" ON "SecurityEvent"("severity");
CREATE INDEX "SecurityEvent_correlationId_idx" ON "SecurityEvent"("correlationId");
CREATE INDEX "SecurityEvent_createdAt_idx" ON "SecurityEvent"("createdAt");
CREATE INDEX "ApiKey_userId_idx" ON "ApiKey"("userId");
CREATE INDEX "ApiKey_organizationId_idx" ON "ApiKey"("organizationId");
CREATE INDEX "ApiKey_keyPrefix_idx" ON "ApiKey"("keyPrefix");
CREATE INDEX "ApiKey_status_expiresAt_idx" ON "ApiKey"("status", "expiresAt");
CREATE INDEX "MfaFactor_userId_idx" ON "MfaFactor"("userId");
CREATE INDEX "MfaFactor_type_idx" ON "MfaFactor"("type");
CREATE INDEX "MfaFactor_status_idx" ON "MfaFactor"("status");
CREATE INDEX "MfaChallenge_userId_idx" ON "MfaChallenge"("userId");
CREATE INDEX "MfaChallenge_factorId_idx" ON "MfaChallenge"("factorId");
CREATE INDEX "MfaChallenge_status_expiresAt_idx"
  ON "MfaChallenge"("status", "expiresAt");

ALTER TABLE "PasswordHistory"
  ADD CONSTRAINT "PasswordHistory_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SecurityEvent"
  ADD CONSTRAINT "SecurityEvent_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ApiKey"
  ADD CONSTRAINT "ApiKey_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ApiKey"
  ADD CONSTRAINT "ApiKey_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "MfaFactor"
  ADD CONSTRAINT "MfaFactor_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "MfaChallenge"
  ADD CONSTRAINT "MfaChallenge_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "MfaChallenge"
  ADD CONSTRAINT "MfaChallenge_factorId_fkey"
  FOREIGN KEY ("factorId") REFERENCES "MfaFactor"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
