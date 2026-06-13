-- Track the exact time a session was revoked for audit, cleanup, and incident
-- investigation queries.
ALTER TABLE "Session"
  ADD COLUMN "revokedAt" TIMESTAMP(3);

CREATE INDEX "Session_revokedAt_idx" ON "Session"("revokedAt");
