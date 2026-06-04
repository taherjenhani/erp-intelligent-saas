-- CreateEnum
CREATE TYPE "PlatformRole" AS ENUM ('SUPER_ADMIN', 'USER');

-- AlterEnum
ALTER TYPE "AuditAction" ADD VALUE 'EMAIL_VERIFICATION_REQUESTED';

-- AlterTable
ALTER TABLE "User" ADD COLUMN "platformRole" "PlatformRole" NOT NULL DEFAULT 'USER';

-- AlterTable
ALTER TABLE "RefreshToken" ADD COLUMN "rotatedAt" TIMESTAMP(3),
ADD COLUMN "replacedByTokenId" TEXT;

-- CreateIndex
CREATE INDEX "User_platformRole_idx" ON "User"("platformRole");

-- CreateIndex
CREATE INDEX "RefreshToken_replacedByTokenId_idx" ON "RefreshToken"("replacedByTokenId");
