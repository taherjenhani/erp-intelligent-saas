import { rotateEmailOutboxEncryptionBatch } from "../lib/email";
import { prisma } from "../lib/prisma";

const limit = Number(process.argv[2] ?? 100);

rotateEmailOutboxEncryptionBatch(limit)
  .then((result) => {
    console.log("Email outbox key rotation completed", result);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
