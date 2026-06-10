import {
  encryptLegacyEmailOutboxBatch,
} from "../lib/email";
import { prisma } from "../lib/prisma";

const limit = Number(process.argv[2] ?? 100);

encryptLegacyEmailOutboxBatch(limit)
  .then((result) => {
    console.log("Email outbox legacy encryption completed", result);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
