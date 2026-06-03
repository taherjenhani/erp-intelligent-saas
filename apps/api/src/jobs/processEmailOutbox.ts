import { processEmailOutbox } from "../lib/email";
import { prisma } from "../lib/prisma";

if (require.main === module) {
  processEmailOutbox()
    .then((count) => {
      console.log(`Processed ${count} queued emails`);
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}
