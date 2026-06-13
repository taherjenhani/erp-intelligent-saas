import { listSentUnknownEmailOutbox } from "../lib/email";
import { prisma } from "../lib/prisma";

async function main() {
  const limit = Number.parseInt(
    process.env.EMAIL_OUTBOX_SENT_UNKNOWN_LIMIT ?? "50",
    10
  );
  const emails = await listSentUnknownEmailOutbox(
    Number.isFinite(limit) && limit > 0 ? limit : 50
  );

  console.log(JSON.stringify({
    count: emails.length,
    emails,
  }, null, 2));
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
