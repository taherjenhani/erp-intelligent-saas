import type { EmailOutbox, Prisma } from "@prisma/client";
import crypto from "crypto";
import nodemailer from "nodemailer";

import { env } from "../config/env";
import { prisma } from "./prisma";

type PrismaClientLike = Prisma.TransactionClient | typeof prisma;

type EmailMessage = {
  to: string;
  subject: string;
  text: string;
  html: string;
};

function buildTransport() {
  if (!env.SMTP_HOST) {
    if (env.NODE_ENV === "production") {
      throw new Error("SMTP_HOST is required in production");
    }

    return null;
  }

  return nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: env.SMTP_PORT === 465,
    auth:
      env.SMTP_USER && env.SMTP_PASS
        ? {
            user: env.SMTP_USER,
            pass: env.SMTP_PASS,
          }
        : undefined,
  });
}

async function deliverEmail(message: EmailMessage) {
  const transport = buildTransport();

  if (!transport) {
    console.info("Email delivery skipped in development", {
      to: message.to,
      subject: message.subject,
      text: message.text,
    });
    return;
  }

  await transport.sendMail({
    from: env.SMTP_FROM,
    ...message,
  });
}

function retryDelay(attempts: number) {
  const minutes = Math.min(60, 2 ** attempts);
  return new Date(Date.now() + minutes * 60 * 1000);
}

export async function recoverStaleOutboxLocks() {
  const cutoff = new Date(
    Date.now() - env.EMAIL_OUTBOX_LOCK_TIMEOUT_MS
  );

  const recovered = await prisma.emailOutbox.updateMany({
    where: {
      status: "PROCESSING",
      lockedAt: {
        lt: cutoff,
      },
    },
    data: {
      status: "PENDING",
      lockedAt: null,
      lockedBy: null,
      nextAttemptAt: new Date(),
      lastError: "Recovered stale processing lock",
    },
  });

  return recovered.count;
}

async function claimOutboxEmail(id: string, workerId: string) {
  const claimed = await prisma.emailOutbox.updateMany({
    where: {
      id,
      status: "PENDING",
      nextAttemptAt: {
        lte: new Date(),
      },
    },
    data: {
      status: "PROCESSING",
      lockedAt: new Date(),
      lockedBy: workerId,
    },
  });

  if (claimed.count !== 1) {
    return null;
  }

  return prisma.emailOutbox.findUnique({
    where: { id },
  });
}

async function deliverOutboxEmail(email: EmailOutbox) {
  const lockOwner = email.lockedBy;

  if (!lockOwner) {
    return;
  }

  try {
    await deliverEmail(email);

    await prisma.emailOutbox.updateMany({
      where: {
        id: email.id,
        status: "PROCESSING",
        lockedBy: lockOwner,
      },
      data: {
        status: "SENT",
        sentAt: new Date(),
        lastError: null,
        lockedAt: null,
        lockedBy: null,
      },
    });
  } catch (error) {
    const attempts = email.attempts + 1;

    await prisma.emailOutbox.updateMany({
      where: {
        id: email.id,
        status: "PROCESSING",
        lockedBy: lockOwner,
      },
      data: {
        status: attempts >= 5 ? "FAILED" : "PENDING",
        attempts,
        lastError:
          error instanceof Error ? error.message : "Unknown error",
        nextAttemptAt: retryDelay(attempts),
        lockedAt: null,
        lockedBy: null,
      },
    });

    console.error("Email delivery failed", error);
  }
}

async function claimAndDeliverOutboxEmail(
  id: string,
  workerId: string
) {
  const email = await claimOutboxEmail(id, workerId);

  if (!email) {
    return false;
  }

  await deliverOutboxEmail(email);
  return true;
}

export async function enqueueEmail(
  client: PrismaClientLike,
  message: EmailMessage
) {
  return client.emailOutbox.create({
    data: message,
    select: {
      id: true,
    },
  });
}

export function processQueuedEmail(id: string, workerId = "inline") {
  return claimAndDeliverOutboxEmail(id, workerId);
}

export async function processEmailOutbox(limit = env.EMAIL_OUTBOX_BATCH_SIZE) {
  const workerId = `worker-${crypto.randomUUID()}`;

  await recoverStaleOutboxLocks();

  const emails = await prisma.emailOutbox.findMany({
    where: {
      status: "PENDING",
      nextAttemptAt: {
        lte: new Date(),
      },
    },
    orderBy: {
      createdAt: "asc",
    },
    take: limit,
  });

  let processed = 0;

  for (const email of emails) {
    if (await claimAndDeliverOutboxEmail(email.id, workerId)) {
      processed += 1;
    }
  }

  return processed;
}

export function buildEmailVerificationMessage(
  to: string,
  token: string
): EmailMessage {
  const url = `${env.APP_URL}/verify-email?token=${encodeURIComponent(
    token
  )}`;

  return {
    to,
    subject: "Verify your email address",
    text: `Verify your email address: ${url}`,
    html: `<p>Verify your email address:</p><p><a href="${url}">${url}</a></p>`,
  };
}

export function buildPasswordResetMessage(
  to: string,
  token: string
): EmailMessage {
  const url = `${env.APP_URL}/reset-password?token=${encodeURIComponent(
    token
  )}`;

  return {
    to,
    subject: "Reset your password",
    text: `Reset your password: ${url}`,
    html: `<p>Reset your password:</p><p><a href="${url}">${url}</a></p>`,
  };
}
