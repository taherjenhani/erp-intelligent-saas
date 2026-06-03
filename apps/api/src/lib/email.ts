import type { EmailOutbox } from "@prisma/client";
import nodemailer from "nodemailer";

import { env } from "../config/env";
import { prisma } from "./prisma";

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

async function deliverOutboxEmail(email: EmailOutbox) {
  try {
    await deliverEmail(email);

    await prisma.emailOutbox.update({
      where: {
        id: email.id,
      },
      data: {
        status: "SENT",
        sentAt: new Date(),
        lastError: null,
      },
    });
  } catch (error) {
    const attempts = email.attempts + 1;

    await prisma.emailOutbox.update({
      where: {
        id: email.id,
      },
      data: {
        status: attempts >= 5 ? "FAILED" : "PENDING",
        attempts,
        lastError:
          error instanceof Error ? error.message : "Unknown error",
        nextAttemptAt: retryDelay(attempts),
      },
    });

    console.error("Email delivery failed", error);
  }
}

async function enqueueEmail(message: EmailMessage) {
  try {
    const email = await prisma.emailOutbox.create({
      data: message,
    });

    void deliverOutboxEmail(email);
  } catch (error) {
    console.error("Email enqueue failed", error);
  }
}

export async function processEmailOutbox(limit = env.EMAIL_OUTBOX_BATCH_SIZE) {
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

  for (const email of emails) {
    await deliverOutboxEmail(email);
  }

  return emails.length;
}

export async function sendEmailVerification(
  to: string,
  token: string
) {
  const url = `${env.APP_URL}/verify-email?token=${encodeURIComponent(
    token
  )}`;

  await enqueueEmail({
    to,
    subject: "Verify your email address",
    text: `Verify your email address: ${url}`,
    html: `<p>Verify your email address:</p><p><a href="${url}">${url}</a></p>`,
  });
}

export async function sendPasswordReset(
  to: string,
  token: string
) {
  const url = `${env.APP_URL}/reset-password?token=${encodeURIComponent(
    token
  )}`;

  await enqueueEmail({
    to,
    subject: "Reset your password",
    text: `Reset your password: ${url}`,
    html: `<p>Reset your password:</p><p><a href="${url}">${url}</a></p>`,
  });
}
