import type { EmailOutbox, Prisma } from "@prisma/client";
import crypto from "crypto";
import nodemailer from "nodemailer";

import { env } from "../config/env";
import { incrementCounter, setGauge } from "./metrics";
import { prisma } from "./prisma";

type PrismaClientLike = Prisma.TransactionClient | typeof prisma;

type EmailMessage = {
  messageId?: string;
  idempotencyKey?: string;
  to: string;
  subject: string;
  text: string;
  html: string;
};

type StoredEmailMessage = EmailMessage & {
  messageId: string;
};

const ENCRYPTED_VALUE_PREFIX = "enc:v1:";
const KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;
export const SCRUBBED_EMAIL_BODY =
  "[scrubbed after successful delivery]";

function parseEmailKeyring() {
  const keys = new Map<string, string>();
  keys.set(
    env.EMAIL_OUTBOX_ENCRYPTION_KEY_ID,
    env.EMAIL_OUTBOX_ENCRYPTION_KEY
  );

  if (!env.EMAIL_OUTBOX_ENCRYPTION_KEYS) {
    return keys;
  }

  const parsed = JSON.parse(env.EMAIL_OUTBOX_ENCRYPTION_KEYS) as Record<
    string,
    string
  >;

  for (const [keyId, secret] of Object.entries(parsed)) {
    keys.set(keyId, secret);
  }

  return keys;
}

export function activeEmailOutboxEncryptionKeyId() {
  return env.EMAIL_OUTBOX_ENCRYPTION_KEY_ID;
}

function emailEncryptionKey(keyId: string) {
  const secret = parseEmailKeyring().get(keyId);

  if (!secret) {
    throw new Error(`Missing email outbox encryption key: ${keyId}`);
  }

  return crypto.createHash("sha256").update(secret).digest();
}

function parseEncryptedOutboxValue(value: string) {
  if (!value.startsWith(ENCRYPTED_VALUE_PREFIX)) {
    return null;
  }

  const body = value.slice(ENCRYPTED_VALUE_PREFIX.length);
  const separator = body.indexOf(":");

  if (separator === -1) {
    return {
      keyId: env.EMAIL_OUTBOX_ENCRYPTION_KEY_ID,
      payload: body,
      legacyPrefix: true,
    };
  }

  const keyId = body.slice(0, separator);
  const payload = body.slice(separator + 1);

  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new Error("Invalid email outbox encryption key id");
  }

  return {
    keyId,
    payload,
    legacyPrefix: false,
  };
}

export function isEncryptedOutboxValue(value: string) {
  return Boolean(parseEncryptedOutboxValue(value));
}

export function getEncryptedOutboxKeyId(value: string) {
  return parseEncryptedOutboxValue(value)?.keyId ?? null;
}

function encryptOutboxValue(
  value: string,
  keyId = activeEmailOutboxEncryptionKeyId()
) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    emailEncryptionKey(keyId),
    iv
  );
  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return `${ENCRYPTED_VALUE_PREFIX}${keyId}:${Buffer.concat([
    iv,
    tag,
    encrypted,
  ]).toString("base64url")}`;
}

function decryptOutboxValue(value: string) {
  const encryptedValue = parseEncryptedOutboxValue(value);

  if (!encryptedValue) {
    return value;
  }

  const payload = Buffer.from(encryptedValue.payload, "base64url");
  const iv = payload.subarray(0, 12);
  const tag = payload.subarray(12, 28);
  const encrypted = payload.subarray(28);
  const keyIds = encryptedValue.legacyPrefix
    ? [
        encryptedValue.keyId,
        ...Array.from(parseEmailKeyring().keys()).filter(
          (keyId) => keyId !== encryptedValue.keyId
        ),
      ]
    : [encryptedValue.keyId];
  let lastError: unknown;

  for (const keyId of keyIds) {
    try {
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        emailEncryptionKey(keyId),
        iv
      );

      decipher.setAuthTag(tag);

      return Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
      ]).toString("utf8");
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError;
}

function outboxMessageIdDomain() {
  try {
    return new URL(env.APP_URL).hostname || "erp-api.local";
  } catch {
    return "erp-api.local";
  }
}

export function createEmailMessageId() {
  return `<${crypto.randomUUID()}@${outboxMessageIdDomain()}>`;
}

export function encryptEmailMessageForStorage(message: EmailMessage) {
  const keyId = activeEmailOutboxEncryptionKeyId();

  return {
    ...message,
    text: encryptOutboxValue(message.text, keyId),
    html: encryptOutboxValue(message.html, keyId),
    encryptionKeyId: keyId,
    encryptedAt: new Date(),
  };
}

export function decryptEmailMessageFromStorage(
  email: Pick<
    EmailOutbox,
    "messageId" | "to" | "subject" | "text" | "html"
  >
): StoredEmailMessage {
  return {
    messageId: email.messageId,
    to: email.to,
    subject: email.subject,
    text: decryptOutboxValue(email.text),
    html: decryptOutboxValue(email.html),
  };
}

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

async function deliverEmail(message: StoredEmailMessage) {
  const transport = buildTransport();

  if (!transport) {
    console.info("Email delivery skipped in development", {
      messageId: message.messageId,
      to: message.to,
      subject: message.subject,
    });
    return {
      providerMessageId: message.messageId,
    };
  }

  const info = await transport.sendMail({
    from: env.SMTP_FROM,
    messageId: message.messageId,
    to: message.to,
    subject: message.subject,
    text: message.text,
    html: message.html,
  });

  return {
    providerMessageId:
      typeof info.messageId === "string"
        ? info.messageId
        : message.messageId,
  };
}

function retryDelay(attempts: number) {
  const minutes = Math.min(60, 2 ** attempts);
  return new Date(Date.now() + minutes * 60 * 1000);
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Unknown error";
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
      lastErrorSource: "LOCK_RECOVERY",
    },
  });

  if (recovered.count > 0) {
    incrementCounter(
      "erp_email_outbox_recovered_total",
      "Total stale email outbox locks recovered.",
      {},
      recovered.count
    );
  }

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
    incrementCounter(
      "erp_email_outbox_claim_total",
      "Total email outbox claim attempts by status.",
      { status: "miss" }
    );
    return null;
  }

  incrementCounter(
    "erp_email_outbox_claim_total",
    "Total email outbox claim attempts by status.",
    { status: "success" }
  );

  return prisma.emailOutbox.findUnique({
    where: { id },
  });
}

async function markDeliveryFailed(
  email: EmailOutbox,
  lockOwner: string,
  error: unknown
) {
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
      lastError: errorMessage(error),
      lastErrorSource: "SMTP",
      nextAttemptAt: retryDelay(attempts),
      lockedAt: null,
      lockedBy: null,
    },
  });

  incrementCounter(
    "erp_email_outbox_delivery_total",
    "Total email outbox delivery attempts by status.",
    { status: attempts >= 5 ? "failed_terminal" : "failed_retryable" }
  );
  console.error("Email delivery failed", error);
}

async function markDeliveryPersistenceUnknown(
  email: EmailOutbox,
  lockOwner: string,
  providerMessageId: string,
  error: unknown
) {
  try {
    await prisma.emailOutbox.updateMany({
      where: {
        id: email.id,
        status: "PROCESSING",
        lockedBy: lockOwner,
      },
      data: {
        status: "SENT_UNKNOWN",
        providerMessageId,
        sentUnknownAt: new Date(),
        lastError: errorMessage(error),
        lastErrorSource: "PERSISTENCE",
        lockedAt: null,
        lockedBy: null,
      },
    });
  } catch (persistenceError) {
    console.error(
      "Email delivery succeeded but SENT_UNKNOWN persistence failed",
      persistenceError
    );
  }

  incrementCounter(
    "erp_email_outbox_delivery_total",
    "Total email outbox delivery attempts by status.",
    { status: "sent_unknown" }
  );
  console.error("Email delivery state persistence failed", error);
}

async function deliverOutboxEmail(email: EmailOutbox) {
  const lockOwner = email.lockedBy;

  if (!lockOwner) {
    return;
  }

  let deliveryResult: Awaited<ReturnType<typeof deliverEmail>>;
  const heartbeat = setInterval(() => {
    void prisma.emailOutbox
      .updateMany({
        where: {
          id: email.id,
          status: "PROCESSING",
          lockedBy: lockOwner,
        },
        data: {
          lockedAt: new Date(),
        },
      })
      .catch((error) => {
        console.error("Email outbox heartbeat failed", error);
      });
  }, env.EMAIL_OUTBOX_LOCK_HEARTBEAT_MS);

  try {
    deliveryResult = await deliverEmail(
      decryptEmailMessageFromStorage(email)
    );
  } catch (error) {
    clearInterval(heartbeat);
    await markDeliveryFailed(email, lockOwner, error);
    return;
  }

  clearInterval(heartbeat);

  try {
    const updated = await prisma.emailOutbox.updateMany({
      where: {
        id: email.id,
        status: "PROCESSING",
        lockedBy: lockOwner,
      },
      data: {
        status: "SENT",
        sentAt: new Date(),
        providerMessageId: deliveryResult.providerMessageId,
        lastError: null,
        lastErrorSource: null,
        text: SCRUBBED_EMAIL_BODY,
        html: SCRUBBED_EMAIL_BODY,
        scrubbedAt: new Date(),
        lockedAt: null,
        lockedBy: null,
      },
    });

    if (updated.count !== 1) {
      throw new Error("Email outbox SENT update did not match a locked row");
    }

    incrementCounter(
      "erp_email_outbox_delivery_total",
      "Total email outbox delivery attempts by status.",
      { status: "success" }
    );
  } catch (error) {
    await markDeliveryPersistenceUnknown(
      email,
      lockOwner,
      deliveryResult.providerMessageId,
      error
    );
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
  const messageId = message.messageId ?? createEmailMessageId();
  const idempotencyKey = message.idempotencyKey ?? messageId;

  return client.emailOutbox.create({
    data: {
      messageId,
      idempotencyKey,
      ...encryptEmailMessageForStorage({
        ...message,
        messageId,
      }),
    },
    select: {
      id: true,
      messageId: true,
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

  setGauge(
    "erp_email_outbox_batch_size",
    "Last email outbox batch size selected for processing.",
    {},
    emails.length
  );

  let processed = 0;

  for (const email of emails) {
    if (await claimAndDeliverOutboxEmail(email.id, workerId)) {
      processed += 1;
    }
  }

  setGauge(
    "erp_email_outbox_batch_processed",
    "Last email outbox batch processed count.",
    {},
    processed
  );
  incrementCounter(
    "erp_email_outbox_processed_total",
    "Total email outbox messages processed.",
    {},
    processed
  );

  return processed;
}

export async function encryptLegacyEmailOutboxBatch(limit = 100) {
  const now = new Date();
  const scrubbedSent = await prisma.emailOutbox.updateMany({
    where: {
      status: "SENT",
      OR: [
        { text: { not: SCRUBBED_EMAIL_BODY } },
        { html: { not: SCRUBBED_EMAIL_BODY } },
      ],
    },
    data: {
      text: SCRUBBED_EMAIL_BODY,
      html: SCRUBBED_EMAIL_BODY,
      scrubbedAt: now,
    },
  });

  const emails = await prisma.emailOutbox.findMany({
    where: {
      status: {
        in: ["PENDING", "FAILED"],
      },
      encryptionKeyId: null,
    },
    orderBy: {
      createdAt: "asc",
    },
    take: limit,
  });

  let encrypted = 0;

  for (const email of emails) {
    const message = decryptEmailMessageFromStorage(email);
    const storage = encryptEmailMessageForStorage(message);
    const updated = await prisma.emailOutbox.updateMany({
      where: {
        id: email.id,
        text: email.text,
        html: email.html,
      },
      data: storage,
    });

    encrypted += updated.count;
  }

  return {
    scrubbedSent: scrubbedSent.count,
    encryptedPendingOrFailed: encrypted,
  };
}

export async function rotateEmailOutboxEncryptionBatch(limit = 100) {
  const activeKeyId = activeEmailOutboxEncryptionKeyId();
  const emails = await prisma.emailOutbox.findMany({
    where: {
      status: {
        in: ["PENDING", "FAILED", "SENT_UNKNOWN"],
      },
      OR: [
        { encryptionKeyId: null },
        { encryptionKeyId: { not: activeKeyId } },
      ],
    },
    orderBy: {
      createdAt: "asc",
    },
    take: limit,
  });

  let rotated = 0;
  let failed = 0;

  for (const email of emails) {
    try {
      const message = decryptEmailMessageFromStorage(email);
      const storage = encryptEmailMessageForStorage(message);
      const updated = await prisma.emailOutbox.updateMany({
        where: {
          id: email.id,
          text: email.text,
          html: email.html,
        },
        data: storage,
      });

      rotated += updated.count;
    } catch (error) {
      failed += 1;
      await prisma.emailOutbox.update({
        where: {
          id: email.id,
        },
        data: {
          lastError: errorMessage(error),
          lastErrorSource: "ENCRYPTION_ROTATION",
        },
      });
    }
  }

  return {
    rotated,
    failed,
  };
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
