import crypto from "crypto";

import { env } from "../../config/env";

export async function applyAuthResponseJitter() {
  const min = env.AUTH_RESPONSE_JITTER_MIN_MS;
  const max = env.AUTH_RESPONSE_JITTER_MAX_MS;

  if (max <= 0) {
    return;
  }

  const delayMs =
    min === max ? min : crypto.randomInt(min, max + 1);

  await new Promise((resolve) => setTimeout(resolve, delayMs));
}
