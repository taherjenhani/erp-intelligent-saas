import { env } from "../config/env";

export function isLegacySecretFallbackEnabled() {
  return (
    Date.now() <=
    new Date(env.LEGACY_SECRET_FALLBACK_UNTIL).getTime()
  );
}
