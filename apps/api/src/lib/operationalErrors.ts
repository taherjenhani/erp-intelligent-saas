type OperationalErrorContext = Record<
  string,
  string | number | boolean | null | undefined
>;

function serializeError(error: unknown) {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }

  return {
    message: "Unknown error",
    value: String(error),
  };
}

function sanitizeContext(context: OperationalErrorContext = {}) {
  return Object.fromEntries(
    Object.entries(context).filter(
      ([, value]) => value !== undefined
    )
  );
}

export function reportOperationalError(
  event: string,
  error: unknown,
  context: OperationalErrorContext = {}
) {
  console.error(
    JSON.stringify({
      level: "error",
      event,
      ...sanitizeContext(context),
      error: serializeError(error),
    })
  );
}
