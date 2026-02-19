import { Elysia } from "elysia";
import { logger } from "@/libs/logger";
import { randomUUID } from "node:crypto";

export const loggerMiddleware = new Elysia()
  .derive(({ request }) => {
    const requestId = request.headers.get("x-request-id") || randomUUID();

    return {
      startTime: Date.now(),
      requestId,
      log: logger.child({ requestId }),
    };
  })
  .onAfterResponse(({ request, set, startTime, requestId }) => {
    const url = new URL(request.url);

    if (url.pathname === "/favicon.ico") {
      return;
    }

    const start = startTime || Date.now();
    const durationMs = Date.now() - start;

    const status = set.status || 200;
    const level =
      Number(status) >= 500 ? "error" : Number(status) >= 400 ? "warn" : "info";

    logger[level](
      {
        requestId,
        method: request.method,
        url: request.url,
        status: status,
        duration: `${durationMs}ms`,
      },
      "Incoming Request",
    );
  })
  .as("global");
