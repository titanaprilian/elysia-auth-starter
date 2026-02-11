import { createBaseApp } from "@/libs/base";
import { HealthService } from "./service";
import { HealthModel } from "./model";
import { successResponse } from "@/libs/response";

export const health = createBaseApp({
  tags: ["Health"],
}).get(
  "/health",
  async ({ set }) => {
    const healthCheck = await HealthService.check();
    return successResponse(set, healthCheck, "Server up and running", 200);
  },
  {
    response: {
      200: HealthModel.ok,
      503: HealthModel.shuttingDown,
    },
  },
);
