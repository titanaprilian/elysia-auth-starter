import { successResponse } from "@/libs/response";
import { HealthService } from "./service";
import type { Context } from "elysia";

export class HealthController {
  static async getHealth({ set }: { set: Context["set"] }) {
    const details = await HealthService.getHealthDetails();
    return successResponse(set, details, "SERVER_UP", 200, undefined);
  }
}
