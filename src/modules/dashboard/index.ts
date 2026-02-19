import { DashboardService } from "./service";
import { successResponse } from "@/libs/response";
import { createBaseApp, createProtectedApp } from "@/libs/base";

const protectedDashboard = createProtectedApp().get(
  "/",
  async ({ set, log }) => {
    const dashboard = await DashboardService.getDashboard(log);
    return successResponse(
      set,
      dashboard,
      "Dashboard data retrieved successfully",
    );
  },
);

export const dashboard = createBaseApp({ tags: ["Dashboard"] }).group(
  "/dashboard",
  (app) => app.use(protectedDashboard),
);
