import { openapi } from "@elysiajs/openapi";

export const openapiPlugin = openapi({
  enabled: process.env.NODE_ENV !== "production",
  path: "/openapi",
  scalar: {
    customCss: `
      /* Fix modal scrolling issue */
      .swagger-modal .modal-body {
        max-height: calc(100vh - 200px);
        overflow-y: auto;
      }
      
      /* Fix for Scalar UI - modal scrolling */
      .scalar-modal__window {
        max-height: 90vh !important;
        overflow-y: auto !important;
      }
      
      .scalar-modal__body {
        max-height: calc(90vh - 120px) !important;
        overflow-y: auto !important;
      }
    `,
  },
  documentation: {
    openapi: "3.0.3",
    info: {
      title: "Elysia Auth Best Practices API",
      version: "1.0.0",
      description: `
This API demonstrates **authentication best practices** using **Elysia**, **Prisma**, and **JWT**.

### Principles
- Stateless authentication using JWT
- Explicit separation of public and protected routes
- Schema-first validation (Zod + TypeBox)
- No URL-based API versioning
- Backward-compatible API evolution

⚠️ This documentation is disabled in production.
      `.trim(),
    },
    tags: [
      {
        name: "Auth",
        description:
          "Authentication & authorization flows (login, refresh, logout, logout all)",
      },
      {
        name: "User",
        description: "Protected user-related operations",
      },
      {
        name: "Health",
        description: "System & health-check endpoints",
      },
      {
        name: "RBAC",
        description: "System Role Based Access Control",
      },
    ],

    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description:
            "Provide a valid JWT access token in the Authorization header: `Bearer <token>`",
        },
      },
    },

    // /**
    //  * Default security requirement
    //  * All routes are considered protected unless explicitly overridden
    //  */
    // security: [
    //   {
    //     bearerAuth: [],
    //   },
    // ],
  },
});
