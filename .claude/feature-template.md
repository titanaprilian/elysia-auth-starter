# Feature Implementation Walkthrough & Template

This document provides a step-by-step example workflow for implementing a new feature or module (e.g., adding a `products` feature) from database schema changes down to route registration and tests.

---

## Step 1: Database Schema Changes

Edit `prisma/schema.prisma` to add your model definitions. Then run migrations and generate type definitions:

```bash
# Edit prisma/schema.prisma to add new models
# Then generate and apply the dev migration
prisma migrate dev --name add_products
prisma generate
```

---

## Step 2: Create the Module Directory Structure

Create your new feature folder under `src/modules/[feature-name]/`. For example, for a `products` module, create `src/modules/products/` containing:

- `schema.ts` - Zod validation schemas for inputs and outputs
- `model.ts` - Zod/TypeBox schemas for API documentation/response validation
- `error.ts` - Custom feature-specific error classes (optional)
- `service.ts` - Core business logic with injected pino logging
- `index.ts` - Elysia route handlers
- `locales/` - Localized key-value translation files (optional)

Example folder tree:
```
src/modules/products/
  index.ts
  service.ts
  model.ts
  schema.ts
  error.ts
  locales/
    en.ts
    es.ts
    id.ts
```

---

## Step 3: Implement the Service Layer (with Logging)

Your service layer implements all database queries, transactions, and business logic. Inject the logger as a parameter `log: Logger` and log all operations clearly:

```typescript
import type { Logger } from "pino";
import { prisma } from "@/libs/prisma";

export abstract class ProductService {
  static async getProducts(params: { page: number; limit: number }, log: Logger) {
    const { page, limit } = params;
    log.debug({ page, limit }, "Fetching products list");

    const skip = (page - 1) * limit;
    const [products, total] = await prisma.$transaction([
      prisma.product.findMany({
        skip,
        take: limit,
        orderBy: { createdAt: "desc" },
      }),
      prisma.product.count(),
    ]);

    log.info({ count: products.length, total }, "Products retrieved successfully");
    return {
      products,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  static async createProduct(data: { name: string; price: number }, log: Logger) {
    log.debug({ name: data.name }, "Creating new product");

    const product = await prisma.product.create({ data });

    log.info({ productId: product.id }, "Product created successfully");
    return product;
  }

  static async updateProduct(id: string, data: { name?: string; price?: number }, log: Logger) {
    log.debug({ productId: id }, "Updating product");

    const product = await prisma.product.update({
      where: { id },
      data,
    });

    log.info({ productId: id }, "Product updated successfully");
    return product;
  }

  static async deleteProduct(id: string, log: Logger) {
    log.debug({ productId: id }, "Deleting product");

    await prisma.product.delete({ where: { id } });

    log.info({ productId: id }, "Product deleted successfully");
  }
}
```

---

## Step 4: Implement Route Handlers

Set up your endpoints using Elysia `createProtectedApp()` (for routes requiring auth) or `createBaseApp()` (for public routes). Make sure to pass `log` and `locale` context to your service layer and response helpers:

```typescript
import { createBaseApp, createProtectedApp } from "@/libs/base";
import { successResponse } from "@/libs/response";
import { ProductService } from "./service";

const protectedProducts = createProtectedApp()
  .get("/", async ({ query, set, log, locale }) => {
    const page = Number(query.page || 1);
    const limit = Number(query.limit || 10);

    const { products, pagination } = await ProductService.getProducts(
      { page, limit },
      log,
    );

    return successResponse(
      set,
      products,
      { key: "products.listSuccess" },
      200,
      { pagination },
      locale,
    );
  })
  .post("/", async ({ body, set, log, locale }) => {
    const product = await ProductService.createProduct(body, log);

    return successResponse(
      set,
      product,
      { key: "products.createSuccess" },
      201,
      undefined,
      locale,
    );
  });

export const products = createBaseApp({ tags: ["Products"] }).group(
  "/products",
  (app) => app.use(protectedProducts),
);
```

---

## Step 5: Implement Feature Tests

Create tests in `src/__tests__/products/` (e.g. `list.test.ts`, `create.test.ts`):

```typescript
import { describe, it, expect, beforeEach } from "bun:test";
import { app } from "@/app";
import { getAuthToken, resetDatabase } from "@tests/test_utils";

describe("POST /products", () => {
  beforeEach(async () => {
    await resetDatabase();
  });

  it("should create a new product", async () => {
    const token = await getAuthToken();

    const res = await app.handle(
      new Request("http://localhost/products", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: "Test Product",
          price: 99.99,
        }),
      }),
    );

    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.data.name).toBe("Test Product");
  });
});
```

---

## Step 6: Register the Module

Open `src/modules/index.ts` and add your module:

```typescript
import { auth } from "./auth";
import { user } from "./user";
import { rbac } from "./rbac";
import { products } from "./products";

export const modules = [auth, user, rbac, products];
```

---

## Step 7: Verify Everything

Run ESLint, unit tests, and check features locally:

```bash
bun run lint           # Check for linting errors
bun test products      # Run your feature tests
bun run dev            # Run the dev server to test manually
```
