# Code Style Guidelines

These are the coding style and architectural standards for the Elysia Auth Starter project.

## Imports

- Use path aliases: `@/*` for `src/*`, `@modules/*`, `@plugins/*`, `@libs/*`, `@middlewares/*`, `@utils/*`, `@generated/*`
- Place standard library imports first, then third-party libraries, then local files (absolute paths using aliases are preferred)
- ESLint auto-removes unused imports on lint/fix

## Formatting

- Prettier config: semicolons, trailing commas, no single quotes, 2-space indent, 80-char width
- Run `bun run format` before committing

## Types

- **No `any`** - Use `unknown` or specific types instead (ESLint warns on `any`)
- Enable `strict: true` in `tsconfig.json`
- Use `zod` for input validation schemas
- Export types for module consumers (e.g., `LoginInput` from schema files)

## Naming Conventions

- **Classes**: PascalCase (e.g., `AuthService`, `AccountDisabledError`)
- **Functions/variables**: camelCase (e.g., `login`, `refreshToken`)
- **Constants**: SCREAMING_SNAKE_CASE for configs (e.g., `JWT_REFRESH_EXPIRES_IN`)
- **Files**: kebab-case for modules, PascalCase for classes
- **Test files**: `*.test.ts` (unit) or `integration.test.ts` (integration)

## Error Handling

- Create custom error classes extending `Error` in `@/libs/exceptions`
- Use `throw new AccountDisabledError()` or `throw new UnauthorizedError()`
- Log with structured pino logger at appropriate levels (debug/warn/error)
- Global error handler catches unhandled errors and returns 500 with safe message

## Logging

- **Log in the Service Layer** - All logging must be implemented in the service layer (see `src/modules/auth/service.ts` as reference)
- Use pino logger from `@/libs/logger` - inject via method parameter: `log: Logger`
- Log levels:
  - `debug`: Method entry, operation details, parameter values
  - `info`: Successful operations (creation, updates, deletions), counts of retrieved data
  - `warn`: Security blocks, validation failures, unauthorized attempts
  - `error`: System errors, database failures, unexpected exceptions
- Include structured context: `log.info({ userId, email, count }, "message")`
- **Never log passwords, tokens, or sensitive data**
- Pattern example:
  ```typescript
  static async getUsers(params: {...}, log: Logger) {
    log.debug({ page, limit }, "Fetching users list");
    // ... database operations
    log.info({ count: users.length, total }, "Users retrieved successfully");
  }
  ```

## Architecture

- **Modules**: Feature-based in `src/modules/[name]/` with `index.ts`, `service.ts`, `model.ts`, `schema.ts`, `error.ts`, `locales/`
- **Plugins**: Elysia plugins in `src/plugins/`
- **Middleware**: Auth, error, permission, logging, i18n in `src/middleware/`
- **Libraries**: Prisma client, logger, exceptions, i18n in `src/libs/`
- **Locales**: Common translations in `src/locales/[lang].ts`, module-specific in `src/modules/[name]/locales/[lang].ts`
- **Config**: Environment variables in `src/config/env.ts`

## Internationalization (i18n)

The project uses a module-based i18n structure:

**Common locales** (shared across all modules):

```
src/locales/
  en.ts    # English common + validation messages
  es.ts    # Spanish common + validation messages
  id.ts    # Indonesian common + validation messages
```

**Module-specific locales** (each module has its own):

```
src/modules/
  auth/
    locales/
      en.ts, es.ts, id.ts
  user/
    locales/
      en.ts, es.ts, id.ts
  rbac/
    locales/
      en.ts, es.ts, id.ts
  dashboard/
    locales/
      en.ts, es.ts, id.ts
  health/
    locales/
      en.ts, es.ts, id.ts
```

**Using i18n in routes:**

```typescript
import { successResponse, errorResponse } from "@/libs/response";

// Success message with i18n
return successResponse(
  set,
  data,
  { key: "user.createSuccess" }, // uses module-specific translation
  201,
  undefined,
  locale,
);

// Error message with i18n
return errorResponse(
  set,
  404,
  { key: "common.notFound" }, // uses common translation
  null,
  locale,
);
```

**Frontend:** Send `Accept-Language` header with requests (e.g., `es-ES`, `id-ID`, `en`)
