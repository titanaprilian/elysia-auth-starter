# Agent Guidelines for login-best-practices

## Project Overview

This is a TypeScript-based authentication service using Bun, Elysia framework, and Prisma ORM. The project implements secure login flows with JWT tokens, refresh tokens, and RBAC.

## Build, Lint, and Test Commands

```bash
# Development
bun run dev                    # Start dev server with hot reload
bun run --watch src/server.ts  # Alternative dev command

# Build
bun build src/server.ts --outdir dist --target bun --external @prisma/client
bun run dist/server.js         # Start production server

# Database
prisma generate                # Generate Prisma client
prisma migrate dev             # Run migrations in dev
prisma migrate deploy          # Deploy migrations in prod
prisma migrate reset           # Reset database (dev only)

# Testing
bun test                       # Run all tests
bun test unit                  # Run only unit tests
bun test integration          # Run only integration tests
bun test auth/unit.test.ts     # Run single test file
bun test auth                  # Run all auth tests
dotenv -e .env.test -- prisma db push  # Setup test DB

# Linting & Formatting
bun run lint                   # Run ESLint
bun run lint:fix               # Fix ESLint issues
bun run format                 # Format with Prettier
bun run prepare                # Install Husky hooks

# Code Generation
bun run generate               # Run Plop scaffolding
```

## Code Style Guidelines

### Imports

- Use path aliases: `@/*` for `src/*`, `@modules/*`, `@plugins/*`, `@libs/*`, `@middlewares/*`, `@utils/*`, `@generated/*`
- Place stdlib imports first, then third-party, then local (absolute paths preferred)
- ESLint auto-removes unused imports

### Formatting

- Prettier config: semicolons, trailing commas, no single quotes, 2-space indent, 80-char width
- Run `bun run format` before committing

### Types

- **No `any`** - Use `unknown` or specific types instead (ESLint warns on `any`)
- Enable `strict: true` in tsconfig.json
- Use `zod` for input validation schemas
- Export types for module consumers (e.g., `LoginInput` from schema files)

### Naming Conventions

- **Classes**: PascalCase (e.g., `AuthService`, `AccountDisabledError`)
- **Functions/variables**: camelCase (e.g., `login`, `refreshToken`)
- **Constants**: SCREAMING_SNAKE_CASE for configs (e.g., `JWT_REFRESH_EXPIRES_IN`)
- **Files**: kebab-case for modules, PascalCase for classes
- **Test files**: `*.test.ts` (unit) or `integration.test.ts` (integration)

### Error Handling

- Create custom error classes extending `Error` in `@/libs/exceptions`
- Use `throw new AccountDisabledError()` or `throw new UnauthorizedError()`
- Log with structured pino logger at appropriate levels (debug/warn/error)
- Global error handler catches unhandled errors and returns 500 with safe message

### Logging

- Use pino logger from `@/libs/logger`
- Log levels: `debug` (dev details), `info` (key events), `warn` (expected failures), `error` (exceptions)
- Include context objects: `log.info({ userId, email }, "message")`
- Never log passwords, tokens, or sensitive data

### Testing

- Use `bun:test` framework
- Mock Prisma with `mock.module("@/libs/prisma", () => ({ prisma }))`
- Place mocks in `src/__tests__/__mocks__/`
- Use `describe()` for grouping, `it()` or `test()` for cases
- Reset mocks in `beforeEach()`

### Architecture

- **Modules**: Feature-based in `src/modules/[name]/` with `index.ts`, `service.ts`, `model.ts`, `schema.ts`
- **Plugins**: Elysia plugins in `src/plugins/`
- **Middleware**: Auth, error, permission, logging in `src/middleware/`
- **Libraries**: Prisma client, logger, exceptions in `src/libs/`
- **Config**: Environment variables in `src/config/env.ts`

### Security Best Practices

- Never commit secrets - use `.env` files
- Hash passwords with `Bun.password` (bcrypt)
- Rotate refresh tokens on use
- Increment `tokenVersion` on logout_all or password change
- Validate all inputs with Zod schemas
- Use HTTPS in production, Helmet for headers
- Rate limiting enabled via `globalRateLimit` plugin
