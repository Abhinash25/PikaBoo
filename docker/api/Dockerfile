# ============================================================================
# PRIVACY GATEWAY API — SECURE NON-ROOT PRODUCTION DOCKERFILE
# Stage 1: Build & TypeScript Compilation
# Stage 2: Minimal Distroless / Alpine Runtime (Non-root UID 10001)
# ============================================================================

FROM node:22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache libc6-compat

# Copy package manifests
COPY package.json tsconfig.base.json tsconfig.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY apps/ ./apps/
COPY packages/ ./packages/
COPY infrastructure/ ./infrastructure/
COPY server.ts vite.config.ts index.html ./
COPY src/ ./src/

# Production build using unified build script
RUN npm run build

# ----------------------------------------------------------------------------
# Stage 2: Runtime Image
# ----------------------------------------------------------------------------
FROM node:22-alpine AS runner

WORKDIR /app

# Create unprivileged user
RUN addgroup --system --gid 10001 nodejs && \
    adduser --system --uid 10001 appuser

# Set environment
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

# Copy node_modules & compiled artifacts
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/infrastructure ./infrastructure

# Ensure ownership by unprivileged user
RUN chown -R appuser:nodejs /app

USER appuser

EXPOSE 3000

# Health check
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/health/live || exit 1

CMD ["node", "dist/server.cjs"]
