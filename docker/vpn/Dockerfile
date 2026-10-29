# Stage 1: Build the Node Controller API
FROM node:22-alpine AS builder

WORKDIR /app
COPY apps/vpn-node/package.json ./apps/vpn-node/
COPY tsconfig.base.json ./

WORKDIR /app/apps/vpn-node
RUN npm install

COPY apps/vpn-node/tsconfig.json ./
COPY apps/vpn-node/src/ ./src/
RUN npm run build

# Stage 2: VPN Runtime Node
FROM alpine:3.19

# Install Node.js, WireGuard, and iptables
RUN apk add --no-cache nodejs wireguard-tools iptables iproute2

WORKDIR /app

# Copy built artifacts from builder
COPY --from=builder /app/apps/vpn-node/package.json ./
COPY --from=builder /app/apps/vpn-node/node_modules ./node_modules
COPY --from=builder /app/apps/vpn-node/dist ./dist

# Copy entrypoint
COPY docker/vpn/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose WireGuard UDP port and Node API port
EXPOSE 51820/udp
EXPOSE 4000/tcp

CMD ["/entrypoint.sh"]
