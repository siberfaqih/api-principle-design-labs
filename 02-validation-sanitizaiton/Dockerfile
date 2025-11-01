# Dockerfile for Secure API Design Lab (Node.js)

FROM node:18-alpine AS base
WORKDIR /usr/src/app

# Install dependencies first for better layer caching
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Environment
ENV NODE_ENV=production

# Expose both server ports
EXPOSE 3001 3002

# Default command (overridden by docker-compose per service)
CMD ["node", "secure-server.js"]