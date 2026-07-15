# Build in one stage, ship another. The runtime image gets the compiled output and
# production dependencies only, so the TypeScript compiler and the test tooling do
# not travel to production.
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY scripts/copy-migrations.js ./scripts/copy-migrations.js
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist

# Do not run as root.
USER node
EXPOSE 3000

# No shell wrapper, so the process is PID 1 and receives SIGTERM directly. Without
# this the graceful shutdown never fires and Kubernetes kills connections mid flight.
CMD ["node", "dist/index.js"]
