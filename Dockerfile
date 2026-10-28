# syntax=docker/dockerfile:1

FROM node:26.12.0-trixie-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build && npm prune --omit=dev && mkdir -p /out/data

# Node runs the TypeScript sources directly; only production dependencies are copied. Runtime takes Falco's events from
# its agents and sends detections on to SIEM over HTTP; it needs no other tool (ADR 0066).
FROM gcr.io/distroless/nodejs26-debian13:nonroot
WORKDIR /app
COPY --from=build /app/package.json /app/openapi.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/server ./server
COPY --from=build /app/dist/web ./dist/web
COPY --from=build /app/dist/docs ./dist/docs
COPY --from=build --chown=nonroot:nonroot /out/data /data
# Everything that is written goes to /data, so the root filesystem can be read-only (ADR 0022).
ENV NODE_ENV=production PORT=8080 RUNTIME_DB=/data/runtime.db
VOLUME /data
EXPOSE 8080
USER nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["server/main.ts"]
