FROM node:22-bookworm-slim AS dependencies
WORKDIR /opt/lookout
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /opt/lookout
COPY --from=dependencies /opt/lookout/node_modules ./node_modules
COPY --chown=10001:10001 package.json ./
COPY --chown=10001:10001 src ./src
COPY --chown=10001:10001 public ./public
COPY --chown=10001:10001 bin ./bin
COPY --chown=10001:10001 scripts ./scripts
USER 10001:10001
VOLUME ["/var/lib/lookout"]
EXPOSE 4173
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:4173/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "src/server.js"]
