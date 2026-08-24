FROM node:24-bookworm-slim
ENV NODE_ENV=production LOOKOUT_RELEASE_VERSION=v0.1.0 LOOKOUT_ARTIFACT_MANIFEST=/service/hosting/release-manifest.json
WORKDIR /service
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && mkdir -p vendor && cp node_modules/@supabase/supabase-js/dist/umd/supabase.js vendor/supabase.js
COPY hosting/distribution-server.js ./hosting/distribution-server.js
COPY hosting/release-artifacts.js hosting/release-manifest.json ./hosting/
COPY bootstrap/hosted-install.sh.in ./bootstrap/hosted-install.sh.in
COPY bootstrap/hosted-install.ps1.in ./bootstrap/hosted-install.ps1.in
COPY bootstrap/workstation-cli-install.sh.in ./bootstrap/workstation-cli-install.sh.in
COPY bootstrap/workstation-cli-install.ps1.in ./bootstrap/workstation-cli-install.ps1.in
COPY src ./src
COPY config ./config
COPY public ./public
COPY tools ./tools
USER 10001:10001
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:3000/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "hosting/distribution-server.js"]
