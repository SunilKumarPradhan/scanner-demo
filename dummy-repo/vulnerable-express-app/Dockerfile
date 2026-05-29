FROM node:18-alpine@sha256:c0a3badbd8a0a760de903e00cedbca94588e609299820557e72cba2a53dbaa2c

WORKDIR /app

COPY package.json package-lock.json* ./
# SECURITY: Add --ignore-scripts to prevent arbitrary script execution during install
# SECURITY: Use package-lock.json to lock dependency versions and prevent supply chain attacks
RUN npm ci --ignore-scripts --no-audit --no-fund && \
    rm -rf /root/.npm

COPY . .

# SECURITY: Run as non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 3000

CMD ["node", "server.js"]