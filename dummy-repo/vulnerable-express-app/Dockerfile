FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
# SECURITY: Pin package.json and lockfile to specific versions
RUN npm install --ignore-scripts --package-lock-only --audit
RUN npm install --ignore-scripts --legacy-peer-deps

COPY . .

# SECURITY: Drop capabilities and set non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /app
USER appuser

# SECURITY: Expose port 3000 but do not publish it to the host
EXPOSE 3000

CMD ["node", "server.js"]