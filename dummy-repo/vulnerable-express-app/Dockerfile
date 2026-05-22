FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

# SECURITY: Using --package-lock-only ensures package.json and package-lock.json are in sync
RUN npm install --package-lock-only

COPY . .

# SECURITY: Dropping package-manager caches
RUN rm -rf /root/.npm

EXPOSE 3000

# SECURITY: Run container as non-root user
USER node

CMD ["node", "server.js"]