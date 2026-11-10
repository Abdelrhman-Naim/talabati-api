FROM node:24-bookworm-slim
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund && npx playwright install --with-deps chromium
COPY . .
RUN npm run build && mkdir -p /app/data && chown -R node:node /app/data /ms-playwright
ENV NODE_ENV=production DATA_DIR=/app/data
USER node
EXPOSE 3000
CMD ["npm", "run", "start:all"]
