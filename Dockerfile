FROM node:24-bookworm-slim

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOME=/tmp/devicefit \
    XDG_CACHE_HOME=/tmp/devicefit-cache \
    XDG_CONFIG_HOME=/tmp/devicefit-config

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
    && npx playwright install --with-deps chromium \
    && npm cache clean --force \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin devicefit \
    && chmod -R a+rX /ms-playwright

COPY --chown=devicefit:devicefit . .

USER devicefit
EXPOSE 3000
CMD ["node", "server.mjs"]
