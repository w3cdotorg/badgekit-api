FROM node:26-alpine
WORKDIR /app
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN npm ci --omit=dev
COPY . .
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 --start-period=60s \
  CMD wget -qO- http://localhost:8080/healthcheck || exit 1
CMD ["sh", "-c", "node bin/db-migrate up && node app"]
