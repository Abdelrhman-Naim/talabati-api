# NodeGoat is built from official source: no official prebuilt image is invented.
# Base digest recorded by the Tekton project's pinned Node 12 Alpine task.
FROM docker.io/library/node:12-alpine@sha256:dfbebf17bfb014e1e7068e76325a117bccf8679c68aec6a28514184a209c8bae
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production --ignore-scripts
COPY . .
EXPOSE 4000
CMD ["npm", "start"]
