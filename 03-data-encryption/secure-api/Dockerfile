FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --no-audit --no-fund
COPY src ./src
COPY scripts ./scripts
EXPOSE 3001
CMD ["npm", "start"]