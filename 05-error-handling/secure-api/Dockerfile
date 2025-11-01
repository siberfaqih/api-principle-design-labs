FROM node:18-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --only=production

COPY src ./src

ENV NODE_ENV=production
ENV PORT=3001
EXPOSE 3001

CMD ["npm", "start"]