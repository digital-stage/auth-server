FROM node:14.15.0-buster AS build

ENV SECRET=dawd2f2f2f2222dcwwdwdwe23593g33v6c73147a
ENV MONGO_URL=mongodb://mongo:27017/auth

COPY package.json ./
COPY tsconfig.json ./
RUN npm install
COPY src ./src
RUN npm run build

FROM node:14.15.0-buster
ENV NODE_ENV=production
COPY package.json ./
RUN npm install
COPY --from=build /dist ./dist
EXPOSE 5000
ENTRYPOINT ["node", "./dist/index.js"]