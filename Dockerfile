FROM node:18-alpine

WORKDIR /app
COPY . .
RUN yarn
RUN yarn build

EXPOSE 3000

CMD ["yarn", "preview", "--host", "0.0.0.0", "--port", "3000"]