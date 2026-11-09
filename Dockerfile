FROM node:18-alpine

WORKDIR /app

# نسخ ملفات الحزم وتثبيتها أولاً
COPY package*.json ./

RUN npm install --production

# نسخ باقي كود المشروع
COPY . .

# المنفذ الذي يعمل عليه كود الـ API
EXPOSE 3000

CMD ["npm", "start"]
