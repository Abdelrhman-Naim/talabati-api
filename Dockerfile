FROM node:20-alpine

WORKDIR /app

# نسخ الحزم وتثبيتها أولاً
COPY package*.json ./
RUN npm install --production

# نسخ كود الـ API
COPY . .

# المنفذ
EXPOSE 3000

# تشغيل خادم الـ API
CMD ["npm", "start"]
