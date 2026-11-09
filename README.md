# Talabati API 🚀

واجهة برمجة تطبيقات (RESTful API) لنظام **طلباتي (Talabati)**، مُجهزة للعمل داخل بيئة **Docker** ومُعدة للنشر التلقائي عبر منصة طاقات الأكاديمية (Taqat Academy).

---

## 📌 نبذة عن المشروع
- **التقنية المستخدمة:** Node.js + Express.js
- **الحاوية:** Docker (مبنية على `node:18-alpine` خفيفة وسريعة)
- **المنفذ الافتراضي:** `3000`
- **رابط النشر المستهدف:** [https://talabati-api.apps.taqat.academy](https://talabati-api.apps.taqat.academy)

---

## 🛠️ نقاط النهاية (Endpoints)

| الطريقة | المسار | الوصف |
|---------|--------|-------|
| `GET` | `/` | فحص عمل الخدمة والرسالة الترحيبية |
| `GET` | `/health` | فحص صحة الحاوية (Healthcheck) |
| `GET` | `/api/orders` | عرض جميع الطلبات |
| `GET` | `/api/orders/:id` | عرض تفاصيل طلب محدد |
| `POST` | `/api/orders` | إنشاء طلب جديد |
| `GET` | `/api/restaurants` | استعراض قائمة المطاعم |

---

## 💻 التشغيل محلياً (بدون Docker)

```bash
# تثبيت الحزم
npm install

# تشغيل الخادم
npm start
```
سيعمل الخادم عند: `http://localhost:3000`

---

## 🐳 التشغيل بواسطة Docker

```bash
# بناء الصورة
docker build -t talabati-api .

# تشغيل الحاوية
docker run -p 3000:3000 talabati-api
```

---

## 🚀 النشر على منصة الأكاديمية
1. إنشاء مستودع عام على GitHub باسم `talabati-api`.
2. ربط المستودع في منصة الأكاديمية:
   - **Name:** `API`
   - **Subdomain:** `talabati-api`
   - **GitHub Repo:** `https://github.com/Abdelrhman-Naim/talabati-api`
   - **Branch:** `main`
3. الضغط على **Create** وانتظار اكتمال البناء.
