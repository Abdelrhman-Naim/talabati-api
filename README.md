# Aegis Audit 🛡️ (Beta v0.12.0)

منصة متقدمة لفحص الأمان والتدقيق البرمجي التلقائي للمواقع ومستودعات الكود وواجهات البرمجة (APIs).
مبنية بأحدث تقنيات الويب: **Next.js 16 + React 19 + Node.js 24 + TypeScript**.

---

## 🚀 محركات الفحص والتدقيق الأمني المدمجة

- **فحص الكود المصدري و AST (Abstract Syntax Tree):** تحليل الكود بحثاً عن الدوال الخطيرة (`eval`, `Function`), وتجاوزات الذاكرة وحقن الأوامر.
- **كشف تسريب المفاتيح والأسرار (Secret Leak Detection):** مسح للتوكنات الحساسة (OpenAI, Stripe, AWS, Supabase service_role, JWT, Private Keys) مع حجبها التلقائي لحماية الخصوصية.
- **فحص الحزم والثغرات التابعة (OSV Vulnerability Scanner):** استعلام قاعدة ثغرات البرمجيات المفتوحة المصدر عبر `package-lock.json` و `npm-shrinkwrap`.
- **حماية الشبكة والـ SSRF:** جدار حماية شبكي صارم يرفض عناوين IP الخاصة والشبكات المحجوزة (`169.254.169.254`, `localhost`, `10.x.x.x`) لمنع هجمات Server-Side Request Forgery.
- **فحص أمان واجهات البرمجة (API Security & CORS & RLS):** اختبارات تلقائية لسياسات CORS، وتحقق من قواعد الصفوف في Supabase (Row Level Security)، وتدقيق ترويسات الأمان (CSP, HSTS, X-Content-Type-Options).
- **فحص المتصفح وسهولة الوصول (Browser Headless + axe-core):** تشغيل متصفح Chromium عبر Playwright للتحقق من أمان عناصر DOM وقياس الأداء ووصولية الويب.

---

## 🐳 التشغيل والنشر عبر Docker

### 1. تشغيل كحاوية متكاملة (Standalone Container - منصة طاقات / VPS):
الحاوية تشغل تلقائياً كلاً من واجهة الويب وعامل الفحص بالخلفية (`npm run start:all`):

```bash
# بناء الصورة
docker build -t aegis-audit .

# تشغيل الحاوية
docker run -p 3000:3000 aegis-audit
```

### 2. تشغيل عبر Docker Compose:
تشغيل واجهة الويب (`web`) وعامل الفحص الخلفي (`worker`) كخدمتين منفصلتين متصلتين بمجلد تخزين دائم:

```bash
docker compose up -d
```

---

## 🛠️ التشغيل والتطوير محلياً

```bash
# تثبيت الحزم
npm install

# إعداد المتصفح
npx playwright install --with-deps chromium

# نسخ متغيرات البيئة
copy .env.example .env.local

# تشغيل بيئة التطوير (الويب + العامل معاً)
npm run dev
```

---

## 🧪 الاختبارات وضمان الجودة (QA & Testing)

```bash
# تشغيل جميع اختبارات الوحدة والأمان
npm test

# فحص توافق الأنواع (TypeScript)
npm run typecheck

# تشغيل البنشمارك الأمني
npm run test:benchmark
```
