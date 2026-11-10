# Security Audit & Vulnerability Testing API 🛡️

واجهة برمجة تطبيقات بدون واجهة رسومية (**Pure Headless REST API**) مخصصة للربط المباشر مع منصتك وتطبيقاتك لفحص أمان المواقع، واكتشاف الثغرات البرمجية، ورصد تسريب الأسرار ومفاتيح الـ API.

---

## ⚡ الميزات الأساسية:
- **بدون أي واجهة ويب أو شاشات تسجيل دخول (Zero UI / 100% JSON API)**.
- **دعم كامل لـ CORS (`*`)** للاتصال من أي منصة ويب أو تطبيق جوال دون أي مشاكل CORS.
- **فحص أمان المواقع الحية (Live URL Scanner):** فحص ترويسات الأمان (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)، وكشف ترويسات السيرفر، وحماية الـ Clickjacking والـ SSRF.
- **فحص الكود المصدري والأسرار (Code & Secret Scanner):** كشف مفاتيح API (AWS, Stripe, OpenAI, GitHub, Supabase, Slack, DB strings, Private Keys) ورصد الدوال الخطيرة (`eval`, Command Injection, SQL Injection, XSS sinks).

---

## 🚀 نقاط النهاية (Endpoints):

### 1. الفحص الشامل (Universal Scan):
- **المسار:** `POST /api/scan` أو `POST /scan`

#### أ. فحص موقع مباشر:
```json
{
  "url": "https://example.com"
}
```

#### ب. فحص كود مصدري:
```json
{
  "code": "const secret = 'sb_secret_sample_mock_123456789'; eval(req.query.cmd);",
  "filename": "auth.js"
}
```

---

### 2. فحص الصحة (Healthcheck):
- **المسار:** `GET /health`

---

## 💻 مثال الاستدعاء البرمجي (JavaScript / Fetch):

```javascript
// فحص موقع
async function scanWebsite(url) {
  const response = await fetch('https://api.apps.taqat.academy/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  const data = await response.json();
  console.log('Score:', data.score, 'Grade:', data.grade);
  console.log('Vulnerabilities:', data.findings);
}
```

---

## 🐳 التشغيل عبر Docker

```bash
docker build -t security-audit-api .
docker run -p 3000:3000 security-audit-api
```
