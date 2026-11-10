const express = require('express');
const cors = require('cors');
const http = require('http');
const https = require('https');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

// Global Middlewares
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS', 'DELETE', 'PUT'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
}));
app.use(express.json({ limit: '5mb' }));

// ============================================================================
// 1. SSRF & URL VALIDATOR
// ============================================================================
function isPrivateIp(hostname) {
  const h = hostname.toLowerCase().trim();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return true;
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(h)) return true; // AWS metadata
  if (/\.(local|internal|test|invalid|corp)$/.test(h)) return true;
  return false;
}

function validateScanUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    throw new Error('الرابط المقدم غير صالح. تأكد من كتابة الرابط بشكل كامل مثل: https://example.com');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('البروتوكول غير مدعوم. يجب أن يبدأ الرابط بـ http:// أو https://');
  }

  if (isPrivateIp(parsed.hostname)) {
    throw new Error('حماية SSRF: لا يمكن فحص الشبكات الداخلية أو العناوين المحلية (localhost / private IPs).');
  }

  return parsed;
}

// ============================================================================
// 2. SECRET SCANNER & REDACTION
// ============================================================================
function redactSecret(secret) {
  if (!secret || typeof secret !== 'string') return '';
  if (secret.length <= 8) return '****';
  return secret.slice(0, 4) + '...' + secret.slice(-4);
}

const SECRET_PATTERNS = [
  { name: 'Stripe Secret Key', regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/g, severity: 'CRITICAL', fix: 'احذف المفتاح فوراً وانقله إلى متغيرات البيئة السرية بالخادم.' },
  { name: 'OpenAI API Key', regex: /\b(sk-[a-zA-Z0-9_-]{20,})\b/g, severity: 'CRITICAL', fix: 'قم بإلغاء التوكن فوراً من لوحة تحكم OpenAI واستخدم متغيرات الخادم.' },
  { name: 'GitHub Personal Access Token', regex: /\b((?:ghp_|github_pat_)[a-zA-Z0-9_]{20,})\b/g, severity: 'CRITICAL', fix: 'قم بحذف التوكن فوراً من حساب GitHub وأنشئ توكن جديد بصلاحيات محدودة.' },
  { name: 'AWS Access Key ID', regex: /\b(AKIA[0-9A-Z]{16})\b/g, severity: 'HIGH', fix: 'احذف مفتاح الوصول وأنشئ مفتاحاً جديداً عبر AWS IAM مع التحقق من الأذونات.' },
  { name: 'Supabase Secret Token', regex: /\b(sb_secret_[a-zA-Z0-9_-]{10,})\b/g, severity: 'CRITICAL', fix: 'المفتاح الخاص بـ Supabase يملك صلاحيات تخطي الـ RLS. احذفه من الكود العام.' },
  { name: 'Private Key Block', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: 'CRITICAL', fix: 'المفتاح الخاص مشفر أو مكشوف. لا يجب تخزينه في الكود المصدري إطلاقاً.' },
  { name: 'Database Connection String with Credentials', regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/:"'<>]+:([^\s@"'<>]+)@[^\s"'<>]+/g, severity: 'HIGH', fix: 'بيانات اعتماد قاعدة البيانات مكشوفة. استخدم متغير DATABASE_URL مشفر في الخادم.' },
  { name: 'Slack Bot / User Token', regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,})\b/g, severity: 'HIGH', fix: 'قم بإلغاء توكن Slack واستخدم متغير بيئة سري.' },
];

const CODE_VULN_PATTERNS = [
  { id: 'VULN-EVAL', name: 'Dynamic Code Execution (eval / Function)', regex: /\b(eval\s*\(|new\s+Function\s*\()/g, severity: 'HIGH', impact: 'قد يؤدي إلى تنفيذ أوامر عشوائية عن بُعد (Remote Code Execution) إذا وصلت بيانات غير موثوقة.', fix: 'استبدل eval بدوال محددة ومنطق برمجي آمن.' },
  { id: 'VULN-CMD-INJECT', name: 'System Command Execution', regex: /\b(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*\s*\+)/g, severity: 'CRITICAL', impact: 'بناء أوامر النظام عبر دمج النصوص قد يسبب Command Injection خطيراً.', fix: 'استخدم execFile أو spawn مع تمرير المعاملات كمصفوفة مستقلة دون shell.' },
  { id: 'VULN-SQLI', name: 'SQL Injection via String Concatenation', regex: /\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*\b(?:SELECT|UPDATE|DELETE|INSERT)\b[^"']*["']\s*\+)/i, severity: 'HIGH', impact: 'دمج نصوص المستخدم مباشرة في استعلامات SQL يعرض قاعدة البيانات للاختراق.', fix: 'استخدم Parameterized Queries (المعاملات المربوطة $1, ?) أو ORM موثوق.' },
  { id: 'VULN-XSS-SINK', name: 'Dangerous HTML Injection (XSS Sink)', regex: /\b(?:dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\()/g, severity: 'MEDIUM', impact: 'إدخال نصوص HTML غير معالجة قد يؤدي إلى هجمات Cross-Site Scripting.', fix: 'استخدم textContent أو مرر النصوص عبر مكتبة تطهير مثل DOMPurify.' },
  { id: 'VULN-WEAK-CRYPTO', name: 'Weak Hashing Algorithm (MD5 / SHA1)', regex: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/i, severity: 'MEDIUM', impact: 'خوارزميات MD5 و SHA1 لم تعد آمنة للتشفير وحماية كلمات المرور.', fix: 'استخدم Argon2 أو bcrypt أو scrypt لكلمات المرور، و SHA-256 أو أعلى للمطابقة.' },
  { id: 'VULN-TLS-BYPASS', name: 'Insecure TLS Verification Bypass', regex: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/g, severity: 'HIGH', impact: 'تعطيل التحقق من شهادات SSL يفتح الباب لهجمات Man-in-the-Middle.', fix: 'أبقِ التحقق من الشهادات مفعلاً وقم بتثبيت شهادات CA المناسبة في الخادم.' },
  { id: 'VULN-PUBLIC-SECRET', name: 'Public Frontend Secret Exposure', regex: /\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z\d_]*(?:SECRET|PRIVATE_KEY|PASSWORD|SERVICE_ROLE)\b/g, severity: 'HIGH', impact: 'متغيرات البيئة التي تبدأ بـ NEXT_PUBLIC أو VITE تُدمج في كود المتصفح وتظهر للعامة.', fix: 'انقل المتغيرات السرية إلى متغيرات خادم سرية دون بادئة عامة.' },
];

function scanCode(code, filename = 'code.js') {
  const findings = [];
  const lines = code.split('\n');

  // 1. Check Secrets
  for (const rule of SECRET_PATTERNS) {
    rule.regex.lastIndex = 0;
    let match;
    while ((match = rule.regex.exec(code)) !== null) {
      const matchIndex = match.index;
      const lineNumber = code.substring(0, matchIndex).split('\n').length;
      findings.push({
        id: `SEC-${findings.length + 1}`,
        type: 'SECRET_LEAK',
        rule: rule.name,
        severity: rule.severity,
        title: `تسريب سري محتمل: ${rule.name}`,
        evidence: `القيمة المرصودة: ${redactSecret(match[1] || match[0])}`,
        line: lineNumber,
        file: filename,
        impact: 'كشف المفاتيح الحساسة في الكود يمنح المخترقين وصولاً غير مصرح به إلى خدماتك.',
        recommendation: rule.fix,
      });
    }
  }

  // 2. Check Code Vulnerabilities
  for (const rule of CODE_VULN_PATTERNS) {
    rule.regex.lastIndex = 0;
    let match;
    while ((match = rule.regex.exec(code)) !== null) {
      const matchIndex = match.index;
      const lineNumber = code.substring(0, matchIndex).split('\n').length;
      findings.push({
        id: rule.id,
        type: 'CODE_VULNERABILITY',
        rule: rule.name,
        severity: rule.severity,
        title: rule.name,
        evidence: `السطر ${lineNumber}: تم رصد نمط غير آمن مطابق للقاعدة.`,
        line: lineNumber,
        file: filename,
        impact: rule.impact,
        recommendation: rule.fix,
      });
    }
  }

  // Calculate Score
  let deductions = 0;
  for (const f of findings) {
    if (f.severity === 'CRITICAL') deductions += 25;
    else if (f.severity === 'HIGH') deductions += 15;
    else if (f.severity === 'MEDIUM') deductions += 8;
    else deductions += 3;
  }
  const score = Math.max(0, 100 - deductions);

  return {
    score,
    grade: calculateGrade(score),
    findings,
  };
}

// ============================================================================
// 3. LIVE URL SECURITY SCANNER
// ============================================================================
function fetchUrl(targetUrl, maxRedirects = 3) {
  return new Promise((resolve, reject) => {
    const parsed = validateScanUrl(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;

    const req = client.request(parsed, {
      method: 'GET',
      headers: {
        'User-Agent': 'SecurityAuditAPI/1.0 (Automated Security Scanner)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'identity',
      },
      timeout: 12000,
    }, res => {
      // Handle redirects safely
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        if (maxRedirects <= 0) {
          return reject(new Error('تم تجاوز الحد الأقصى لإعادة التوجيه (Too many redirects).'));
        }
        const redirectUrl = new URL(res.headers.location, parsed).href;
        return resolve(fetchUrl(redirectUrl, maxRedirects - 1));
      }

      const chunks = [];
      let totalBytes = 0;
      res.on('data', chunk => {
        totalBytes += chunk.length;
        if (totalBytes > 2 * 1024 * 1024) { // 2MB max
          req.destroy(new Error('حجم الصفحة يتجاوز الحد المسموح للفحص (2MB).'));
        } else {
          chunks.push(chunk);
        }
      });

      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body,
          finalUrl: parsed.href,
          protocol: parsed.protocol,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error('انتهت مهلة الاتصال بالهدف (12 ثانية).'));
    });

    req.on('error', err => {
      reject(new Error(`فشل الاتصال بالهدف: ${err.message}`));
    });

    req.end();
  });
}

async function scanUrl(rawUrl) {
  const start = Date.now();
  const page = await fetchUrl(rawUrl);
  const findings = [];
  const passedChecks = [];
  const headers = page.headers;

  // 1. HTTPS Check
  if (page.protocol !== 'https:') {
    findings.push({
      id: 'SEC-HTTPS',
      severity: 'HIGH',
      title: 'الاتصال غير مشفر (HTTP بدلاً من HTTPS)',
      impact: 'البيانات المنقولة بين المستخدم والخادم مكشوفة ويمكن اعتراضها أو تعديلها (Man-in-the-Middle).',
      recommendation: 'قم بتثبيت شهادة SSL/TLS وتحويل كافة الطلبات تلقائياً إلى HTTPS.',
    });
  } else {
    passedChecks.push({ id: 'SEC-HTTPS', title: 'استخدام بروتوكول HTTPS المشفر' });
  }

  // 2. Strict-Transport-Security (HSTS)
  const hsts = headers['strict-transport-security'];
  if (!hsts) {
    findings.push({
      id: 'SEC-HSTS',
      severity: 'HIGH',
      title: 'غياب ترويسة Strict-Transport-Security (HSTS)',
      impact: 'المتصفح لن يجبر المستخدمين على الاتصال المشفر دائماً، مما يسمح بهجمات SSL Stripping.',
      recommendation: 'أضف الترويسة: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    });
  } else {
    passedChecks.push({ id: 'SEC-HSTS', title: 'ترويسة HSTS مفعلة' });
  }

  // 3. Content-Security-Policy (CSP)
  const csp = headers['content-security-policy'];
  if (!csp) {
    findings.push({
      id: 'SEC-CSP',
      severity: 'HIGH',
      title: 'غياب سياسة أمان المحتوى (Content-Security-Policy)',
      impact: 'غياب CSP يترك الموقع عرضة لهجمات حقن السكريبتات الخبيثة (XSS) وسرقة الجلسات وتضمين الإطارات غير المصرح بها.',
      recommendation: 'أضف ترويسة Content-Security-Policy تحدد المصادر الموثوقة للسكريبتات والوسائط.',
    });
  } else if (csp.includes('unsafe-inline') || csp.includes('unsafe-eval')) {
    findings.push({
      id: 'SEC-CSP-UNSAFE',
      severity: 'MEDIUM',
      title: 'سياسة أمان المحتوى تحتوي على توجيهات غير آمنة (unsafe-inline / unsafe-eval)',
      impact: 'السماح بـ unsafe-inline يقلل بشكل كبير من الحماية ضد ثغرات XSS.',
      recommendation: 'استخدم Nonce أو Hashes للسكريبتات وتجنب استخدام unsafe-inline.',
    });
  } else {
    passedChecks.push({ id: 'SEC-CSP', title: 'سياسة أمان المحتوى (CSP) محددة' });
  }

  // 4. Clickjacking Protection (X-Frame-Options)
  const xfo = headers['x-frame-options'];
  if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
    findings.push({
      id: 'SEC-XFO',
      severity: 'MEDIUM',
      title: 'غياب الحماية من الاختطاف بالنقر (Clickjacking / X-Frame-Options)',
      impact: 'يمكن تضمين موقعك داخل iframe على موقع خبيث وخداع المستخدمين للنقر على أزرار حساسة دون علمهم.',
      recommendation: 'أضف الترويسة: X-Frame-Options: DENY أو SAMEORIGIN، أو استخدم frame-ancestors في CSP.',
    });
  } else {
    passedChecks.push({ id: 'SEC-XFO', title: 'الحماية من تضمين الإطارات (Clickjacking Protection)' });
  }

  // 5. MIME-Sniffing (X-Content-Type-Options)
  const xcto = headers['x-content-type-options'];
  if (!xcto || !xcto.toLowerCase().includes('nosniff')) {
    findings.push({
      id: 'SEC-XCTO',
      severity: 'LOW',
      title: 'غياب ترويسة X-Content-Type-Options: nosniff',
      impact: 'قد يحاول المتصفح تخمين نوع الملفات وتفسير ملف نصي أو صورة ككود تنفيذي (MIME Sniffing).',
      recommendation: 'أضف الترويسة: X-Content-Type-Options: nosniff',
    });
  } else {
    passedChecks.push({ id: 'SEC-XCTO', title: 'منع تخمين نوع المحتوى (nosniff)' });
  }

  // 6. Information Disclosure (Server / X-Powered-By)
  const server = headers['server'];
  const poweredBy = headers['x-powered-by'];
  if (poweredBy || (server && /[\d.]/.test(server))) {
    findings.push({
      id: 'SEC-INFO-DISCLOSE',
      severity: 'LOW',
      title: 'كشف معلومات الإصدار والتقنية (Information Disclosure)',
      evidence: `Server: ${server || 'none'}, X-Powered-By: ${poweredBy || 'none'}`,
      impact: 'كشف أسماء وإصدارات السيرفر أو إطار العمل يساعد المهاجمين في استهداف ثغرات الإصدار المكتشف.',
      recommendation: 'قم بإخفاء أو تعطيل ترويسات X-Powered-By وإخفاء إصدار السيرفر في الإعدادات.',
    });
  } else {
    passedChecks.push({ id: 'SEC-INFO-DISCLOSE', title: 'إخفاء إصدارات الخادم وإطار العمل' });
  }

  // 7. CORS Wildcard with Credentials Check
  const corsOrigin = headers['access-control-allow-origin'];
  const corsCreds = headers['access-control-allow-credentials'];
  if (corsOrigin === '*' && corsCreds === 'true') {
    findings.push({
      id: 'SEC-CORS-WILDCARD',
      severity: 'HIGH',
      title: 'إعداد CORS غير آمن (Wildcard مع Credentials)',
      impact: 'إتاحة الوصول لكافة النطاقات مع تمرير الاعتماديات يكسر سياسة الأصل نفسه (Same-Origin Policy).',
      recommendation: 'حدد النطاقات المسموح بها بدقة ولا تستخدم * عند الحاجة إلى Cookies أو Authorization.',
    });
  }

  // 8. Body Scan for Exposed Secrets
  const bodySecrets = scanCode(page.body, 'page-html');
  for (const sf of bodySecrets.findings) {
    if (sf.type === 'SECRET_LEAK') {
      findings.push({
        id: `PAGE-${sf.id}`,
        severity: sf.severity,
        title: `تسريب سري مكشوف في كود الصفحة العام: ${sf.rule}`,
        evidence: sf.evidence,
        impact: 'وجود أسرار ومفاتيح API في كود الصفحة المصدري أو ملفات JS يتيح لأي زائر استخراجها واستخدامها.',
        recommendation: sf.recommendation,
      });
    }
  }

  // Calculate Score
  let deductions = 0;
  for (const f of findings) {
    if (f.severity === 'CRITICAL') deductions += 25;
    else if (f.severity === 'HIGH') deductions += 15;
    else if (f.severity === 'MEDIUM') deductions += 8;
    else deductions += 4;
  }
  const score = Math.max(0, 100 - deductions);

  return {
    score,
    grade: calculateGrade(score),
    target: page.finalUrl,
    statusCode: page.statusCode,
    durationMs: Date.now() - start,
    findings,
    passedChecks,
    securityHeaders: {
      contentSecurityPolicy: Boolean(headers['content-security-policy']),
      strictTransportSecurity: Boolean(headers['strict-transport-security']),
      xFrameOptions: headers['x-frame-options'] || false,
      xContentTypeOptions: headers['x-content-type-options'] || false,
      cors: headers['access-control-allow-origin'] || 'not-set',
      server: headers['server'] || 'hidden',
    }
  };
}

function calculateGrade(score) {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

// ============================================================================
// 4. REST API ROUTES (PURE JSON - NO HTML / NO UI)
// ============================================================================

// Root API Greeting (JSON)
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'Security Audit & Vulnerability Testing API',
    version: '1.0.0',
    message: 'Welcome! This is a headless security testing API. Send POST requests to /api/scan or /scan with { url } or { code } to audit security.',
    endpoints: {
      scan: 'POST /api/scan (or POST /scan)',
      universalScan: 'POST /api/scan (or POST /scan)',
      urlScan: 'POST /api/scan/url',
      codeScan: 'POST /api/scan/code',
      health: 'GET /health',
    },
    documentation: {
      scanUrlExample: {
        method: 'POST',
        url: `${req.protocol}://${req.get('host')}/api/scan`,
        headers: { 'Content-Type': 'application/json' },
        body: { url: 'https://example.com' }
      },
      scanCodeExample: {
        method: 'POST',
        url: `${req.protocol}://${req.get('host')}/api/scan`,
        headers: { 'Content-Type': 'application/json' },
        body: { code: 'const key = "sb_secret_sample_token_123"; eval(userInput);', filename: 'api.js' }
      }
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Security Audit API',
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString()
  });
});

// Universal Scan Endpoint
async function handleUniversalScan(req, res) {
  try {
    const { url, code, filename } = req.body || {};

    if (!url && !code) {
      return res.status(400).json({
        success: false,
        error: 'طلب غير صالح. يرجى إرسال حقل url لفحص موقع حي، أو حقل code لفحص الكود المصدري.',
        example: {
          urlScan: { url: 'https://example.com' },
          codeScan: { code: 'eval(userInput);', filename: 'script.js' }
        }
      });
    }

    // 1. If Code provided
    if (code) {
      const codeResult = scanCode(code, filename || 'snippet.js');
      return res.json({
        success: true,
        type: 'code',
        target: filename || 'snippet.js',
        score: codeResult.score,
        grade: codeResult.grade,
        summary: {
          totalFindings: codeResult.findings.length,
          critical: codeResult.findings.filter(f => f.severity === 'CRITICAL').length,
          high: codeResult.findings.filter(f => f.severity === 'HIGH').length,
          medium: codeResult.findings.filter(f => f.severity === 'MEDIUM').length,
          low: codeResult.findings.filter(f => f.severity === 'LOW').length,
        },
        findings: codeResult.findings,
        timestamp: new Date().toISOString()
      });
    }

    // 2. If URL provided
    if (url) {
      const urlResult = await scanUrl(url);
      return res.json({
        success: true,
        type: 'url',
        target: urlResult.target,
        statusCode: urlResult.statusCode,
        score: urlResult.score,
        grade: urlResult.grade,
        summary: {
          totalFindings: urlResult.findings.length,
          critical: urlResult.findings.filter(f => f.severity === 'CRITICAL').length,
          high: urlResult.findings.filter(f => f.severity === 'HIGH').length,
          medium: urlResult.findings.filter(f => f.severity === 'MEDIUM').length,
          low: urlResult.findings.filter(f => f.severity === 'LOW').length,
          passedChecks: urlResult.passedChecks.length,
        },
        findings: urlResult.findings,
        passedChecks: urlResult.passedChecks,
        securityHeaders: urlResult.securityHeaders,
        durationMs: urlResult.durationMs,
        timestamp: new Date().toISOString()
      });
    }
  } catch (err) {
    return res.status(400).json({
      success: false,
      error: err.message || 'حدث خطأ أثناء إجراء الفحص الأمني.'
    });
  }
}

// Bind universal scan endpoints
app.post('/api/scan', handleUniversalScan);
app.post('/scan', handleUniversalScan);
app.post('/api/v1/scan', handleUniversalScan);

// Dedicated URL endpoint
app.post('/api/scan/url', async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ success: false, error: 'حقل url مطلوب.' });
  try {
    const result = await scanUrl(url);
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Dedicated Code endpoint
app.post('/api/scan/code', (req, res) => {
  const { code, filename } = req.body || {};
  if (!code) return res.status(400).json({ success: false, error: 'حقل code مطلوب.' });
  const result = scanCode(code, filename);
  res.json({ success: true, ...result });
});

// 404 Handler (JSON only)
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: `المسار غير موجود (${req.method} ${req.originalUrl}). راجع GET / للاطلاع على المسارات المتاحة.`
  });
});

// Error Handler (JSON only)
app.use((err, req, res, next) => {
  res.status(500).json({
    success: false,
    error: err.message || 'خطأ داخلي في الخادم.'
  });
});

// Export app for tests or start server directly
if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`[Security Audit API] Running on http://${HOST}:${PORT}`);
    console.log(`[Security Audit API] Pure Headless REST API ready for platform integration.`);
  });
}

module.exports = app;
