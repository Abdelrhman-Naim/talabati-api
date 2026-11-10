# خريطة معمارية محرك الفحص الحالي — Task 0

تاريخ المراجعة: 9 نوفمبر 2026. إصدار التطبيق: **0.12.0**. مرجع المصدر: **b2fcb2f** على الفرع **feat/audit-beta**. هذه خريطة للحالة الموجودة، وليست تنفيذًا لترقية المحرك أو شهادة اكتشاف ثغرات. نُفّذت Task 0 فقط من الخطة المرفقة security-scanner-upgrade-plan(1).md.

## 1. خلاصة موثقة

- المسار الحالي: Next.js API ← SQLite queue ← Node.js Worker ← فحوص محلية/طلبات HTTP محدودة/OSV اختياري ← نتيجة JSON داخل SQLite ← واجهة التقارير.
- لا توجد خدمة scan-service منفصلة أو Redis أو تشغيل Docker أو adapters لـSemgrep/Gitleaks/TruffleHog/OSV-Scanner/Nuclei في مسار التطبيق الحالي.
- قراءة المستودعات تتم عبر GitHub REST API لنسخة commit واحدة، لا عبر git clone، ولا تشمل التاريخ المحذوف.
- Ollama يشرح Finding موجودة عند طلب المستخدم، ولا ينشئ قائمة النتائج ولا يحسب درجاتها. برومبت الإصلاح الأساسي قالب محلي.
- جميع أسماء الملفات والدوال أدناه تحققت من المصدر. مراجعة الأدوات تخص بيئة العمل الحالية فقط، وليست جردًا لسيرفر المستخدم أو سيرفر Ollama.

## 2. خريطة الملفات ومسارات التنفيذ

| المسؤولية | الملف الحقيقي | نقطة الدخول أو الدالة |
|---|---|---|
| الصفحة الرئيسية | src/app/page.tsx | Page → Workspace |
| إنشاء المشروع/الفحص والتحقق والوصول للنتيجة | src/app/api/[...path]/route.ts | handler، صادرات GET/POST/DELETE |
| API العميل | src/lib/client-api.ts | api |
| الأنواع الحالية | src/lib/types.ts | Finding، AuditCheck، Scan، ScanResult، Service |
| قاعدة البيانات والطابور | src/lib/db.ts | Store، getStore، queueScan، claimJob، progress، finishScan، cancelScan |
| تشغيل التطوير مع العامل | scripts/dev.mjs | spawn لـsrc/worker.ts وNext dev |
| تشغيل الإنتاج مع العامل | scripts/start.mjs | spawn للعامل وNext start |
| إعادة بدء حجز العامل في التطوير | scripts/restart-worker.ts | سكريبت الصيانة المستخدم من dev.mjs |
| مدخل العامل | src/worker.ts | حلقة claimJob؛ runRepositoryJob أو runJob |
| زحف الموقع وتخزين مراحل الفحص | src/lib/jobs.ts | runJob |
| سياسة الروابط وrobots وsitemaps | src/lib/crawler.ts | resolveCrawlOptions، normalizeCrawlUrl، parseRobots، parseSitemap |
| نقل HTTP وSSRF | src/lib/network.ts | validateTarget، assertPublicAddress، assertResolved، resolvePublicHostname، pinnedLookup، requestResource، collect، decodeHttpResponseBody |
| المتصفح والجمع وaxe | src/lib/browser.ts | browserExecutable، createBrowserCollector، collectPage الداخلية |
| اختبار جاهزية المتصفح | src/lib/browser-selfcheck.ts | browserSelfcheck |
| سياسة طلبات المتصفح | src/lib/resource-policy.ts | resourcePolicy |
| تحويل HTML لنتائج | src/lib/audit.ts | analyze |
| قواعد الصفحة ودمج browser checks | src/lib/checks.ts | evaluateChecks |
| قواعد أمان الاستجابة | src/lib/security.ts | securityChecks |
| اكتشاف API من المصادر | src/lib/api-discovery.ts | discoverApiReferences، apiReferenceResults، mergeApiServices |
| HTTP الوصفي التلقائي | src/lib/auto-api-http.ts | runAutomaticApiHttp، identityCapability |
| إعداد واختبار عزل الحسابات الاختياري | src/lib/api-tests.ts | parseApiConfig، verifyApiConfig، runApiTests |
| العامل العميق | src/lib/repository/job.ts | runRepositoryJob |
| جلب المستودع | src/lib/repository/github.ts | parseRepository، validBranch، GitHubReader.info/resolve/snapshot/blob |
| قواعد المصدر | src/lib/repository/analyzer.ts | eligibleSource، analyzeSource، repositoryScopeChecks |
| AST لـJS/TS وscript chunks | src/lib/repository/ast.ts | supportsJavaScript، analyzeJavaScript |
| قواعد SQL/TOML | src/lib/repository/advanced-security.ts | advancedSecurity |
| تجزئة SQL | src/lib/repository/sql-security.ts | tokenizeSql، sqlSecurity |
| فصل النصوص عن إعداد TOML | src/lib/repository/toml-lines.ts | tomlLines |
| قراءة إصدارات npm المثبتة | src/lib/repository/dependencies.ts | isNpmLockfile، parseLockfile |
| استعلام قاعدة نشرات OSV | src/lib/repository/osv.ts | auditDependencies |
| تحويل نتائج OSV لنتائج التطبيق | src/lib/repository/engine-results.ts | dependencyResults |
| HTTP للتطبيق المنشور — اختياري | src/lib/repository/runtime-security.ts | runRuntimeSecurity |
| تشفير توكنات GitHub واختبارات API | src/lib/repository/vault.ts | encryptToken، decryptToken، repositoryKey، credentialOriginAllowed |
| أنماط الأسرار | src/lib/secret-patterns.ts | secretCount |
| الحجب | src/lib/redaction.ts | redact؛ يعاد تصديره من network.ts |
| الدرجات | src/lib/scoring.ts | SCORE_VERSION، summarizeChecks، scoreReport، metric الداخلية |
| Ollama | src/lib/ai.ts | explanationBody، enrichFinding، parseOllamaResponse |
| التقرير والبرومبتات | src/lib/prompts.ts | remediationPrompt، markdownReport، scanRemediationPrompt |
| مقارنة تقارير واختيار التقرير | src/lib/comparison.ts، src/lib/scan-selection.ts | منطق المقارنة والاختيار المحلي |
| بيانات المعاينة | src/lib/demo.ts | demoReport وdemoRepositoryReport؛ ليست فحصًا حيًا |

### 2.1 إنشاء المهمة، التخزين والحالات

1. واجهة Workspace ترسل POST إلى /api/projects/:id/scan مع authorized:true ونوع url أو repository. الخيارات الحالية: dependencyAudit، runtimeSecurity، apiTests، mode، maxPages.
2. handler يتحقق من الجلسة وصاحب المشروع ومن Origin في طلبات التغيير؛ المصدر المعتمد APP_ORIGIN أو أصل الطلب عند عدم ضبطه.
3. Store.queueScan يتحقق من الملكية والحدود ووجود ربط GitHub عند اللزوم، ويكتب scans وscan_settings. المهمة الجديدة داخليًا queued_v12؛ العامل الحديث ينقلها إلى running_v12. decode يعرض queued/running للعميل ويحافظ على قراءة الإصدارات الأقدم.
4. عامل واحد عبر lock باسم scan-worker؛ heartbeat وتجديد الحجز كل 4 ثوانٍ، مع lease للمهمة. لا يوجد Redis أو distributed task queue حاليًا.
5. Store.progress يحفظ ScanResult والأحداث أثناء العمل؛ finishScan يحفظ completed/partial/failed. cancelScan يحافظ على حالات الطلبات المخططة الملغاة ولا يسمح للعامل بإكمال مهمة لم يعد حجزها ساريًا.
6. جدول scans.result نص JSON. Finding وAuditCheck كلاهما محفوظان داخل النتيجة. لا يوجد جدول findings مستقل أو جدول suppressions أو toolStatus موحد.

الجداول الحالية: users، sessions، projects، scans، repository_links، api_test_configs، scan_settings، locks، limits، worker_health، engine_runtime، engine_diagnostic. قاعدة البيانات الافتراضية DATA_DIR/aegis.sqlite، وDATA_DIR الافتراضي data. مفتاح التشفير data/.repository-key أو REPOSITORY_ENCRYPTION_KEY؛ لا تعرض قيمه الخريطة. توكنات الجلسات مخزنة كـhash، وكلمات المرور عبر scrypt في src/lib/auth.ts.

### 2.2 مسار فحص الرابط

runJob → جمع robots/sitemap والصفحات ضمن سياسة الزحف → analyze/evaluateChecks/securityChecks. العامل يحاول Chromium+axe عند البداية. إذا فشل الجاهزية أو تعطل الجمع، يرجع إلى HTTP مع تحذير ظاهر. وضع المتصفح يشغل JavaScript الصفحة في سياق وسيط بسياسة موارد، ويرصد DOM وpageerror وبعض LCP/CLS وaxe، وليس Lighthouse أو INP ميدانيًا. وضع HTTP يجمع HTML وبعض مصادر JavaScript فقط. تُكتشف الخدمات وتدمج مساراتها؛ ثم runAutomaticApiHttp ينفذ HEAD/OPTIONS دون اعتمادات على الجذر، أو /rest/v1/ لأصول Supabase المعروفة. لا يعتبر ذلك اختبار تفويض أو RLS.

### 2.3 مسار المستودع

runRepositoryJob → repositoryCredential → GitHubReader.snapshot(branch) يثبت commit/tree → GitHubReader.blob لكل ملف مؤهل → analyzeSource → AST وقواعد المصدر وSQL/TOML واكتشاف API. لا يتم تثبيت اعتماديات أو بناء/تشغيل المستودع. عقد git tree تقبل أوضاع 100644/100755 فقط؛ symlinks وsubmodules مستبعدة. LFS pointer لا يُتبع تلقائيًا. حدود المصدر 256KiB، lockfile حتى4MiB، نصوص المجموعة20MiB، ملفات1000 افتراضيًا/3000 كحد أقصى، وقت افتراضي10دقائق. الشجرة المقتطعة أو حدود الجمع تُنتج تقريرًا جزئيًا.

OSV اختياري: parseLockfile يستخرج npm lockv1/2/3 من package-lock.json أو npm-shrinkwrap.json فقط؛ auditDependencies يرسل الاسم والإصدار إلى endpoint ثابت. هذه ليست أداة OSV-Scanner الثنائية. runRuntimeSecurity اختياري لجمع HTTP من نطاق التطبيق الموثق. runAutomaticApiHttp تلقائي من المراجع المكتشفة. runApiTests يعمل فقط عند apiTests:true وبعد إعداد API موثق وتوكنين وموردين تجريبيين.

## 3. التحقق من الملكية وحدود الشبكة

- route.ts: POST /projects/:id/verify يدعم TXT باسم _aegis-audit.<host> وقيمة aegis-audit=<project token> أو الملف /.well-known/aegis-audit.txt. Store.verifyProject يثبت الصلاحية سبعة أيام.
- Store.queueScan: فحص url أو runtimeSecurity يحتاج verified_until صالحًا؛ تحليل repository وحده يحتاج ربطًا وتفويض قراءة المستودع، لا إثبات نطاق الموقع.
- api-tests.ts: ملف إثبات مستقل على أصل API، بلا تحويلات أو توكنات في طلب الإثبات. التوثيق مربوط بمعرف إعداد API وصلاحيته سبعة أيام، والمصفوفة تتأكد من الحجز والتوثيق قبل كل طلب.
- network.ts: يسمح http/https فقط، منافذ80/443 فقط، بلا بيانات اعتماد في URL، ويرفض الشبكات الخاصة والمحجوزة؛ يتحقق من كل IP محلول ويربط الاتصال بواحد منها مع Host/SNI الأصلي. collect يسمح حتى3 تحويلات داخل الأصل المخول، ويفحص allowUrl في كل خطوة. requestResource لا يتبع التحويلات بذاته.
- POST في requestResource محصور بعنوان OSV querybatch الثابت. OPTIONS أضيف للمرحلة الوصفية التلقائية. GitHubReader عنوانه ثابت api.github.com؛ Ollama عنوان إداري من env وليس URL هدف مستخدم.
- resourcePolicy يسمح GET/HEAD لموارد المتصفح ويحظر التنقل الخارجي والطلبات التي تحتوي نمط مفتاح إداري معروف. قد تمر اعتمادات عامة/جلسة في الطلبات الطبيعية للصفحة؛ لا يوجد تحقق حي من صلاحية مفاتيح مكتشفة.
- **فرق مهم عن الخطة الجديدة:** runAutomaticApiHttp في0.12 يرسل HEAD/OPTIONS لأصول API عامة مكتشفة دون إثبات ملكية مستقل لكل أصل. الخطة الجديدة تشترط توثيق النطاق لكل API probe نشط. هذا فرق موثق للمراجعة في مهام SSRF/API اللاحقة، ولم يُغيّر في Task0.

## 4. مخطط النتائج والـSeverity والثقة

Finding الحالي: id، rule، category، severity، confidence:high|medium، title، description، url، evidence، recommendation، checks؛ ومعها file/line/security اختياريًا. القيم category: seo/accessibility/technical/security/ux/geo/performance. لا يوجد tool أو numeric confidence أو fingerprint أو status open/suppressed في المخطط الحالي.

AuditCheck: status:pass|fail|not_applicable|unavailable وweight؛ unavailableReason قد يكون configuration_required أو unsupported أو collection_error، وexecution قد يحوي الطريقة والهوية والوقت وHTTP والحجم والزمن وحالة المحاولة. نجاح قاعدة جزئية ليس شهادة سلامة. معظم Findings المحلية تنشأ عند status=fail فقط؛ الفحوص غير المتاحة تبقى checks.

في audit.ts: Severity تؤخذ من check أو low، والثقة medium لقواعد GEO أو security.basis=indicator، وإلا high. في analyzeSource: Severity ثابتة في جدول القواعد؛ الثقة medium للمؤشرات أو high فقط عند basis=configuration. advancedSecurity SQL/TOML يعطي medium confidence، وseverity high عندما high=true وإلا medium. لا يرفع Ollama أيًا من هذه القيم.

## 5. جرد Rule IDs والمنطق الحالي

يتضمن الجرد check-only items حتى عندما لا تنشئ Finding. الأسماء الديناميكية موثقة كعائلات. استُخرجت66 قاعدة حرفية مباشرة من put/add ومصفوفة analyzeSource، ثم راجعت القواعد الإضافية والمولدة يدويًا أدناه. أسماء المتغيرات في عمود الشرط تشير إلى الدالة في ملف المصدر، وليست تعبيرات يُرسلها المستخدم.

قواعد HTML document=true تصبح unavailable إذا لم تُجمع استجابة HTML ناجحة2xx. أعمدة Severity هي القيمة الحالية عند تحويل الفشل إلى Finding، حتى لو كانت القاعدة عادة check-only. تثبيت اسم القاعدة لا يعني ثبات نطاقها: المورد/الملف/السطر والمرحلة جزء من الدليل.

### src/lib/checks.ts

| Rule ID | الغرض | Severity الحالية | الوزن | شرط الحالة / النطاق |
|---|---|---|---|---|
| `seo.title` | عنوان صفحة وصفي موجود | 'medium' | 2 | Boolean(title) |
| `seo.title-unique` | عنوان واحد داخل المستند | 'low' | 1 | $('title').length===1 |
| `seo.description` | وصف محركات البحث موجود | 'low' | 1 | Boolean(description) |
| `seo.canonical` | رابط canonical مطلق صالح | 'low' | 1 | canonicalValid |
| `seo.h1` | عنوان رئيسي واحد | 'low' | 1 | $('h1').length===1 |
| `seo.indexable` | لا يوجد توجيه noindex مرصود | 'low' | 2 | !/(?:^\|[\s,:])(?:noindex\|none)(?:$\|[\s,])/i.test(robots) |
| `seo.headings` | تدرج مستويات العناوين | 'low' | 1 | headings.length?ordered:'not_applicable' |
| `seo.og-title` | عنوان مشاركة Open Graph | 'low' | 1 | Boolean($('meta[property="og:title"]').attr('content')) |
| `seo.og-description` | وصف مشاركة Open Graph | 'low' | 1 | Boolean($('meta[property="og:description"]').attr('content')) |
| `seo.rendered` | فهرسة المحتوى بعد تشغيل JavaScript | 'low' | 1 | 'unavailable' |
| `geo.structured-present` | بيانات منظمة قابلة للاكتشاف | 'low' | 2 | blocks.length>0&&invalid===0&&typed |
| `geo.structured-valid` | JSON-LD مقروء ويحدد نوعًا | 'low' | 2 | !blocks.length?'not_applicable':invalid===0&&typed |
| `geo.author` | هوية كاتب أو ناشر معرفة | 'low' | 1 | hasAuthor |
| `geo.date` | تاريخ نشر أو تحديث قابل للقراءة | 'low' | 1 | hasDate |
| `geo.structure` | عنوان وأقسام واضحة | 'low' | 1 | $('h1').length===1&&$('h2').length>0 |
| `geo.content` | قدر كافٍ من النص القابل للاستخراج | 'low' | 1 | text.length>=600 |
| `a11y.lang` | لغة HTML محددة | 'medium' | 2 | Boolean($('html').attr('lang')?.trim()) |
| `a11y.image-alt` | خاصية alt للصور | 'medium' | 2 | images.length?missingAlt===0:'not_applicable' |
| `a11y.input-name` | أسماء لحقول الإدخال | 'medium' | 2 | controls.length?unnamed===0:'not_applicable' |
| `a11y.button-name` | أسماء للأزرار | 'medium' | 2 | buttons.length?unnamedButtons===0:'not_applicable' |
| `a11y.ids` | معرفات عناصر غير مكررة | 'low' | 1 | duplicateIds===0 |
| `a11y.main` | منطقة محتوى رئيسية معرفة | 'low' | 1 | $('main,[role="main"]').length>0 |
| `a11y.contrast` | تباين الألوان الفعلي | 'low' | 1 | 'unavailable' |
| `a11y.keyboard` | رحلات لوحة المفاتيح | 'low' | 1 | 'unavailable' |
| `ux.viewport` | إعداد عرض الجوال موجود | 'medium' | 2 | Boolean(viewport) |
| `ux.zoom` | لا يوجد منع تكبير مرصود | 'low' | 1 | viewport?!/user-scalable\s*=\s*no\|maximum-scale\s*=\s*1(?:\.0)?(?:\s\|,\|$)/i.test(viewport):'not_applicable' |
| `ux.direction` | اتجاه المستند العربي محدد | 'low' | 1 | /^ar(?:-\|$)/i.test($('html').attr('lang')??'')?$('html').attr('dir')==='rtl':'not_applicable' |
| `ux.navigation` | منطقة تنقل دلالية | 'low' | 1 | $('nav,[role="navigation"]').length>0 |
| `ux.visual` | التمدد الأفقي عند عرض الصفحة | 'low' | 1 | 'unavailable' |
| `technical.http` | استجابة HTTP ناجحة | 'high' | 2 | page.status>=200&&page.status<300 |
| `technical.html` | محتوى HTML متاح | 'medium' | 1 | (page.headers['content-type']??'').includes('html') |
| `technical.doctype` | تعريف HTML5 doctype | 'low' | 1 | /^\s*<!doctype html/i.test(page.body) |
| `technical.mixed` | لا موارد HTTP صريحة داخل HTTPS | 'low' | 2 | page.url.startsWith('https:')?mixed===0:'not_applicable' |
| `technical.console` | أخطاء console وقت التشغيل | 'low' | 1 | 'unavailable' |
| `performance.response` | زمن جلب HTTP ضمن 1500ms | 'low' | 1 | measuredTime?page.elapsedMs<=1500:'unavailable' |
| `performance.payload` | حجم HTML ضمن 250KiB | 'low' | 1 | measuredBytes?page.bytes<=250*1024:'unavailable' |
| `performance.lcp` | LCP من المتصفح | 'low' | 1 | 'unavailable' |
| `performance.cls` | CLS من المتصفح | 'low' | 1 | 'unavailable' |
| `performance.inp` | INP ميداني | 'low' | 1 | 'unavailable' |

### src/lib/security.ts

| Rule ID | الغرض | Severity الحالية | الوزن | شرط الحالة / النطاق |
|---|---|---|---|---|
| `security.https` | استخدام HTTPS | 'medium' | high→4 / medium→2 / other→1 | https |
| `security.csp` | تحليل سياسة CSP المفروضة | 'medium' | high→4 / medium→2 / other→1 | cspState |
| `security.nosniff` | منع تخمين MIME | 'low' | high→4 / medium→2 / other→1 | h['x-content-type-options']?.trim().toLowerCase()==='nosniff' |
| `security.hsts` | HSTS بمدة موجبة | 'low' | high→4 / medium→2 / other→1 | https?Boolean(maxAge&&Number(maxAge[1])>0):'not_applicable' |
| `security.frame` | سياسة تقييد تضمين الصفحة | 'low' | high→4 / medium→2 / other→1 | frame |
| `security.referrer` | سياسة Referrer مقيدة صالحة | 'low' | high→4 / medium→2 / other→1 | Boolean(ref&&ref!=='unsafe-url'&&ref!=='no-referrer-when-downgrade') |
| `security.cookies` | حماية الكوكيز المرصودة | 'medium' | high→4 / medium→2 / other→1 | cookies.length?issues.length===0:'not_applicable' |
| `security.cors` | اتساق رؤوس CORS | 'low' | high→4 / medium→2 / other→1 | cors?!(cors.trim()==='*'&&credentials):'not_applicable' |
| `security.secret` | لا أنماط أسرار مرتفعة الصلاحية في المصادر | 'high' | high→4 / medium→2 / other→1 | n===0 |
| `security.password-form` | إرسال كلمات المرور عبر HTTPS وPOST | 'high' | high→4 / medium→2 / other→1 | passwords?insecure===0:'not_applicable' |
| `security.active-mixed` | لا مراجع محتوى نشط عبر HTTP | 'medium' | high→4 / medium→2 / other→1 | https?mixed===0:'not_applicable' |
| `security.sri` | إعلان SRI للسكريبتات الخارجية | 'low' | high→4 / medium→2 / other→1 | external?noIntegrity===0:'not_applicable' |

### src/lib/repository/analyzer.ts

| Rule ID | الغرض | Severity الحالية | الوزن | شرط الحالة / النطاق |
|---|---|---|---|---|
| `repo.secret` | أنماط أسرار مرتفعة الصلاحية | 'high' | high→4 / medium→2 / other→1 | secrets?'fail':'pass' |
| `repo.jwt-expiry` | تجاهل انتهاء صلاحية JWT | 'high' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.jwt-none` | خوارزمية JWT غير موقعة | 'high' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.cors-reflection` | عكس Origin مع السماح بالاعتمادات | 'high' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.weak-hash` | استخدام MD5 أو SHA1 | 'medium' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.eval` | تنفيذ نص ديناميكي | 'medium' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.html-sink` | إدخال HTML مباشر | 'medium' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.tls-bypass` | تعطيل التحقق من TLS | 'high' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.sql-concat` | استعلام SQL مبني ديناميكيًا | 'high' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.shell` | إنشاء أمر نظام ديناميكي | 'high' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.public-secret` | إعداد سر في متغير واجهة عامة | 'high' | high→4 / medium→2 / other→1 | AST للـJS/TS، أو fallback نصي محدود حيث يدعمه analyzeSource |
| `repo.json-valid` | صياغة JSON قابلة للقراءة | 'low' | high→4 / medium→2 / other→1 | valid?'pass':'fail' |
| `repo.dependencies-pinned` | اعتماديات بمراجع قابلة للضبط | 'low' | high→4 / medium→2 / other→1 | floating?'fail':'pass' |
| `repo.dependencies-json` | قراءة package.json | 'low' | high→4 / medium→2 / other→1 | 'fail' |
| `repo.language-rules` | قواعد اللغة المتخصصة | 'low' | high→4 / medium→2 / other→1 | 'unavailable' |

### 5.1 تحديثات المتصفح للقواعد الأساسية

- seo.rendered: pass إذا DOM HTML المعروض متاح، وإلا unavailable؛ لا Search Console أو فهرسة حقيقية.
- technical.console: fail عند pageerror مرصود وإلا pass؛ لا يضمن غياب الأخطاء خارج نافذة الرصد.
- ux.visual: fail للتمدد الأفقي في viewport وإلا pass؛ ليست مراجعة تصميم بصرية.
- performance.lcp: pass عند LCP صالح موجب ≤2500ms وإلا fail؛ unavailable عند غياب القياس.
- performance.cls: pass عند CLS صالح ≥0 و≤0.1 وإلا fail؛ unavailable عند غياب القياس.
- a11y.contrast: تأخذ status/evidence من axe.color-contrast إذا وجدت؛ severity/weight للقالب الأساسي لا يعاد تعيينهما عبر update.
- performance.inp وa11y.keyboard يبقيان unavailable في المحرك الحالي.

### 5.2 SQL وSupabase/TOML — الملف advanced-security.ts وsql-security.ts

| Rule ID | Severity | منطق الحالة الحالي |
|---|---|---|
| repo.sql.parse | medium | pass لتجزئة النص المكتملة، unavailable للاقتباس/التعليق/الأقواس غير المكتملة أو الحدود؛ لا يفحص نحو PostgreSQL كاملًا ولا ينشئ Finding عند النجاح |
| repo.rls-disabled | high | fail لتعليمة DISABLE ROW LEVEL SECURITY، pass لتعليمة ENABLE؛ لا يثبت الحالة الحية |
| repo.sql.rls-declaration | medium | pass عند CREATE TABLE وتفعيل أخير مطابق للاسم داخل الملف؛ وإلا unavailable لا يفترض التعطيل |
| repo.sql.policy-shape | medium | unavailable إذا تعذر تحديد جدول CREATE POLICY بصيغته المدعومة |
| repo.sql.policy-open-read | medium | مؤشر fail لشرط USING دائم true/افتراضي مع public/anon/authenticated؛ غير ذلك pass يعني عدم رصد النمط المحدد فقط |
| repo.sql.policy-open-write | high | مؤشر fail لشروط كتابة واسعة صريحة/افتراضية/موروثة؛ يفحص USING وWITH CHECK في UPDATE، وUSING في DELETE |
| repo.sql.grant-write | high | fail لمراجع GRANT تعديل جدول إلى public/anon؛ لا يثبت تجاوز RLS |
| repo.sql.grant-execute | medium | fail/مراجعة لمنح EXECUTE أو ALL لدالة/procedure/routine إلى public/anon؛ ليس منح تعديل جدول |
| repo.sql.definer-search-path | high | fail إذا SECURITY DEFINER دون SET search_path صريح، وإلا pass لوجود الإعداد فقط |
| repo.sql.definer-row-security | high | fail عند SET row_security=off/false/0 ضمن تعريف SECURITY DEFINER |
| repo.supabase-config-parse | medium | unavailable عند نص TOML غير مكتمل |
| repo.supabase-config-shape | medium | unavailable عند صيغة اسم function لا يدعمها القارئ المحدود |
| repo.supabase-verify-jwt | high | fail عند verify_jwt=false في قسم function معروف، pass عند true؛ webhook عام قد يكون مقصودًا |

كل هذه النتائج مؤشر/مراجعة للسياق، لا إثبات استغلال. حد SQL60000 خطوة و250 ملاحظة لكل ملف؛ لا إعادة بناء شاملة لحالة جميع migrations أو تحليل كل PL/pgSQL/ALTER POLICY.

### 5.3 الاكتشاف والنقل التلقائي والاختبارات الاختيارية

| Rule ID / family | الملف | Severity والمنطق |
|---|---|---|
| security.api-discovery | src/lib/api-discovery.ts | check تقني pass لاكتشاف أصل ومسارات نصية؛ لا severity صريحة أو Finding أمني، ولا يثبت وصولًا للشبكة |
| security.api-reference-https | src/lib/api-discovery.ts | medium؛ fail لمراجع HTTP، pass لمراجع HTTPS؛ ثقة medium ومؤشر من المصدر |
| technical.api-http-response | src/lib/auto-api-http.ts | check تقني، لا severity صريحة؛ pass لاستجابة HEAD بلا تحويل، unavailable لاتصال/تحويل/مهلة؛ لا ينشئ Finding تفويض |
| security.api-http-cors | src/lib/auto-api-http.ts | high لانعكاس Origin التجريبي مع credentials، medium لتركيب wildcard+credentials؛ غير2xx/تحويل/اتصال→unavailable؛ pass يخص Origin والمسار الوصفي فقط |
| security.api-http-hsts | src/lib/auto-api-http.ts | low؛ مشتقة من security.hsts على HEAD فعلي |
| security.api-http-nosniff | src/lib/auto-api-http.ts | low؛ مشتقة من security.nosniff على HEAD فعلي |
| security.api-http-cookies | src/lib/auto-api-http.ts | medium؛ مشتقة من security.cookies على HEAD فعلي |
| security.api-baseline | src/lib/api-tests.ts | check أمن بلا severity صريحة؛ المالك يجب أن يحصل200 وعلامة مورده، وإلا unavailable؛ ليس Finding عند فشل الإعداد |
| security.api-auth | src/lib/api-tests.ts | high عند كشف علامة مورد لحساب غير مالك/زائر، في kind=api؛ لا يظهر كعنصر عام غير منفذ في0.12 |
| security.supabase-rls | src/lib/api-tests.ts | high لكشف المورد التجريبي في kind=supabase/storage؛ يثبت قراءة ذلك المورد لا كل سياسات RLS |
| repo.runtime | src/lib/repository/runtime-security.ts | check جمع تقني عند التنفيذ، أو unavailable عند عدم التفعيل/فقد التوثيق؛ لا severity صريحة ولا Finding استغلال |
| repo.dependencies-cve | src/lib/repository/engine-results.ts | check اكتمال unavailable عند تعطيل/فشل/جزئية OSV؛ لا severity صريحة أو إعلان خلو |
| repo.osv.<npm-name>@<version> | src/lib/repository/engine-results.ts، osv.ts | Severity من database_specific.severity: critical/high/moderate→medium/medium/low، وغير المعروف info مع severityKnown=false؛ ليست CVSS calculation. Finding لكل advisory، وثقته high لمطابقة الإصدار فقط |

مصفوفة الحسابين تطلب صراحة apiTests:true؛ تثبت baseline المالكين أولًا، ثم حساب الآخر والزائر. حالات الرفض المعروفة أو [] في API/REST قد تمر بعد baseline، أما Storage فلا يعتمد [] كرفض. ليست هناك محاولات كتابة. القيم السرية والأجسام لا تُحفظ.

### 5.4 axe — جميع IDs الممكنة حسب النسخة المثبتة

المصدر src/lib/browser.ts؛ العائلة axe.<ruleId>، تعمل عندما تتوفر جلسة Chromium وaxe.run. الإعداد runOnly للوسوم wcag2a/wcag2aa/wcag21a/wcag21aa. كتالوج axe-core4.14.0 المثبت يعيد **69** قاعدة لهذه الوسوم؛ ليست جميعها قابلة للتطبيق على كل صفحة، ولا تمثل نتائج فحص لموقع بعينه.

لكل ID أدناه: status من passes/violations/incomplete → pass/fail/unavailable. severity=medium عندما impact=critical أو serious، وإلا low. الوزن critical→4، serious→3، وإلا1. هذا تحويل محلي لأثر الوصول، وليس تصنيف ثغرة أمنية Critical. قد يعود impact=null للعناصر الناجحة.

- `axe.area-alt`
- `axe.aria-allowed-attr`
- `axe.aria-braille-equivalent`
- `axe.aria-command-name`
- `axe.aria-conditional-attr`
- `axe.aria-deprecated-role`
- `axe.aria-hidden-body`
- `axe.aria-hidden-focus`
- `axe.aria-input-field-name`
- `axe.aria-meter-name`
- `axe.aria-progressbar-name`
- `axe.aria-prohibited-attr`
- `axe.aria-required-attr`
- `axe.aria-required-children`
- `axe.aria-required-parent`
- `axe.aria-roledescription`
- `axe.aria-roles`
- `axe.aria-tab-name`
- `axe.aria-toggle-field-name`
- `axe.aria-tooltip-name`
- `axe.aria-valid-attr-value`
- `axe.aria-valid-attr`
- `axe.audio-caption`
- `axe.autocomplete-valid`
- `axe.avoid-inline-spacing`
- `axe.blink`
- `axe.button-name`
- `axe.bypass`
- `axe.color-contrast`
- `axe.css-orientation-lock`
- `axe.definition-list`
- `axe.dlitem`
- `axe.document-title`
- `axe.duplicate-id-aria`
- `axe.form-field-multiple-labels`
- `axe.frame-focusable-content`
- `axe.frame-title-unique`
- `axe.frame-title`
- `axe.html-has-lang`
- `axe.html-lang-valid`
- `axe.html-xml-lang-mismatch`
- `axe.image-alt`
- `axe.input-button-name`
- `axe.input-image-alt`
- `axe.label-content-name-mismatch`
- `axe.label`
- `axe.link-in-text-block`
- `axe.link-name`
- `axe.list`
- `axe.listitem`
- `axe.marquee`
- `axe.meta-refresh`
- `axe.meta-viewport`
- `axe.nested-interactive`
- `axe.no-autoplay-audio`
- `axe.object-alt`
- `axe.p-as-heading`
- `axe.role-img-alt`
- `axe.scrollable-region-focusable`
- `axe.select-name`
- `axe.server-side-image-map`
- `axe.summary-name`
- `axe.svg-img-alt`
- `axe.table-fake-caption`
- `axe.td-has-header`
- `axe.td-headers-attr`
- `axe.th-has-data-cells`
- `axe.valid-lang`
- `axe.video-caption`

## 6. الدرجات والتكرار والثقة

src/lib/scoring.ts: SCORE_VERSION=aegis-checklist-v3. summarizeChecks يختزل حاليًا بنفس url|rule، ثم metric يحسب:

- الدرجة = تقريب100 × مجموع أوزان pass / مجموع أوزان pass+fail.
- التغطية = تقريب100 × عدد pass+fail / عدد pass+fail+unavailable.
- not_applicable مستبعد من المقامين؛ unknown/empty يعيد null وليس صفرًا أو100.
- findings.severity منفصلة عن score؛ الأوزان تتبع المنشئ وليست CVSS. لا ML confidence score ولا precision/recall في المحرك الحالي.
- **فرق موثق:** بعض السجلات تُبقي أكثر من observation لنفس rule/url (عدة API origins أو عدة SQL statements)، بينما summarizeChecks يجمعها إلى واحدة. قد تختلف أرقام السجل عن مقام الدرجة أو تُغطى نتيجة بأخرى. تُسجل هذه الملاحظة لمهمة Normalizer/benchmark؛ Task0 لا يغير الخوارزمية.
- لا fingerprint suppression أو dedupe بين أدوات مستقلة. jobs.ts يزيل Findings حسب id، وتختلف قواعد اختزال checks بين الطبقات. ملفات المصدر تستخدم id/hash محليًا؛ هذا ليس النظام الموحد المطلوب في Task2.

## 7. أين تعرض وتحفظ النتائج؟

| الغرض | الملف |
|---|---|
| التنقل والتقرير المختار وتفاصيل Finding | src/components/workspace.tsx |
| الدرجات والتغطية | src/components/score-dashboard.tsx |
| سجل pass/fail/unavailable/NA والبحث وJSON | src/components/check-ledger.tsx |
| مركز الأمن والمجموعات والقدرات خارج الطلب | src/components/security-center.tsx |
| ملخص المحركات وOSV وHTTP | src/components/security-engines.tsx |
| منهجية وأثر وخطوات إصلاح Finding | src/components/security-details.tsx |
| commit وجرد الملفات | src/components/repository-report.tsx |
| أحداث المرحلة والمصداقية | src/components/scan-activity.tsx |
| تقرير الطباعة وبرومبت الإصلاح | src/components/scan-outputs.tsx |
| Markdown وprompts على الخادم/المعاينة | src/lib/prompts.ts |

GET /api/state وGET /api/scans/:id يعيدان بيانات صاحب الحساب؛ /scans/:id/checks سجل JSON، و/scans/:id/export تقرير Markdown. البرومبت الشامل عبر POST /scans/:id/prompt، وبرومبت Finding عبر /scans/:id/findings/:findingId/prompt. الردود نصوص React وليست تشغيلًا لمحتوى Finding. لا endpoints suppression حاليًا.

## 8. Ollama والأسرار

enrichFinding يرسل POST إلى /api/chat على OLLAMA_BASE_URL الإداري. explanationBody يرسل title وevidence وrecommendation بعد redact وحد6000 حرف، مع system instruction يصف الأدلة كبيانات غير موثوقة. الموديل الافتراضي qwen2.5:1.5b أو OLLAMA_MODEL من env. stream:false، temperature0.2، num_predict240، مهلة90ثانية، رد≤32768bytes، وقفل ollama واحد. parseOllamaResponse يرفض الرد الفارغ/المبتور ويحجبه قبل العرض. route يعيد verified:false ولا يعدل Finding أو Severity أو الدرجة.

src/lib/redaction.ts يخفي أنماط الأسرار/JWT/DB-URIs/Bearer/query credentials والحقول الشائعة باستخدام placeholders كاملة، وليس تنسيق first4+last4 المطلوب في Task2. secretCount يدعم أنماط Supabase secret، Stripe live، GitHub، Slack، OpenAI sk-proj، private-key PEM وDB URI وJWT service_role. لا تحقق حي من مفاتيح. redaction أوسع من detector (مثل AKIA)؛ لا يثبت ذلك اكتمال كشف AWS أو كل صيغ OpenAI. لا بحث في تاريخ git أو built output مستبعد من tree reader؛ فحص frontend يتوقف على المصادر المجموعة فعليًا.

التوكنات المصرح بها لربط GitHub/حسابات الاختبار تُحفظ مشفرة AES-256-GCM في vault؛ لا تُعد أسرارًا مكتشفة يجب إرسالها للموديل. لا تعرض هذه الوثيقة أي .env.local أو بيانات SQLite أو مفاتيح مستخدمين.

## 9. جرد البيئة والأدوات — قراءة فقط

الأوامر المنفذة: node -v، npm -v، command -v وأوامر version للأدوات المتاحة فقط. لا تثبيت أو تشغيل targets أو containers في هذه المهمة.

| المكون | النتيجة في بيئة العمل الحالية |
|---|---|
| Node.js | v24.22.1 |
| npm | 11.9.0؛ تحذير npm عن env http-proxy لا يمنع تنفيذ الاختبارات |
| Git | 2.52.0 |
| Python | 3.12.14 |
| Docker | غير موجود في PATH؛ docker -v غير قابل للتنفيذ |
| Redis server / cli | غير موجودين في PATH |
| Semgrep | غير موجود في PATH أو dependencies |
| Gitleaks | غير موجود في PATH أو dependencies |
| TruffleHog | غير موجود في PATH أو dependencies |
| OSV-Scanner binary | غير موجود؛ استعلام OSV اليدوي الموجود مختلف |
| Nuclei | غير موجود في PATH أو dependencies |
| Chromium | /usr/bin/chromium؛ 156.0.8078.79 على Debian13؛ أخرج wrapper تحذير unexpected operator ثم رقم الإصدار |
| Next.js |16.4.5 مثبت |
| TypeScript |5.9.3 مثبت |
| Playwright |1.65.0 مثبت |
| axe-core |4.14.0 مثبت |
| cheerio |1.2.0 مثبت |
| ipaddr.js |2.5.0 مثبت |
| Zod |4.6.7 مثبت |

وجود Chromium binary لا يثبت جاهزية socket/sandbox أو نجاح رحلة متصفح. لا يوجد اتصال بسيرفر المستخدم أو VPS ثانٍ في Task0؛ لا نستنتج إصداراتهما من هذه البيئة. Docker غير المتاح يؤثر على تجهيز targets المعزولة في Task1 والخدمة فيTask3.

## 10. تحقق Task0 والحدود بين المهام

- فُحصت الحالة النظيفة للمصدر قبل البدء ومرجع b2fcb2f.
- ملف الخريطة هو التغيير الوحيد المطلوب في هذه المهمة؛ تطبيق0.12.0 ومسار التشغيل لا يُعدلان.
- جرد القواعد أُخرج من AST ملفات المنشئين والكتالوج المحلي لـaxe، مع مراجعة المعرفات الديناميكية وصيغ Severity ومناطق التوثيق والتخزين.
- الاختبارات الموجودة تُشغّل كتحقق عدم تراجع، وليست Benchmark قياس جودة. نتيجة التنفيذ تُسجّل أسفل الوثيقة بعد اكتمال الأمر.
- لا Benchmark بعد: Task1 لم تبدأ، ولا baseline.json أو recall/precision أو ادعاء95%/85%. لا أهداف Docker أو أسرار مزروعة أو أدوات خارجية شُغلت.
- المهمة التالية، بعد مراجعة المستخدم: Task1 Benchmark harness and baseline، بالترتيب المعتمد. لا يبدأ تنفيذها تلقائيًا.

### نتيجة التحقق الفعلية

`npm test`: **185 اختبارًا ناجحًا، صفر فشل** في بيئة هذه المهمة، مدة الاختبارات نحو9.5ثانية. هذا ليس Benchmark ولا قياسًا للـrecall أوprecision. لن تُنقل أرقام الاختبارات كأنها دقة كشف ثغرات.
