# Private Messenger v2 — PostgreSQL + HTTPS + Persistent Accounts

نسخه‌ی Production-oriented پروژه‌ی پیام‌رسان خصوصی. این نسخه نسبت به prototype قبلی، کاربران/جلسات/درخواست‌ها/مخاطب‌ها/پیام‌ها را در PostgreSQL دائمی می‌کند و برای HTTPS، WebSocket، QR و مدیریت حساب آماده است.

> **نکته مهم:** «Production-ready» در این پروژه یعنی معماری و کد برای استقرار واقعی آماده‌تر شده است؛ این پروژه جایگزین ممیزی امنیتی مستقل یا پروتکل E2E رمزنگاری‌شده‌ی آزموده‌شده مثل Signal Protocol نیست. قبل از استفاده عمومی، حتماً TLS واقعی، secrets management، rate limiting در لایه edge، backup، monitoring و security audit را انجام دهید.

## امکانات

- PostgreSQL دائمی: کاربران، sessionها، درخواست‌ها، blockها، گفتگوها، پیام‌ها و حذف برای من.
- بدون شماره تلفن و ایمیل: User ID تصادفی + `@username` + کد اتصال.
- ورود مجدد با **Recovery Key**؛ خود کلید به‌صورت hash روی سرور نگهداری می‌شود.
- امکان تغییر username، چرخش کد اتصال، چرخش Recovery Key، تغییر PIN، خروج و حذف کامل حساب.
- صفحه انتخاب مخاطب و فهرست گفتگوها.
- درخواست گفتگو: Accept / Reject / Block.
- QR اتصال بدون قرار دادن PIN یا private key در QR.
- WebSocket برای پیام لحظه‌ای و eventهای حذف/ویرایش/قبول درخواست.
- پیام‌ها حداکثر ۶۰ ثانیه عمر دارند و **سرور** نیز expiry را enforce می‌کند.
- حذف برای من در PostgreSQL ذخیره می‌شود؛ حذف برای همه از سرور حذف و به هر دو طرف broadcast می‌شود.
- حذف کل گفتگو برای هر دو طرف.
- رمزنگاری محتوای پیام در client با ECDH P-256 + AES-GCM. سرور متن پیام را نمی‌بیند.
- PIN محلی با PBKDF2/SHA-256 و salt تصادفی؛ PIN خام ذخیره نمی‌شود.
- CSP، `nosniff`، `Referrer-Policy` و `frame-ancestors` برای پاسخ‌های static.
- HTTPS مستقیم با cert/key یا TLS termination پشت Caddy/Nginx.

## اجرای محلی با PostgreSQL

نیازمندی: Node.js 20+ و PostgreSQL 16+.

```bash
npm install
cp .env.example .env
# DATABASE_URL را مطابق PostgreSQL خودتان تنظیم کنید
npm start
```

سپس:

```text
http://localhost:3000
```

برای تست دو طرفه، مرورگر/پروفایل دوم را هم به همان سرور وصل کنید.

## اجرای PostgreSQL + app با Docker Compose

```bash
docker compose up -d --build
```

سپس یک reverse proxy مثل Caddy را روی دامنه قرار دهید و `https://chat.example.com` را به `127.0.0.1:3000` proxy کنید. مقدار `PUBLIC_BASE_URL` و `ALLOWED_ORIGIN` را هم با دامنه واقعی تنظیم کنید.

**رمز PostgreSQL داخل compose را حتماً تغییر دهید و در استقرار واقعی از secret manager استفاده کنید.**

## HTTPS

دو حالت پشتیبانی می‌شود:

1. **TLS termination در Caddy/Nginx**: ساده‌تر و توصیه‌شده؛ Node روی localhost با HTTP کار می‌کند و reverse proxy HTTPS را مدیریت می‌کند.
2. **HTTPS مستقیم در Node**: مسیرهای `HTTPS_KEY` و `HTTPS_CERT` را در env بدهید.

برای Web Crypto و PWA/امنیت مرورگر، محیط production باید HTTPS باشد.

## مدل حساب

ثبت‌نام:

- username عمومی، مثال `@ali83`
- User ID تصادفی داخلی
- Connection Code قابل اشتراک
- Recovery Key برای ورود مجدد
- public key برای رمزنگاری پیام

**Recovery Key را به کاربر فقط هنگام ساخت/چرخش نشان دهید و در جای امن نگهداری کنید.** سرور plaintext آن را ذخیره نمی‌کند.

## QR

QR یک share URL می‌سازد که فقط اطلاعات شناسایی عمومی را حمل می‌کند. private key و PIN هرگز وارد QR نمی‌شوند. با باز کردن لینک، username در صفحه «انتخاب مخاطب» قرار می‌گیرد و کاربر می‌تواند درخواست گفتگو بفرستد.

## امنیت و محدودیت‌های باقی‌مانده قبل از عرضه عمومی

- برای سطح امنیتی بالا از یک پروتکل E2E آزموده‌شده استفاده و آن را audit کنید؛ ECDH/AES-GCM دست‌ساز به‌تنهایی Signal-level security نیست.
- private key فعلاً در localStorage به‌صورت JWK export شده است؛ برای محصول حساس، non-extractable Web Crypto keys + IndexedDB و طرح recovery امن‌تر لازم است.
- key verification / fingerprint / safety number هنوز اضافه نشده است.
- WebSocket احراز هویت را با session cookie یا subprotocol انجام می‌دهد؛ در production لاگ‌های reverse proxy نباید credential را ثبت کنند.
- rate limiting فعلی در Node است؛ برای چند instance، rate limit توزیع‌شده مثل Redis یا edge gateway لازم است.
- برای چند instance، presence و event delivery بهتر است با Redis/NATS یا broker مشابه scale شود.
- backup و point-in-time recovery برای PostgreSQL تنظیم کنید.
- monitoring، alerting، audit logging حداقلی و حذف PII از logها را تنظیم کنید.
- push notification، attachment storage، abuse prevention و account recovery UX در این نسخه پیاده‌سازی نشده‌اند.

## ساختار

```text
private-messenger/
├── public/
│   └── index.html
├── server.js
├── package.json
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```
