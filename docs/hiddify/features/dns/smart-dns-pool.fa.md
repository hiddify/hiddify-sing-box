<div dir="rtl">

# مجموعهٔ هوشمند DNS (Smart DNS pool)

[English](smart-dns-pool.en.md) · [همهٔ قابلیت‌های هیدیفای](../../index.fa.md)

مجموعهٔ هوشمند DNS یک سرور DNS محلی است که هر پرسش را به یکی از resolverهای بالادستی متعدد
می‌فرستد. وقتی یک resolver کند، محدودشده یا از کار افتاده باشد، سراغ دیگری می‌رود و
resolverهای ازکارافتاده را در پس‌زمینه بررسی می‌کند تا دوباره پاسخ دهند. این یک سرویس است:
`"type": "smart_dns_pool"` در فهرست `services`.

## چرا از آن استفاده کنیم

برای [DNSTT](../protocols/dnstt.fa.md) ساخته شده است. تونل DNS پرسش‌های زیادی می‌فرستد و resolverهای
عمومی زود شروع به محدود کردن یا رد کردن آن‌ها می‌کنند. DNSTT را به‌جای یک resolver به این
مجموعه وصل کنید تا مجموعه پرسش‌ها را میان همهٔ resolverهای شما پخش کند. DNSTT فقط یک resolver
محلی معمولی می‌بیند.

هر برنامهٔ دیگری که از یک سرور DNS ساده استفاده می‌کند هم می‌تواند از آن استفاده کند.

## چطور از فیلترینگ عبور می‌کند

به‌تنهایی چیزی را پنهان نمی‌کند. وقتی تک‌تک resolverها محدود یا مسدود می‌شوند، با پخش بار و
کنار گذاشتن resolverهایی که از کار می‌افتند، تونل DNS را سرپا نگه می‌دارد.

## چطور کار می‌کند

- مجموعه روی UDP و TCP در `listen` و `listen_port` گوش می‌دهد.
- برای هر پرسش، resolverهایی را که از کار نیفتاده‌اند بر اساس `load_balance` مرتب می‌کند و یکی
  پس از دیگری امتحان می‌کند تا یکی پاسخ دهد. هر تلاش حداکثر `per_attempt` و کل پرسش حداکثر
  `deadline` طول می‌کشد.
- وقتی resolverی با رد درخواست، خطای سرور یا HTTP 429 پاسخ دهد، مجموعه نرخ ارسال به آن را کم
  می‌کند و تا وقتی resolver پاسخ می‌دهد، دوباره بالا می‌برد.
- پس از `down_after` بار timeout یا خطای شبکه پشت سر هم، resolver از کار افتاده حساب می‌شود.
  مجموعه هر `probe_interval` همان پرسش ناموفق را برایش می‌فرستد. وقتی پاسخ دهد، دوباره به کار
  می‌رود.

## پیکربندی

```json
{
  "services": [
    {
      "type": "smart_dns_pool",
      "tag": "dns-pool",
      "listen": "127.0.0.1",
      "listen_port": 19876,
      "load_balance": "lowest_latency",
      "upstreams": [
        { "type": "udp", "address": "8.8.8.8:53" },
        { "type": "udp", "address": "1.1.1.1:53" },
        { "type": "https", "address": "https://cloudflare-dns.com/dns-query" }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "dnstt",
      "tag": "dnstt-out",
      "domain": "t.example.com",
      "pubkey": "<server public key, hex>",
      "resolvers": ["127.0.0.1:19876"]
    }
  ]
}
```

در DNSTT نشانی مجموعه را به صورت `host:port` و بدون پیشوند `udp://` بنویسید.

| فیلد | نوع | پیش‌فرض | معنی |
|---|---|---|---|
| `listen` | string | `"127.0.0.1"` | نشانی گوش دادن. |
| `listen_port` | int | الزامی | درگاه گوش دادن، برای UDP و TCP. |
| `upstreams` | list of objects | الزامی | resolverها. دست‌کم یکی. فیلدها در جدول پایین. |
| `load_balance` | string | `"roundrobin"` | `roundrobin` به نوبت می‌چرخد. `weighted` بر اساس `weight` تصادفی انتخاب می‌کند. `lowest_latency` سریع‌ترین را ترجیح می‌دهد و resolverهای تست‌نشده را اول امتحان می‌کند تا هر کدام اندازه‌گیری شوند. |
| `deadline` | duration | `5s` | بیشترین زمان یک پرسش، با همهٔ تلاش‌ها. |
| `per_attempt` | duration | `2s` | بیشترین زمان یک تلاش روی یک resolver. |
| `probe_interval` | duration | `5s` | هر چند وقت یک resolver ازکارافتاده بررسی شود. |
| `down_after` | int | `8` | تعداد timeout یا خطای شبکهٔ پشت سر هم تا از کار افتادن resolver. |

هر مورد در `upstreams`:

| فیلد | نوع | پیش‌فرض | معنی |
|---|---|---|---|
| `type` | string | `"udp"` | `udp`، `tcp`، `tls` (DoT، یا `dot`) یا `https` (DoH، یا `doh`). |
| `address` | string | الزامی | برای `udp`، `tcp` و `tls` به صورت `host:port`؛ برای `https` نشانی کامل. |
| `weight` | int | `0` | در `weighted` به کار می‌رود. resolver با وزن `0` فقط وقتی به کار می‌رود که هیچ resolver وزن‌داری در دسترس نباشد. |
| `name` | string | پروتکل و نشانی، مثلاً `udp://8.8.8.8:53` | نامی برای لاگ‌ها. |

فیلدهای دیگر listen در sing-box پذیرفته می‌شوند، ولی فقط `listen` و `listen_port` به کار
می‌روند.

فیلد `smart_pool` خود DNSTT مجموعه‌ای مثل این را با تنظیمات پیش‌فرض درون همان خروجی راه
می‌اندازد و resolverهایی را که بررسی DNSTT را قبول شوند در آن می‌گذارد.

## همچنین ببینید

- [DNSTT](../protocols/dnstt.fa.md)

</div>
