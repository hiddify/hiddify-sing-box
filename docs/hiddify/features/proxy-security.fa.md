<div dir="rtl">

# امنیت پراکسی (Proxy security)

[English](proxy-security.en.md) · [همهٔ قابلیت‌های هیدیفای](../index.fa.md)

هر خروجی و endpoint از روی گزینه‌هایش امن یا ناامن علامت می‌خورد و اگر ناامن باشد، دلیلش هم گفته
می‌شود. اپ این علامت را در فهرست پراکسی‌ها نشان می‌دهد. گزینه‌ای ندارد: هنگام ساخته شدن خروجی تعیین
می‌شود.

## چرا از آن استفاده کنیم

پراکسی ترافیک را از فیلتر رد می‌کند، اما هر پراکسی‌ای آن را پنهان نمی‌کند. پراکسی SOCKS یا HTTP،
VLESS یا Trojan بدون TLS، یا Shadowsocks با روش `none` همه‌چیز را بی‌رمز می‌فرستد: شبکهٔ میان دستگاه و
سرور، و هر کسی که آن را فیلتر می‌کند، می‌تواند آن را بخواند و تغییر دهد. TLS با `insecure` روشن هر
گواهی‌ای را می‌پذیرد، پس هر کسی در مسیر می‌تواند خود را جای سرور جا بزند. کاربر این را در لینک اشتراک
به‌ندرت می‌بیند؛ این علامت به او می‌گوید.

## چگونه از فیلتر عبور می‌کند

عبور نمی‌دهد. فقط گزارش می‌دهد گزینه‌های دیگر چه می‌کنند.

## چگونه کار می‌کند

پراکسی **امن** است وقتی چیزی ترافیکش را رمز کند و هویت سرور را بسنجد:

- رمزنگاری خود پروتکل: Shadowsocks (نه `none`)، VMess (نه `none` یا `zero`)، رمزنگاری VLESS، Snell،
  Mieru، Sudoku، WireGuard، AmneziaWG، WARP، SSH، Tor، Psiphon، OpenVPN، Tailscale، dnstt، Soar،
  GooseRelay، و MasterDnsVPN با رمز واقعی؛
- یا TLS که گواهی سرور را بررسی می‌کند؛
- یا TLS با `insecure` روشن ولی گواهیِ pin‌شده (`certificate_sha256` یا
  `certificate_public_key_sha256`؛ برای MASQUE، `certificate_public_key_sha256`)؛
- یا REALITY، که سرور را با کلید عمومی‌اش می‌سنجد.

در غیر این صورت **ناامن** است، به یکی از این دلیل‌ها (`C.Insecure*`):

| دلیل | معنی | نمونه‌ها |
|---|---|---|
| `plaintext` | هیچ چیز ترافیک را رمز نمی‌کند | SOCKS؛ HTTP، VLESS، Trojan، AnyTLS، Hysteria، TUIC، Naive یا TrustTunnel بدون TLS |
| `no_cipher` | رمزنگاری خود پروتکل خاموش است و TLS جایش را نمی‌گیرد | Shadowsocks `none`، VMess `none`/`zero`، Sudoku با `aead_method: none`، MasterDnsVPN با `encryption: none` |
| `weak_cipher` | رمزنگاری خود پروتکل فقط داده را می‌پوشاند | ShadowsocksR `table`/`rc4`، MasterDnsVPN `xor` (پیش‌فرضش) |
| `tls_insecure` | TLS با `insecure` روشن و بدون گواهی pin‌شده | Trojan، VLESS، Hysteria2 با `insecure: true`؛ MASQUE با `insecure: true` و بدون pin |

VMess با یک رمز، با TLS ناامن هم امن می‌ماند: رمزنگاری خودش که کلیدش UUID است همچنان ترافیک را
محافظت می‌کند. VMess با `none` دلیلِ TLS خود را می‌گیرد. خروجی lazy با گزینه‌های خروجی واقعی‌اش
سنجیده می‌شود. خروجی `xray` با نخستین خروجی پراکسیِ پیکربندی Xray سنجیده می‌شود: پروتکلش،
`streamSettings.security` و `tlsSettings.allowInsecure` همراه خانوادهٔ `pinnedPeerCertSha256`. گروه‌ها
(selector، urltest، balancer، fallback)، direct، block، ShadowTLS (پراکسی درونی‌اش تعیین می‌کند) و Bond
دلیلی ندارند.

مدیرهای خروجی و endpoint دلیل هر تگ را هنگام ساختنش نگه می‌دارند، در hot reload هم، و با حذف خروجی
آن را پاک می‌کنند.

## پیکربندی

چیزی برای پیکربندی نیست. در Go:

```go
reason := adapter.InsecureReason(box.Outbound(), "my-proxy") // "" when secure
reason = option.InsecureReason(&option.SOCKSOutboundOptions{})  // C.InsecurePlaintext
```

| تابع | خروجی |
|---|---|
| `option.InsecureReason(options any)` | دلیلِ خروجی یا endpoint با این گزینه‌ها (اشاره‌گر، همان‌طور که registry می‌سازد) |
| `adapter.InsecureReason(manager, tag)` | دلیلی که مدیر خروجی برای خروجی یا endpoint با تگ `tag` نگه داشته؛ برای گروه یا تگ ناشناخته "" |

hiddify-core آن را در `OutboundInfo.is_secure` و `OutboundInfo.insecure_reason` می‌فرستد.

## نکته‌ها

- این علامت دربارهٔ مسیر میان دستگاه و سرور پراکسی است. پس از سرور، سایتی که HTTPS ندارد، با هر
  پراکسی‌ای خواندنی است.
- detour علامت را تغییر نمی‌دهد: پراکسی SOCKS که از راه یک پراکسی امن وصل می‌شود، میان سرورِ آن پراکسی
  امن و سرور SOCKS همچنان بی‌رمز خوانده می‌شود.
- endpointهای خانوادهٔ WireGuard از نظر بررسی کلید peer بررسی نمی‌شوند؛ رمزشده فرض می‌شوند.

## همچنین ببینید

- [REALITY در هیدیفای](reality-hiddify.fa.md)
- [ملاحظات اپ](../app_considerations.md)

</div>
