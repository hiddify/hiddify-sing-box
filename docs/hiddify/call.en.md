# Call tunnel

[فارسی](call.fa.md) · [All Hiddify features](index.md)

The call tunnel carries proxy traffic inside a video call on a public conferencing service: VK
Calls, Yandex Telemost, Dion, WB Stream or Bitrix24. One side runs the inbound
`"type": "call"` and the other side runs the outbound `"type": "call"`. Both join the same
call, and the data travels as the call's video frames or WebRTC data channels. It was ported
from sing-box-extended.

**Not tested end to end in Hiddify.** Testing needs accounts on these services, so only the
data-channel code has been checked on its own. Expect to debug it yourself.

## Why use it

- The network allows only a short list of domestic services, and video calls on one of them
  still work.
- Every other proxy is blocked, and you accept low speed and an unstable link to get through.

Choose a normal proxy whenever one works. This tunnel is slower, depends on someone else's
service, and needs a real account on it.

## How it gets past filtering

The client never connects to your server. It connects only to the call service's own web,
signaling and media servers, the same way a browser does when it joins a call. To the filter,
the traffic is a video call to a service that it allows. The data inside the call is encrypted
and, in video mode, packed into frames that start like VP8 video.

Limits:

- **Account bans.** The server side uses your own account. The service can see a call that
  runs all day with a non-human video stream and can block the account.
- **Speed limits.** The service limits the bitrate of video and data channels, so the tunnel is
  much slower than a direct proxy. The speed has not been measured in Hiddify.
- **Service changes.** The code imitates each service's web client: hard-coded API versions,
  a Chrome user agent, and, for Telemost, values scraped from the web page. When a service
  changes its client or API, the tunnel stops working until the code is updated.
- **Captcha on VK.** The VK client side joins as an anonymous guest. VK may ask for a captcha.
  The log then shows "vk-auth: solve the captcha to continue: http://127.0.0.1:PORT/". Open
  that address in a browser on the same device within 5 minutes, or the connection fails.
- **The link is the key.** The encryption key comes from the call link. Anyone who has the
  link, including the service, can read the tunnel and use your server as a proxy. Keep the
  link private.
- It does not help when the service itself is blocked or when the filter limits video calls.

## How it works

- **Server side (inbound).** It logs in to the service with your account and creates a call,
  or joins the call in `join_link`. If it creates the call, it writes the link to the log, for
  example "call[vk]: join_link=…". Connections that arrive through the call go to the router
  like those of any other inbound. The inbound does not listen on a port.
- **Client side (outbound).** It joins the call in `join_link` as a guest, without an account.
  It carries TCP and UDP.
- **Data path.** Each connection is a numbered stream inside one tunnel. The tunnel uses one of
  two carriers:
  - Video: data is encrypted with XChaCha20-Poly1305 and sent as frames of a VP8 video track,
    and on some services also a screen-share track.
  - Data channel: data is sent over the call's WebRTC data channel.
- **Start-up.** Both sides connect once, when sing-box starts. The server side gives up after
  60 seconds. If either side fails to start, it logs the error and does not try again until
  sing-box restarts. Until then the outbound fails with "call: tunnel not initialized".

## Configuration

Needs the `with_call` build tag. Without it, a config with `"type": "call"` fails with "Call is
not included in this build, rebuild with -tags with_call".

Server (inbound):

```json
{
  "type": "call",
  "tag": "call-in",
  "platform": "vk",
  "join_link": "https://vk.ru/call/join/AbCdEf123",
  "cookies": [
    { "name": "<cookie name>", "value": "<cookie value>" },
    { "name": "<cookie name>", "value": "<cookie value>" }
  ]
}
```

Client (outbound):

```json
{
  "type": "call",
  "tag": "call-out",
  "platform": "vk",
  "join_link": "https://vk.ru/call/join/AbCdEf123"
}
```

The link and the cookies above are placeholders. Use the link of a call you created, and the
cookies of your own logged-in browser session.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `platform` | string | none, required | The service: `vk`, `telemost`, `dion`, `wbstream` or `bitrix`. It is not guessed from the link. |
| `join_link` | string | `""` | The call to join. Required on the outbound. On the inbound, leave it empty to create a new call and read its link from the log. |
| `mode` | string | see below | How data is carried, for `wbstream` and `bitrix` only: `dc` (data channel) or `video`. Both sides must use the same mode. |
| `cookies` | list of `{name, value}` | `[]` | Inbound only. The cookies of your logged-in session on the service. |
| `email` | string | `""` | Inbound, `dion` only. Used to log in again when the refresh cookie is missing or expired. |
| `password` | string | `""` | Inbound, `dion` only. Goes with `email`. |
| `read_buffer` | number | `32768` | Read buffer size, in bytes, for data-channel tunnels. |

The usual dial fields (`detour`, `bind_interface` and the rest) also work. The tunnel uses them
to reach the call service.

### Platforms

| `platform` | Service | Inbound | `join_link` | `mode` |
|---|---|---|---|---|
| `vk` | VK Calls | yes | A VK call link. The last part of the path is the call token. | not used, video |
| `telemost` | Yandex Telemost | yes | A Telemost conference link. | not used, video |
| `dion` | Dion | yes | `https://dion.vc/event/<slug>`, `dion://<slug>` or the slug alone. | not used, video |
| `wbstream` | WB Stream | yes | `https://stream.wb.ru/room/<id>`, `wbstream://<id>` or the id alone. | `dc` (default) or `video` |
| `bitrix` | Bitrix24 | **no** | `https://<portal>/video/<alias>` | `video` (default) or `dc` |

### Cookies

`cookies` is a JSON list of `{"name": …, "value": …}` objects, the format that browser cookie
export extensions produce. Other fields in those objects are ignored. Entries without a name
are skipped. Copy the cookies of a browser where you are logged in to the service. What each
service needs, as far as the code shows:

- `vk`: your vk.ru login cookies. The code sends them to login.vk.ru to get a token.
- `telemost`: your Yandex login cookies. The code sends them to the Telemost API.
- `dion`: the list must not be empty. The code reads `vc-refresh-token` and `vc-access-token`.
  If `vc-refresh-token` is missing or rejected and `email` and `password` are set, it logs in
  with them instead.
- `wbstream`: must include `__wb_device_id`. Of the rest, only `wbx-refresh`, `x_wbaas_token`,
  `_wbauid` and `wbx-validation-key` are sent.

The cookies and the password are as powerful as your account login. Anyone who reads your
config can use your account.

### Notes

- `bitrix` works only as an outbound. An inbound with `"platform": "bitrix"` fails with "call:
  unsupported platform bitrix", so a Hiddify server cannot be the other side.
- The outbound accepts `cookies`, but they are not used: the client always joins as a guest.
- `max_buffered_amount` and `memory_limit` are accepted and have no effect.
- On `vk`, `telemost` and `dion`, when the call reconnects, the server side may open new
  connections straight from the inbound's dial settings instead of passing them to the router,
  so route rules no longer apply until sing-box restarts.
- When the server side creates a new call, the link changes each time it starts. Set
  `join_link` on the inbound to keep it the same.

## See also

- [Bond](bond.en.md)
- [All Hiddify features](index.md)
