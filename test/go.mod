module test

go 1.24.7

require github.com/sagernet/sing-box v0.0.0

replace github.com/sagernet/sing-box => ../

replace github.com/sagernet/sing-dns => github.com/shtorm-7/sing-dns v0.4.6-extended-1.0.0

replace github.com/ameshkov/dnscrypt/v2 => github.com/shtorm-7/dnscrypt/v2 v2.4.0-extended-1.0.0

replace github.com/sagernet/wireguard-go => ../replace/wireguard-go

replace github.com/sagernet/tailscale => ../replace/tailscale

replace github.com/Psiphon-Labs/quic-go => ../replace/psiphon-quic-go

replace github.com/Psiphon-Labs/psiphon-tls => ../replace/psiphon-tls

replace github.com/net2share/vaydns => github.com/hiddify/vaydns v0.0.0-20260401180616-890dc987a6a9

require (
	github.com/docker/docker v27.3.1+incompatible
	github.com/docker/go-connections v0.5.0
	github.com/gofrs/uuid/v5 v5.4.0
	github.com/sagernet/quic-go v0.59.0-sing-box-mod.4
	github.com/sagernet/sing v0.8.7-0.20260417135631-0d22698ed386
	github.com/sagernet/sing-quic v0.6.2-0.20260412143638-8f65b6be7cd6
	github.com/sagernet/sing-shadowsocks v0.2.8
	github.com/sagernet/sing-shadowsocks2 v0.2.1
	github.com/spyzhov/ajson v0.9.4
	github.com/stretchr/testify v1.11.1
	go.uber.org/goleak v1.3.0
	golang.org/x/net v0.50.0
)

require (
	filippo.io/bigmod v0.0.1 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	filippo.io/keygen v0.0.0-20230306160926-5201437acf8e // indirect
	github.com/AdguardTeam/golibs v0.32.7 // indirect
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/Jigsaw-Code/outline-sdk v0.0.16 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/Psiphon-Labs/bolt v0.0.0-20200624191537-23cedaef7ad7 // indirect
	github.com/Psiphon-Labs/consistent v0.0.0-20240322131436-20aaa4e05737 // indirect
	github.com/Psiphon-Labs/goptlib v0.0.0-20200406165125-c0e32a7a3464 // indirect
	github.com/Psiphon-Labs/psiphon-tls v0.0.0-20250318183125-2a2fae2db378 // indirect
	github.com/Psiphon-Labs/psiphon-tunnel-core v1.0.11-0.20260126173038-c86a1497a760 // indirect
	github.com/Psiphon-Labs/quic-go v0.0.0-20250527153145-79fe45fb83b1 // indirect
	github.com/Psiphon-Labs/utls v0.0.0-20260129182755-24497d415a8d // indirect
	github.com/ajg/form v1.5.1 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa // indirect
	github.com/ameshkov/dnscrypt/v2 v2.4.0 // indirect
	github.com/ameshkov/dnsstamps v1.0.3 // indirect
	github.com/amnezia-vpn/amneziawg-go v0.2.16 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/anthropics/anthropic-sdk-go v1.26.0 // indirect
	github.com/anytls/sing-anytls v0.0.11 // indirect
	github.com/armon/go-proxyproto v0.0.0-20180202201750-5b7edb60ff5f // indirect
	github.com/axiomhq/hyperloglog v0.2.6 // indirect
	github.com/bifurcation/mint v0.0.0-20180306135233-198357931e61 // indirect
	github.com/biter777/countries v1.7.5 // indirect
	github.com/bits-and-blooms/bitset v1.10.0 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.6.0 // indirect
	github.com/caddyserver/certmagic v0.25.2 // indirect
	github.com/caddyserver/zerossl v0.1.5 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cheekybits/genny v0.0.0-20170328200008-9127e812e1e9 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/cognusion/go-cache-lru v0.0.0-20170419142635-f73e2280ecea // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/coreos/go-iptables v0.7.1-0.20240112124308-65c67c9f46e6 // indirect
	github.com/coreos/go-oidc/v3 v3.17.0 // indirect
	github.com/cretz/bine v0.2.0 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/database64128/tfo-go/v2 v2.3.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dblohm7/wingoes v0.0.0-20240119213807-a09d6be7affa // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgraph-io/badger v1.5.4-0.20180815194500-3a87f6d9c273 // indirect
	github.com/dgryski/go-farm v0.0.0-20240924180020-3414d57e47da // indirect
	github.com/dgryski/go-metro v0.0.0-20250106013310-edb8663e5e33 // indirect
	github.com/distribution/reference v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.9.1 // indirect
	github.com/enfein/mieru/v3 v3.27.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/florianl/go-nfqueue/v2 v2.0.2 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/gaissmai/bart v0.18.0 // indirect
	github.com/go-chi/chi/v5 v5.2.5 // indirect
	github.com/go-chi/render v1.0.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/go-json-experiment/json v0.0.0-20250813024750-ebf49471dced // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/nftables v0.2.1-0.20240414091927-5e242ec57806 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grafov/m3u8 v0.0.0-20171211212457-6ab8f28ed427 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20260220084031-5adc3eb26f91 // indirect
	github.com/josharian/native v1.1.1-0.20230202152459-5c7d0dd6ab86 // indirect
	github.com/jsimonetti/rtnetlink v1.4.0 // indirect
	github.com/kamstrup/intmap v0.5.2 // indirect
	github.com/keybase/go-keychain v0.0.1 // indirect
	github.com/klauspost/compress v1.18.3 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0 // indirect
	github.com/libdns/acmedns v0.5.0 // indirect
	github.com/libdns/alidns v1.0.6 // indirect
	github.com/libdns/cloudflare v0.2.2 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/marusama/semaphore v0.0.0-20171214154724-565ffd8e868a // indirect
	github.com/mdlayher/netlink v1.9.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/metacubex/utls v1.8.4 // indirect
	github.com/mholt/acmez/v3 v3.1.6 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/mroth/weightedrand v1.0.0 // indirect
	github.com/net2share/vaydns v0.2.6 // indirect
	github.com/openai/openai-go/v3 v3.26.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pion/datachannel v1.5.5 // indirect
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/ice/v2 v2.3.24 // indirect
	github.com/pion/interceptor v0.1.25 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/mdns v0.0.12 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.12 // indirect
	github.com/pion/rtp v1.8.5 // indirect
	github.com/pion/sctp v1.8.16 // indirect
	github.com/pion/sdp/v3 v3.0.9 // indirect
	github.com/pion/srtp/v2 v2.0.18 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/transport/v2 v2.2.4 // indirect
	github.com/pion/turn/v2 v2.1.3 // indirect
	github.com/pion/webrtc/v3 v3.2.40 // indirect
	github.com/pires/go-proxyproto v0.8.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus-community/pro-bing v0.4.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/conjure v0.7.11-0.20240130155008-c8df96195ab2 // indirect
	github.com/refraction-networking/ed25519 v0.1.2 // indirect
	github.com/refraction-networking/gotapdance v1.7.10 // indirect
	github.com/refraction-networking/obfs4 v0.1.2 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/sagernet/bbolt v0.0.0-20231014093535-ea5cb2fe9f0a // indirect
	github.com/sagernet/cors v1.2.1 // indirect
	github.com/sagernet/cronet-go v0.0.0-20260413093659-e4926ba205fa // indirect
	github.com/sagernet/cronet-go/all v0.0.0-20260413093659-e4926ba205fa // indirect
	github.com/sagernet/cronet-go/lib/android_386 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/android_amd64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/android_arm v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/android_arm64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/darwin_amd64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/darwin_arm64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/ios_amd64_simulator v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/ios_arm64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/ios_arm64_simulator v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_386 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_386_musl v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_amd64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_amd64_musl v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_arm v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_arm64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_arm64_musl v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_arm_musl v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_loong64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_loong64_musl v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_mips64le v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_mipsle v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_mipsle_musl v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_riscv64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/linux_riscv64_musl v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/tvos_amd64_simulator v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/tvos_arm64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/tvos_arm64_simulator v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/windows_amd64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/cronet-go/lib/windows_arm64 v0.0.0-20260413092954-cd09eb3e271b // indirect
	github.com/sagernet/fswatch v0.1.1 // indirect
	github.com/sagernet/gvisor v0.0.0-20250822052253-5558536cf237 // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/sagernet/nftables v0.3.0-beta.4 // indirect
	github.com/sagernet/sing-cloudflared v0.0.0-20260416083718-efa6ab16dba9 // indirect
	github.com/sagernet/sing-mux v0.3.4 // indirect
	github.com/sagernet/sing-shadowtls v0.2.1-0.20250503051639-fcd445d33c11 // indirect
	github.com/sagernet/sing-tun v0.8.8-0.20260410061515-018f5eaae695 // indirect
	github.com/sagernet/sing-vmess v0.2.8-0.20250909125414-3aed155119a1 // indirect
	github.com/sagernet/smux v1.5.50-sing-box-mod.1 // indirect
	github.com/sagernet/tailscale v1.92.4-sing-box-1.13-mod.7 // indirect
	github.com/sagernet/wireguard-go v0.0.2-beta.1.0.20260224074747-506b7631853c // indirect
	github.com/sagernet/ws v0.0.0-20231204124109-acfe8907c854 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	github.com/shadowsocks/go-shadowsocks2 v0.1.5 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/tailscale/certstore v0.1.1-0.20231202035212-d3fa0460f47e // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/goupnp v1.0.1-0.20210804011211-c64d0f06ea05 // indirect
	github.com/tailscale/hujson v0.0.0-20221223112325-20486734a56a // indirect
	github.com/tailscale/netlink v1.1.1-0.20240822203006-4d49adab4de7 // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20250124233751-d4cd19a26976 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/wader/filtertransport v0.0.0-20200316221534-bdd9e61eee78 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xtaci/kcp-go/v5 v5.6.70 // indirect
	github.com/xtaci/smux v1.5.50 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/metric v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/oauth2 v0.34.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/term v0.40.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.1 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/v3 v3.5.1 // indirect
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
	tailscale.com v1.58.2 // indirect
	zombiezen.com/go/capnproto2 v2.18.2+incompatible // indirect
)
