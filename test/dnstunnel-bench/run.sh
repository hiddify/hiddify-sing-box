#!/usr/bin/env bash
# DNS tunnel benchmark: DNSTT and MasterDNS through rate-limited local
# resolvers, with and without the smart resolver pool (common/dnspool, built on
# github.com/hiddify/hmrd_multi_resolver_dns). Everything runs on the loopback:
# no internet, no root. See README.md next to this script.
#
#   QUICK=1 test/dnstunnel-bench/run.sh          # a check that the pool works, about 2 minutes
#   test/dnstunnel-bench/run.sh                  # every setup once, about 5 minutes
#   SETUPS="three-limited" ROUNDS=3 test/dnstunnel-bench/run.sh
#   APPROACHES="masterdns-own masterdns-pool" test/dnstunnel-bench/run.sh
#   WORK=dir SKIP_BUILD=1 test/dnstunnel-bench/run.sh  # reuse the binaries a run built in dir
#   WORK=dir APPROACHES="masterdns-pool" test/dnstunnel-bench/run.sh  # rerun one approach; the
#       tables take the other approaches' rows from dir's cache of earlier runs
#   MASTERDNS_EXTRA='"packet_duplication":1' test/dnstunnel-bench/run.sh  # more masterdns fields
#   POOL_EXTRA='"duplicate":2' test/dnstunnel-bench/run.sh  # more smart_pool fields
#   DNSTT_EXTRA='"udp-workers":200' test/dnstunnel-bench/run.sh  # more dnstt fields
#   QUERY_BYTES=50 test/dnstunnel-bench/run.sh   # each query carries about 50 bytes of upload
#   PARALLEL=all test/dnstunnel-bench/run.sh     # every setup at once (faster, noisier)
#
# Output: one markdown table row per run, on stdout. QUICK=1 runs four setups
# once with small transfers and then checks the pool's behaviour (PASS or FAIL
# lines; the exit status is 1 on a failure): run it first, and the full
# benchmark when it passes.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
WORK=${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/dnstunnel-bench.XXXXXX")}
ROUNDS=${ROUNDS:-1}
MAX_TIME=${MAX_TIME:-60}
QUICK=${QUICK:-}
# The quick check does not judge uploads, and DNSTT's upload through refusing
# resolvers can crawl at 1 kbps (its KCP window collapses under refusals, with
# or without the pool), so its uploads get a short limit
UP_MAX_TIME=${UP_MAX_TIME:-$([ -n "$QUICK" ] && echo 15 || echo "$MAX_TIME")}
# Downloads without a rate limit run for DOWN_SECONDS, whatever the approach's
# speed: long enough for a pool to learn which resolvers lose (a loss shows only
# after a timeout), and the same for every approach; 0 downloads a fixed size
# instead. Through rate-limited resolvers a tunnel on one resolver takes seconds
# to deliver anything, so those download a fixed size (setup_sizes).
DOWN_SECONDS=${DOWN_SECONDS:-$([ -n "$QUICK" ] && echo 2 || echo 5)}
if [ -n "$QUICK" ]; then
	APPROACHES=${APPROACHES:-"dnstt-first dnstt-pool masterdns-first masterdns-pool"}
	SETUPS=${SETUPS:-"three-unlimited three-uneven-latency three-lossy three-limited"}
fi
ALL_APPROACHES="dnstt-first dnstt-pool masterdns-first masterdns-own masterdns-own-nodup masterdns-pool"
APPROACHES=${APPROACHES:-$ALL_APPROACHES}
SETUPS=${SETUPS:-"one-unlimited one-10ms one-limited three-unlimited three-limited three-limited-one-dead three-uneven-latency three-lossy"}
# Every (setup, approach) measured is also kept in $WORK/cache, and the tables
# at the end show, for each setup run, every approach in the cache: an approach
# whose code did not change need not be run again. CACHE= turns that off.
CACHE=${CACHE-1}
BASE_PORT=${BASE_PORT:-27100}
# QUERY_BYTES bounds the upload a query carries (a resolver that limits the
# name length does the same): DNSTT's max-qname-len (base32: 8 characters
# per 5 bytes, plus the client ID and the domain), MasterDNS's max_upload_mtu.
QUERY_BYTES=${QUERY_BYTES:-}
# PARALLEL=all runs every setup at once; by default the setups without a rate
# limit run one after another, since they are bound by the machine.
PARALLEL=${PARALLEL:-}

# Resolvers of each setup, as qps:mode[:latency[:loss]]; qps 0 = unlimited,
# mode refuse (REFUSED over the limit), drop (no answer) or dead.
setup_resolvers() {
	case $1 in
	one-unlimited) echo "0:refuse" ;;
	one-limited) echo "30:refuse" ;;
	three-unlimited) echo "0:refuse 0:refuse 0:refuse" ;;
	three-limited) echo "20:refuse 30:refuse 40:drop" ;;
	three-limited-one-dead) echo "30:refuse 40:drop 0:dead" ;;
	three-uneven-latency) echo "0:refuse:10ms 0:refuse:60ms 0:refuse:250ms" ;;
	three-lossy) echo "0:refuse 0:refuse:0:0.1 0:refuse:0:0.3" ;;
	one-10ms) echo "0:refuse:10ms" ;;
	*) echo "unknown setup $1" >&2; exit 2 ;;
	esac
}

# limited <setup>: whether its resolvers have rate limits. These setups are
# bound by the resolvers' query rates, not by the machine, so they run at the
# same time, each on its own resolvers; the others run one after another.
limited() {
	case $1 in one-limited | three-limited | three-limited-one-dead) return 0 ;; esac
	return 1
}

# Transfer sizes: smaller through rate-limited resolvers, where a tunnel moves a
# few kilobytes a second; DOWN_BYTES and UP_BYTES set them for every setup.
setup_sizes() { # "<download bytes> <upload bytes>"
	if [ -n "${DOWN_BYTES:-}" ] || [ -n "${UP_BYTES:-}" ]; then
		echo "${DOWN_BYTES:-524288} ${UP_BYTES:-131072}"
		return
	fi
	if [ -n "$QUICK" ]; then
		if limited "$1"; then echo "65536 8192"; else echo "524288 131072"; fi
		return
	fi
	if limited "$1"; then echo "131072 32768"; else echo "2097152 524288"; fi
}

# check_quick: the quick run's checks over its rows, on stdout; false when one
# fails. Columns: setup, approach, round, ready, download kbps and queries/s,
# upload kbps and queries/s, download share (a/b/c, in the setup's order).
check_quick() {
	for setup in $SETUPS; do cat "$WORK/rows-$setup.md"; done | awk -F' [|] ' '
		function check(ok, what) { printf "%s: %s\n", ok ? "PASS" : "FAIL", what; if (!ok) failed = 1 }
		function has(setup, ap) { if ((setup, ap) in down) return 1; missing = missing " " setup "/" ap; return 0 }
		{
			sub(/^[|] /, "", $1); sub(/ [|]$/, "", $9)
			setup = $1; ap = $2
			down[setup, ap] = $5
			n = split($9, sh, "/")
			for (i = 1; i <= 3; i++) share[setup, ap, i] = (i <= n) ? sh[i] + 0 : 0
			if (ap ~ /-pool$/ && ($5 !~ /^[0-9]+$/ || $7 !~ /^[0-9]+$/)) bad = bad " " setup "/" ap
			seen[setup] = 1
		}
		END {
			check(bad == "", "every transfer through a pool completed" (bad == "" ? "" : ", failed:" bad))
			if ("three-unlimited" in seen) for (t = 1; t <= 2; t++) {
				ap = t == 1 ? "dnstt-pool" : "masterdns-pool"
				check(has("three-unlimited", ap) && share["three-unlimited", ap, 1] >= 20 && share["three-unlimited", ap, 2] >= 20 && share["three-unlimited", ap, 3] >= 20, ap " spreads three equal resolvers evenly (each at least 20%: " share["three-unlimited", ap, 1] "/" share["three-unlimited", ap, 2] "/" share["three-unlimited", ap, 3] ")")
			}
			if ("three-uneven-latency" in seen) {
				check(has("three-uneven-latency", "dnstt-pool") && share["three-uneven-latency", "dnstt-pool", 2] <= 5 && share["three-uneven-latency", "dnstt-pool", 3] <= 5, "dnstt-pool keeps to the 10 ms resolver (60 and 250 ms at most 5%: " share["three-uneven-latency", "dnstt-pool", 2] "/" share["three-uneven-latency", "dnstt-pool", 3] ")")
				check(has("three-uneven-latency", "masterdns-pool") && share["three-uneven-latency", "masterdns-pool", 3] <= 5, "masterdns-pool spares the 250 ms resolver (at most 5%: " share["three-uneven-latency", "masterdns-pool", 3] ")")
			}
			if ("three-lossy" in seen) {
				check(has("three-lossy", "dnstt-pool") && share["three-lossy", "dnstt-pool", 2] <= 20 && share["three-lossy", "dnstt-pool", 3] <= 5, "dnstt-pool avoids the lossy resolvers (10% loss at most 20%, 30% at most 5%: " share["three-lossy", "dnstt-pool", 2] "/" share["three-lossy", "dnstt-pool", 3] ")")
				check(has("three-lossy", "masterdns-pool") && has("three-lossy", "masterdns-first") && share["three-lossy", "masterdns-pool", 1] >= 45 && down["three-lossy", "masterdns-pool"] + 0 >= 0.9 * down["three-lossy", "masterdns-first"], "masterdns-pool sends its queries to the clean resolver and its copies to a free one (clean at least 45%: " share["three-lossy", "masterdns-pool", 1] "; at least 90% of the clean resolver alone: " down["three-lossy", "masterdns-pool"] " against " down["three-lossy", "masterdns-first"] " kbps)")
			}
			if ("three-limited" in seen) for (t = 1; t <= 2; t++) {
				first = t == 1 ? "dnstt-first" : "masterdns-first"
				ap = t == 1 ? "dnstt-pool" : "masterdns-pool"
				check(has("three-limited", ap) && has("three-limited", first) && down["three-limited", ap] + 0 >= 3 * down["three-limited", first], ap " combines the limited resolvers (at least 3 times " first ", whose resolver allows 20 queries a second of the three'"'"'s 90: " down["three-limited", ap] " against " down["three-limited", first] " kbps)")
			}
			if (missing != "") check(0, "a row for every approach the checks need, missing:" missing)
			exit failed
		}'
}

MDNS_PORT=$((BASE_PORT + 1))   # MasterDnsVPN server (UDP)
VAY_PORT=$((BASE_PORT + 2))    # VayDNS (DNSTT) server (UDP)
SOCKS_PORT=$((BASE_PORT + 3))  # SOCKS server the tunnel servers forward to
HTTP_PORT=$((BASE_PORT + 4))   # HTTP target
CLIENT_PORT=$((BASE_PORT + 5)) # client sing-box mixed inbound (setup n: + 100 + n)
RES_PORT=$((BASE_PORT + 10))   # first test resolver (setup n: + 10 n)

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM

log() { echo "$*" >&2; }

build() {
	log "building in $WORK"
	local tags ldflags
	tags=$(sed -n 's/^TAGS ?= //p' "$ROOT/Makefile")
	ldflags=$(cat "$ROOT/release/LDFLAGS")
	(cd "$ROOT" && go build -tags "$tags" -ldflags "$ldflags" -o "$WORK/sing-box" ./cmd/sing-box)
	(cd "$ROOT/replace/MasterDnsVPN" && go build -o "$WORK/mdns-server" ./cmd/server)
	# the hmrd and VayDNS versions sing-box is built with
	local hmrd vay
	hmrd=$(cd "$ROOT" && go list -m -f '{{.Version}}' github.com/hiddify/hmrd_multi_resolver_dns)
	vay=$(cd "$ROOT" && go list -m -f '{{if .Replace}}{{.Replace.Path}}@{{.Replace.Version}}{{else}}{{.Path}}@{{.Version}}{{end}}' github.com/net2share/vaydns)
	GOBIN="$WORK" go install "github.com/hiddify/hmrd_multi_resolver_dns/cmd/hmrdbench@$hmrd"
	mkdir -p "$WORK/vaybuild"
	cat >"$WORK/vaybuild/go.mod" <<EOF
module vaybuild

go 1.26

require github.com/net2share/vaydns v0.2.8

replace github.com/net2share/vaydns => ${vay/@/ }
EOF
	printf 'package vaybuild\n\nimport _ "github.com/net2share/vaydns/vaydns-server"\n' >"$WORK/vaybuild/tools.go"
	(cd "$WORK/vaybuild" && go mod tidy >/dev/null 2>&1 && go build -o "$WORK/vaydns-server" github.com/net2share/vaydns/vaydns-server)
}

wait_port() { # wait_port <tcp port>
	for _ in $(seq 1 80); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.25; done
	return 1
}

start_servers() {
	cd "$WORK"
	cat >socks.json <<EOF
{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":$SOCKS_PORT}],"outbounds":[{"type":"direct","tag":"direct"}]}
EOF
	./sing-box run -c socks.json >socks.log 2>&1 &
	PIDS+=($!)
	./hmrdbench http -listen "127.0.0.1:$HTTP_PORT" >http.log 2>&1 &
	PIDS+=($!)

	# MasterDnsVPN server: TCP mode, every stream forwarded to the SOCKS server
	sed -e 's/^DOMAIN = .*/DOMAIN = ["v.bench.example"]/' \
		-e 's/^UDP_HOST = .*/UDP_HOST = "127.0.0.1"/' \
		-e "s/^UDP_PORT = .*/UDP_PORT = $MDNS_PORT/" \
		-e 's/^PROTOCOL_TYPE = .*/PROTOCOL_TYPE = "TCP"/' \
		-e 's/^FORWARD_IP = .*/FORWARD_IP = "127.0.0.1"/' \
		-e "s/^FORWARD_PORT = .*/FORWARD_PORT = $SOCKS_PORT/" \
		-e "s#^ENCRYPTION_KEY_FILE = .*#ENCRYPTION_KEY_FILE = \"$WORK/mdns.key\"#" \
		-e 's/^LOG_LEVEL = .*/LOG_LEVEL = "ERROR"/' \
		"$ROOT/replace/MasterDnsVPN/server_config.toml.simple" >mdns.toml
	./mdns-server -config "$WORK/mdns.toml" -genkey -nowait >/dev/null 2>&1
	./mdns-server -config "$WORK/mdns.toml" -nowait >mdns.log 2>&1 &
	PIDS+=($!)

	[ -f vay.key ] || ./vaydns-server -gen-key -privkey-file vay.key -pubkey-file vay.pub >/dev/null 2>&1
	./vaydns-server -udp "127.0.0.1:$VAY_PORT" -privkey-file vay.key -domain t.bench.example \
		-upstream "127.0.0.1:$SOCKS_PORT" -log-level warning >vaydns.log 2>&1 &
	PIDS+=($!)
	wait_port "$SOCKS_PORT" && wait_port "$HTTP_PORT" || { log "servers did not start"; exit 1; }
	sleep 1
}

# client_config <approach> <resolver json list>
client_config() {
	local ap=$1 res=$2 tunnel pool=false extra=${MASTERDNS_EXTRA:-}
	case $ap in *-pool) pool=${POOL_EXTRA:+"{\"enabled\":true,$POOL_EXTRA}"} pool=${pool:-true} ;; esac
	# *-nodup: every packet sent once, MasterDnsVPN's duplication off
	case $ap in *-nodup) extra="\"packet_duplication\":1${extra:+,$extra}" ;; esac
	[ -n "$QUERY_BYTES" ] && extra="\"max_upload_mtu\":$QUERY_BYTES${extra:+,$extra}"
	# *-first: the setup's first resolver only, no multi-resolver
	case $ap in *-first) res=$(echo "$res" | sed 's/^\[\("[^"]*"\).*/[\1]/') ;; esac
	case $ap in
	dnstt-*)
		local qname=200
		[ -n "$QUERY_BYTES" ] && qname=$((QUERY_BYTES * 8 / 5 + 40))
		tunnel="{\"type\":\"dnstt\",\"tag\":\"tunnel\",\"domain\":\"t.bench.example\",\"pubkey\":\"$(cat vay.pub)\",\"resolvers\":$res,\"max-qname-len\":$qname,\"smart_pool\":$pool${DNSTT_EXTRA:+,$DNSTT_EXTRA}}"
		;;
	masterdns-*)
		tunnel="{\"type\":\"masterdns\",\"tag\":\"tunnel\",\"domains\":[\"v.bench.example\"],\"resolvers\":$res,\"encryption\":\"xor\",\"key\":\"$(cat mdns.key)\",\"mode\":\"tcp\",\"log_level\":\"error\",\"smart_pool\":$pool${extra:+,$extra}}"
		;;
	*) log "unknown approach $ap"; exit 2 ;;
	esac
	cat <<EOF
{"log":{"level":"error"},
 "inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":$CLIENT_PORT}],
 "outbounds":[$tunnel,
  {"type":"socks","tag":"socks","server":"127.0.0.1","server_port":$SOCKS_PORT,"detour":"tunnel"},
  {"type":"direct","tag":"direct"}],
 "route":{"final":"socks"}${CLIENT_EXTRA:+,$CLIENT_EXTRA}}
EOF
}

# queries <port>...: the queries each resolver got so far (answered + refused or
# dropped), from the last line its -stats ticker wrote
queries() {
	local p line
	for p in "$@"; do
		line=$(tail -n 1 "$WORK/resolver-$p.log" 2>/dev/null || true)
		case $line in
		*served=*) echo "$line" | sed 's/.*served=\([0-9]*\) limited=\([0-9]*\).*/\1 \2/' | awk '{print $1 + $2}' ;;
		*) echo 0 ;;
		esac
	done
}

# rates <bytes> <seconds> <queries before> <queries after>: "kbps | queries/s | share"
rates() {
	awk -v b="$1" -v t="$2" -v before="$3" -v after="$4" 'BEGIN {
		n = split(before, x, " "); split(after, y, " "); total = 0
		for (i = 1; i <= n; i++) { d[i] = y[i] - x[i]; total += d[i] }
		share = ""
		for (i = 1; i <= n; i++) share = share (i > 1 ? "/" : "") (total > 0 ? sprintf("%.0f", 100 * d[i] / total) : 0)
		printf "%.0f | %.0f | %s", b * 8 / 1000 / t, total / t, share
	}'
}

# timeboxed <setup>: whether its download runs for DOWN_SECONDS
timeboxed() {
	[ "$DOWN_SECONDS" != 0 ] && ! limited "$1"
}

# transfer <down|up> <proxy> <url> <bytes> <setup>: "<bytes> <seconds>", 0 bytes on a failure
transfer() {
	if [ "$1" = down ] && timeboxed "$5"; then
		# a download that does not end before its time; curl reports the
		# bytes it received when it stops it
		curl -s -x "$2" -o /dev/null -w '%{size_download} %{time_total}' --max-time "$DOWN_SECONDS" "$3/down?bytes=100000000000" || true
	elif [ "$1" = down ]; then
		curl -s -x "$2" -o /dev/null -w '%{size_download} %{time_total}' --max-time "$MAX_TIME" "$3/down?bytes=$4" || true
	else
		head -c "$4" /dev/urandom | curl -s -x "$2" -o /dev/null -w '%{size_upload} %{time_total}' --max-time "$UP_MAX_TIME" --data-binary @- "$3/up" || true
	fi
}

# timed <down|up> <proxy> <url> <want bytes> <setup>: "kbps | queries/s | share"
timed() {
	local before after out size time
	before=$(queries $RPORTS | tr "\n" " ")
	out=$(transfer "$1" "$2" "$3" "$4" "$5")
	sleep 0.15 # the next -stats tick
	after=$(queries $RPORTS | tr "\n" " ")
	size=${out% *} time=${out#* }
	size=${size:-0}
	if [ "$1" = down ] && timeboxed "$5"; then
		if [ "$size" -le 0 ]; then
			echo "fail (nothing in ${DOWN_SECONDS}s) | - | -"
			return
		fi
	elif [ "$size" != "$4" ]; then
		echo "fail ($size of $4 B) | - | -"
		return
	fi
	rates "$size" "$time" "$before" "$after"
}

measure() { # measure <setup> <round> <approach> <resolver json list>
	local setup=$1 round=$2 ap=$3 res=$4 ready down up
	client_config "$ap" "$res" >"client-$setup-$ap.json"
	local start
	start=$(date +%s)
	./sing-box run -c "client-$setup-$ap.json" >"client-$setup-$ap-r$round.log" 2>&1 &
	local pid=$!
	wait_port "$CLIENT_PORT" || true
	local proxy="socks5h://127.0.0.1:$CLIENT_PORT" url="http://127.0.0.1:$HTTP_PORT"
	# Ready: until a first request goes through (resolver tests, session setup),
	# up to 60 s; the transfers are timed after it
	ready=fail
	while [ $(($(date +%s) - start)) -lt 60 ]; do
		if [ "$(curl -s -x "$proxy" -o /dev/null -w '%{http_code}' --max-time 10 "$url/" || true)" = 204 ]; then
			ready=$(($(date +%s) - start))
			break
		fi
		sleep 0.5
	done
	local sizes
	sizes=$(setup_sizes "$setup")
	down=$(timed down "$proxy" "$url" "${sizes% *}" "$setup")
	up=$(timed up "$proxy" "$url" "${sizes#* }" "$setup")
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	echo "| $setup | $ap | $round | $ready | ${down% | *} | ${up% | *} | ${down##* | } |"
}

# run_setup <setup> <n>: start the setup's resolvers and print a row per
# round and approach. Setup n has its own resolver and client ports.
run_setup() {
	local setup=$1 n=$2 port res="" rpids=()
	port=$((RES_PORT + 10 * (n - 1)))
	CLIENT_PORT=$((BASE_PORT + 100 + n))
	RPORTS=""
	trap 'for p in ${rpids[@]+"${rpids[@]}"}; do kill "$p" 2>/dev/null || true; done' EXIT
	for spec in $(setup_resolvers "$setup"); do
		IFS=: read -r qps mode latency loss <<<"$spec"
		local extra=()
		[ -n "${latency:-}" ] && [ "$latency" != 0 ] && extra+=(-latency "$latency")
		[ -n "${loss:-}" ] && extra+=(-loss "$loss")
		"$WORK/hmrdbench" resolver -listen "127.0.0.1:$port" -qps "$qps" -mode "$mode" -stats 100ms \
			-route "v.bench.example=127.0.0.1:$MDNS_PORT" -route "t.bench.example=127.0.0.1:$VAY_PORT" \
			${extra[@]+"${extra[@]}"} >"$WORK/resolver-$port.log" 2>&1 &
		rpids+=($!)
		res="$res,\"127.0.0.1:$port\""
		RPORTS="$RPORTS $port"
		port=$((port + 1))
	done
	res="[${res#,}]"
	sleep 0.5
	local round ap
	for round in $(seq 1 "$ROUNDS"); do
		for ap in $APPROACHES; do
			(cd "$WORK" && measure "$setup" "$round" "$ap" "$res")
		done
	done
	for p in "${rpids[@]}"; do kill "$p" 2>/dev/null || true; done
	trap - EXIT
}

# cache_rows <setup>: keep the setup's rows of this run in the cache, one file
# per approach, replacing that approach's earlier rows
cache_rows() {
	[ -n "$CACHE" ] || return 0
	local ap
	mkdir -p "$WORK/cache/$1"
	for ap in $APPROACHES; do
		grep "^| $1 | $ap | " "$WORK/rows-$1.md" >"$WORK/cache/$1/$ap.md" || true
	done
}

# table_rows <setup>: the rows the tables use: this run's, plus the cache's for
# the approaches not run, each with the age of its measurement in minutes
table_rows() {
	cat "$WORK/rows-$1.md"
	[ -n "$CACHE" ] || return 0
	local f ap now
	now=$(date +%s)
	for f in "$WORK/cache/$1"/*.md; do
		[ -e "$f" ] || continue
		ap=$(basename "$f" .md)
		case " $APPROACHES " in *" $ap "*) continue ;; esac
		sed "s/ |\$/ | cached $(( (now - $(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f")) / 60 )) min ago |/" "$f"
	done
}

main() {
	for port in $SOCKS_PORT $HTTP_PORT $((BASE_PORT + 101)) $RES_PORT; do
		if nc -z 127.0.0.1 "$port" 2>/dev/null; then
			log "port $port is in use (a previous run still running?); set BASE_PORT to another range"
			exit 1
		fi
	done
	if [ -n "${SKIP_BUILD:-}" ]; then log "using the binaries already in $WORK"; else build; fi
	start_servers
	local downs ups
	if [ "$DOWN_SECONDS" != 0 ]; then
		downs="$(setup_sizes one-limited | awk '{printf "%d and %d KiB", $1/1024, $2/1024}') through rate-limited resolvers (these setups run at the same time); otherwise a download of ${DOWN_SECONDS} s and an upload of $(setup_sizes one-unlimited | awk '{printf "%d KiB", $2/1024}')"
	else
		downs="$(setup_sizes one-limited | awk '{printf "%d and %d KiB", $1/1024, $2/1024}') through rate-limited resolvers (these setups run at the same time), $(setup_sizes one-unlimited | awk '{printf "%d and %d KiB", $1/1024, $2/1024}') otherwise"
	fi
	echo "Ready: seconds from start until a first request goes through. Download and upload, once ready, in kilobits a second (1 kbps = 1000 bit/s): $downs.${QUERY_BYTES:+ Each query carries about $QUERY_BYTES bytes of upload.}${PARALLEL:+ Every setup ran at the same time.} Queries/s: DNS queries a second the tunnel sent to all resolvers during the transfer, answered or not. Download share: each resolver's part of those queries during the download, in the setup's order."
	echo
	echo "| Setup | Approach | Round | Ready (s) | Download (kbps) | Download (queries/s) | Upload (kbps) | Upload (queries/s) | Download share (%) |"
	echo "|---|---|---|---|---|---|---|---|---|"
	# the unlimited setups first, one at a time: they are bound by the machine,
	# so nothing else may run beside them; then the limited ones all at once
	local n=0 jobs=() setup
	for setup in $SETUPS; do
		n=$((n + 1))
		if [ "$PARALLEL" != all ] && ! limited "$setup"; then
			(run_setup "$setup" "$n") >"$WORK/rows-$setup.md"
			cache_rows "$setup"
		fi
	done
	n=0
	for setup in $SETUPS; do
		n=$((n + 1))
		if [ "$PARALLEL" = all ] || limited "$setup"; then
			{ run_setup "$setup" "$n" >"$WORK/rows-$setup.md"; cache_rows "$setup"; } &
			jobs+=($!)
			PIDS+=($!)
		fi
	done
	for j in ${jobs[@]+"${jobs[@]}"}; do wait "$j" || true; done
	for setup in $SETUPS; do table_rows "$setup"; done
	if [ "$ROUNDS" -gt 1 ] || [ -n "$CACHE" ]; then
		echo
		echo "Median of the rounds, in kbps:"
		echo
		echo "| Setup | Approach | Download (kbps) | Upload (kbps) |"
		echo "|---|---|---|---|"
		for setup in $SETUPS; do table_rows "$setup"; done | awk -F' [|] ' -v order="$ALL_APPROACHES" '
			function median(list,   n, v, i, j, t) {
				n = split(list, v, " ")
				for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++) if (v[j] + 0 < v[i] + 0) { t = v[i]; v[i] = v[j]; v[j] = t }
				return n % 2 ? v[(n + 1) / 2] : (v[n / 2] + v[n / 2 + 1]) / 2
			}
			BEGIN { n = split(order, o, " "); for (i = 1; i <= n; i++) rank[o[i]] = i }
			{
				setup = $1; sub(/^[|] /, "", setup)
				if (!(setup in seen)) { seen[setup] = 1; setups[++ns] = setup }
				key = setup " | " $2
				if (!(key in down)) { aps[setup] = aps[setup] " " $2 }
				d = ($5 ~ /^[0-9]+$/) ? $5 : 0
				u = ($7 ~ /^[0-9]+$/) ? $7 : 0
				down[key] = down[key] " " d
				up[key] = up[key] " " u
				if ($NF ~ /cached/) note[key] = " (" $NF ")"; else if (!(key in note)) note[key] = ""
			}
			END {
				for (s = 1; s <= ns; s++) {
					m = split(aps[setups[s]], a, " ")
					for (i = 1; i <= m; i++) for (j = i + 1; j <= m; j++) if ((a[j] in rank ? rank[a[j]] : 99) < (a[i] in rank ? rank[a[i]] : 99)) { t = a[i]; a[i] = a[j]; a[j] = t }
					for (i = 1; i <= m; i++) { key = setups[s] " | " a[i]; printf "| %s%s | %d | %d |\n", key, note[key], median(down[key]), median(up[key]) }
				}
			}'
	fi
	log "logs in $WORK"
	if [ -n "$QUICK" ]; then
		echo
		check_quick
	fi
}

main "$@"
