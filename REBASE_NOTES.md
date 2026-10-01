# v5 → testing rebase notes

Branch: `v5-rebase` (local only, not pushed)
Location: `/Users/mnodhe/Documents/programming/hiddify/sing-box-v5`

Rebased `hiddify/hiddify-sing-box:v5` (205 commits ahead / 454 commits behind at start)
onto `SagerNet/sing-box:testing`. 97 commits needed manual conflict resolution after
patch-id auto-skip of already-applied commits.

## Why it took long

1. **Scale.** 97 commits, each requiring a fresh three-way diff read, not a single
   mechanical merge. Average ~2-8 conflicted files per commit, some (bridge outbound,
   netns/unshare, libbox RoutedFlow) touching 10-15 files at once.

2. **HEAD kept moving.** `v5`'s own history had refactored the same subsystems the
   old `testing` commits were replaying (flow-tracking API, DNS exchange pipeline,
   TUN device stack, tailscale endpoint) multiple times over. Every conflict required
   figuring out *which side is stale* rather than a blind merge — mostly "keep HEAD,"
   but never assumable without checking.

3. **Two distinct conflict shapes, needing opposite defaults:**
   - Old upstream commits being replayed → HEAD (hiddify's later work) is almost
     always the superset; discard theirs.
   - hiddify's *own* commits (`core: extend adapter...`, `feat(protocols): wire...`,
     `feat(route): wire tunnel routing...`) → these add genuinely new functionality
     not yet present, so the default flips: keep theirs, merge into HEAD's current
     shape. Misapplying the wrong default here would have silently dropped features.

4. **Forward-reference gaps.** Several hiddify commits reference packages/types that
   don't exist yet at that point in the rebase (`common/monitoring`, `hiddify/ipinfo`,
   `common/xray/*`, `protocol/hiddify/hinvalid`, MASQUE outbound options) because the
   commit that *adds* them hasn't been replayed yet. Every such gap had to be verified
   as "expected, lands later" via `git log -S<symbol>` against the full commit range,
   not just patched around.

5. **Submodule conflicts.** `replace/wireguard-go` and `replace/tailscale` are git
   submodules pointing at hiddify's own forks. Git can't 3-way-merge submodule pointer
   conflicts automatically ("commits don't follow merge-base") — each one needed manual
   ancestry checking (`git merge-base --is-ancestor`) across divergent fork branches to
   pick the right commit, sometimes discovering the target commit didn't even have the
   API the calling code expected (pre-existing fork/mainline drift, left as a known gap).

6. **Corrupted resolutions from an over-eager regex.** A reusable Python script for
   auto-resolving `go.mod`-style single-block conflicts was applied a few times to
   files with *multiple* conflict markers, silently deleting all content between the
   first and last marker. Required detecting the corruption (missing imports, missing
   functions) and manually reconstructing affected files from `git show HEAD:<path>`.

7. **Verification cost per commit.** `go build` is broken on this machine (unrelated
   Xcode toolchain issue), so every commit's resolution was checked with
   `CGO_ENABLED=0 go vet ./...`, comparing output against a growing list of known/
   expected pre-existing gaps to avoid chasing non-regressions.

## Known remaining gaps (pre-existing, not introduced by this rebase)

- `gvisor.dev/gvisor` module-cache duplicate-package error (protocol/awg, transport/awg)
- `github.com/kianmhz/GooseRelayVPN/goose` subpackage missing from that module version
- `replace/wireguard-go` (hiddify's fork) lacks `SetEndpointResolverFunc` / `FakePackets`
  that `transport/wireguard/endpoint.go` expects — fork hasn't caught up to what a
  later, not-yet-replayed hiddify commit assumes
- `protocol/psiphon` → `Psiphon-Labs/quic-go` declares its own module path as
  `lucas-clemente/quic-go`, a known upstream metadata quirk

None of these block the rest of the tree; they're isolated to specific build-tag-gated
packages and are expected to resolve once corresponding fork/dependency updates land.
