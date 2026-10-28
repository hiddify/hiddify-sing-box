---
name: hiddify-feature
description: Add a feature to, or fix a bug in, hiddify-sing-box (the Hiddify fork of sing-box) the way the project requires - read the Hiddify docs first, keep upstream changes minimal, extend existing code instead of duplicating it, test, document in English and Persian, list it in the README, and commit on top of the latest v5. Use for any code change in this repository.
---

# Adding a feature or fixing a bug in hiddify-sing-box

The rules behind these steps are in [AGENTS.md](../../../AGENTS.md). Follow the steps in order.

## 1. Learn what exists

1. Read every file under `docs/hiddify/`: `index.md`, all pages in `features/` and its
   subfolders, `app_considerations.md`, and `bugfix/v5.en.md`. Read them fully; do not skim.
2. Search the code for the feature's names and options (`grep -rn`), in Hiddify files (`h_*.go`,
   `protocol/hiddify/`, `hiddify/`) and in upstream ones.
3. Decide, and write down in one line, which of these it is:
   - **Already there**: stop, and say where.
   - **Overlaps something**: extend that code and its options. Do not add a second option, type or
     package for the same thing.
   - **New**: a new type, transport or option.

## 2. Start from the latest v5

```bash
git fetch origin
git switch -c <topic> origin/v5   # or: git rebase origin/v5 on an existing branch
git submodule update --init --recursive
```

## 3. Write the change

- New code goes in `h_*.go` files. In an upstream file, change the fewest lines you can and end
  each changed line with `//H`.
- Optional, heavy features get a build tag `with_<feature>` and a stub file for builds without it.
- New options go in `option/`, with a comment on each field. Old options keep their meaning.
- A config the feature cannot run fails when it loads, with an error that says what to change,
  not later at the first connection.

## 4. Test

1. For a bug: write the test first, see it fail, fix, see it pass.
2. Tests go in `h_*_test.go` with `TestH_` names. Network tests skip unless their variable is set.
3. Run, with the Makefile tags (and the feature's own tag):

   ```bash
   TAGS=$(sed -n 's/^TAGS ?= //p' Makefile)
   go vet -tags "$TAGS" ./...
   go test -tags "$TAGS" -ldflags "$(cat release/LDFLAGS)" -race ./<packages you touched>/...
   go test -tags "$TAGS" -ldflags "$(cat release/LDFLAGS)" ./...
   ```

4. If Xray has the feature, run the interop tests against the latest Xray and 26.3.x:
   `HIDDIFY_XRAY=/path/xray-new:/path/xray-26.3 go test ... -run TestH_Xray .`

## 5. Document

1. Feature page pair: `docs/hiddify/features/<category>/<feature>.en.md` and `<feature>.fa.md`.
   Copy the structure of a page in the same category: title; a link to the other language and to
   the index; what it is; why use it; how it gets past filtering; how it works; configuration
   (a JSON example, then a table: field, type, default, meaning); notes; see also. Write the
   Persian page from the English one, with option names, types and code left in Latin script.
2. One line in `docs/hiddify/index.md` and one in `docs/hiddify/index.fa.md`, under its heading:
   `- [Name](features/<category>/<feature>.en.md): one sentence.`
3. One line in the feature list of `README.md`, linking the English page.
4. For a bug fix, an entry at the top of `docs/hiddify/bugfix/v5.en.md` and `v5.fa.md`:
   `## Area: what went wrong`, `Commit: \`<id>\``, **What happened**, **Fix**. Add the commit id
   once you have it.
5. If hiddify-app or hiddify-core must change something, add it to
   `docs/hiddify/app_considerations.md`.
6. Check that every relative link in the files you edited points to a file that exists.

## 6. Commit

- Code: `feat(<area>): ...` or `fix(<area>): ...`, with a body that says why and how it was tested.
- Docs: `docs(hiddify): ...`, in the same pull request.
- No author or co-author lines for AI agents.
- Before opening or updating the pull request: `git fetch origin && git rebase origin/v5`, then
  run the tests again.
