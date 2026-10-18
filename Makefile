NAME = sing-box
COMMIT = $(shell git rev-parse --short HEAD)
TAGS ?= $(shell cat release/DEFAULT_BUILD_TAGS_OTHERS)

GOHOSTOS = $(shell go env GOHOSTOS)
GOHOSTARCH = $(shell go env GOHOSTARCH)
VERSION=$(shell CGO_ENABLED=0 GOOS=$(GOHOSTOS) GOARCH=$(GOHOSTARCH) go run github.com/sagernet/sing-box/cmd/internal/read_tag@latest)

LDFLAGS_SHARED = $(shell cat release/LDFLAGS)
PARAMS = -v -trimpath -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=$(VERSION)' $(LDFLAGS_SHARED) -s -w -buildid="
MAIN_PARAMS = $(PARAMS) -tags "$(TAGS)"
MAIN = ./cmd/sing-box
PREFIX ?= $(shell go env GOPATH)
SING_FFI ?= sing-ffi
LIBBOX_FFI_CONFIG ?= ./experimental/libbox/ffi.json

ADMIN_PANEL_DIR = service/admin_panel
ADMIN_PANEL_WEB = $(ADMIN_PANEL_DIR)/web
ADMIN_PANEL_DIST = $(ADMIN_PANEL_DIR)/dist
ADMIN_PANEL_TAGS = $(TAGS),with_admin_panel

DOCKER_IMAGE ?= shtorm7/sing-box-extended
DOCKER_PLATFORMS ?= linux/amd64,linux/arm64

CRONET_GO_PATH ?= $(shell pwd)/cronet-go

.PHONY: test release docs build schema

build:
	go build $(MAIN_PARAMS) $(MAIN)

build_admin_panel:
	cd $(ADMIN_PANEL_WEB) && \
		npm install --no-fund --no-audit && \
		npm run build
	go run ./cmd/internal/admin_panel_pack \
		-dir $(ADMIN_PANEL_DIST)

build_naive:
	cd $(CRONET_GO_PATH) && \
	for arch in amd64 arm64 386 arm mipsle mips64le riscv64 loong64; do \
		go run ./cmd/build-naive --target=linux/$$arch download-toolchain; \
	done && \
	for arch in amd64 arm64 386 arm mipsle riscv64 loong64; do \
		go run ./cmd/build-naive --target=linux/$$arch --libc=musl download-toolchain; \
	done

race:
	export GOTOOLCHAIN=local && \
	go build -race $(MAIN_PARAMS) $(MAIN)

ci_build:
	export GOTOOLCHAIN=local && \
	go build $(PARAMS) $(MAIN) && \
	go build $(MAIN_PARAMS) $(MAIN)

generate_completions:
	go run -v --tags "$(TAGS),generate,generate_completions" $(MAIN)

schema:
	go run -ldflags "$(LDFLAGS_SHARED)" --tags "$(TAGS)" $(MAIN) schema -o docs/schema.json

install:
	go build -o $(PREFIX)/bin/$(NAME) $(MAIN_PARAMS) $(MAIN)

fmt:
	@golangci-lint fmt

fmt_docs:
	go run ./cmd/internal/format_docs

lint:
	GOOS=linux golangci-lint run ./...
	GOOS=android golangci-lint run ./...
	GOOS=windows golangci-lint run ./...
	GOOS=darwin golangci-lint run ./...
#	GOOS=freebsd golangci-lint run ./...

lint_install:
	go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

proto:
	@go run ./cmd/internal/protogen
	@golangci-lint fmt

proto_install:
	go install -v google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install -v google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

update_certificates:
	go run ./cmd/internal/update_certificates

release: build_admin_panel build_naive
	CRONET_GO_PATH=$(CRONET_GO_PATH) go run ./cmd/internal/build goreleaser release --skip=validate --clean -p 3 --skip publish
	mkdir dist/release
	mv dist/*.tar.gz \
		dist/*.zip \
		dist/*.ipk \
		dist/*.apk \
		dist/release
	ghr --replace --draft --prerelease -p 5 "v${VERSION}" dist/release
	./codeberg-release.sh --replace --draft --prerelease -p 5 "v${VERSION}" dist/release
	rm -r dist/release

release_repo:
	go run ./cmd/internal/build goreleaser release -f .goreleaser.fury.yaml --clean

release_install:
	go install -v github.com/tcnksm/ghr@latest

release_docker:
	sudo docker buildx build \
		--platform $(DOCKER_PLATFORMS) \
		-t $(DOCKER_IMAGE):latest \
		-t $(DOCKER_IMAGE):$(VERSION) \
		--push \
		--network=host \
		.

update_android_version:
	go run ./cmd/internal/update_android_version

update_desktop_version:
	go run ./cmd/internal/update_desktop_version

build_android:
	cd ../sing-box-for-android && ./gradlew :app:clean :app:assembleOtherRelease && ./gradlew --stop

upload_android:
	mkdir -p dist/release_android
	cp ../sing-box-for-android/app/build/outputs/apk/other/release/*.apk dist/release_android
	VERSION_CODE=$$(grep VERSION_CODE ../sing-box-for-android/version.properties | cut -d= -f2); \
	VERSION_NAME=$$(grep VERSION_NAME ../sing-box-for-android/version.properties | cut -d= -f2); \
	printf '{\n  "version_code": %s,\n  "version_name": "%s"\n}\n' "$$VERSION_CODE" "$$VERSION_NAME" > dist/release_android/SFA-version-metadata.json
	ghr --replace --draft --prerelease -p 5 "v${VERSION}" dist/release_android
	./codeberg-release.sh --replace --draft --prerelease -p 5 "v${VERSION}" dist/release_android
	rm -rf dist/release_android

release_android: lib_android update_android_version build_android upload_android

publish_android:
	cd ../sing-box-for-android && ./gradlew :app:publishPlayReleaseBundle && ./gradlew --stop

build_desktop_windows:
	cd ../sing-box-for-desktop && pnpm install --frozen-lockfile && pnpm run package:win

build_desktop_linux:
	cd ../sing-box-for-desktop && pnpm install --frozen-lockfile && pnpm run package:linux

upload_desktop:
	mkdir -p dist/release_desktop
	cp ../sing-box-for-desktop/release/SFW-*.exe dist/release_desktop 2>/dev/null || true
	cp ../sing-box-for-desktop/release/SFL-*.deb ../sing-box-for-desktop/release/SFL-*.rpm ../sing-box-for-desktop/release/SFL-*.pkg.tar.zst dist/release_desktop 2>/dev/null || true
	ghr --replace --draft --prerelease -p 5 "v${VERSION}" dist/release_desktop
	./codeberg-release.sh --replace --draft --prerelease -p 5 "v${VERSION}" dist/release_desktop
	rm -rf dist/release_desktop

release_desktop: update_desktop_version build_desktop_windows build_desktop_linux upload_desktop

# TODO: find why and remove `-destination 'generic/platform=iOS'`
# TODO: remove xcode clean when fix control widget fixed
build_ios:
	cd ../sing-box-for-apple && \
	rm -rf build/SFI.xcarchive && \
	xcodebuild clean -scheme SFI -derivedDataPath build/SFI.dd && \
	xcodebuild archive -scheme SFI -configuration Release -destination 'generic/platform=iOS' -archivePath build/SFI.xcarchive -derivedDataPath build/SFI.dd -allowProvisioningUpdates | xcbeautify | grep -A 10 -e "Archive Succeeded" -e "ARCHIVE FAILED" -e "❌"

upload_ios_app_store:
	cd ../sing-box-for-apple && \
	xcodebuild -exportArchive -archivePath build/SFI.xcarchive -exportOptionsPlist SFI/Upload.plist -allowProvisioningUpdates

build_ios_deb:
	$(MAKE) -C ../sing-box-for-apple build_ios_deb

upload_ios_deb:
	ghr --replace --draft --prerelease "v${VERSION}" ../sing-box-for-apple/build/jailbreak/"SFI-${VERSION}-iphoneos-arm64.deb"
	ghr --replace --draft --prerelease "v${VERSION}" ../sing-box-for-apple/build/jailbreak/"SFI-${VERSION}-iphoneos-arm64e.deb"

release_ios: build_ios upload_ios_app_store

release_ios_deb: build_ios_deb upload_ios_deb

build_macos:
	cd ../sing-box-for-apple && \
	rm -rf build/SFM.xcarchive && \
	xcodebuild archive -scheme SFM -configuration Release -archivePath build/SFM.xcarchive -derivedDataPath build/SFM.dd -allowProvisioningUpdates | xcbeautify | grep -A 10 -e "Archive Succeeded" -e "ARCHIVE FAILED" -e "❌"

upload_macos_app_store:
	cd ../sing-box-for-apple && \
	xcodebuild -exportArchive -archivePath build/SFM.xcarchive -exportOptionsPlist SFI/Upload.plist -allowProvisioningUpdates

release_macos: build_macos upload_macos_app_store

build_macos_standalone:
	$(MAKE) -C ../sing-box-for-apple archive_macos_standalone

build_macos_dmg:
	$(MAKE) -C ../sing-box-for-apple build_macos_dmg

build_macos_pkg:
	$(MAKE) -C ../sing-box-for-apple build_macos_pkg

notarize_macos_dmg:
	$(MAKE) -C ../sing-box-for-apple notarize_macos_dmg

notarize_macos_pkg:
	$(MAKE) -C ../sing-box-for-apple notarize_macos_pkg

upload_macos_dmg:
	mkdir -p dist/SFM
	cp ../sing-box-for-apple/build/SFM-Apple.dmg "dist/SFM/SFM-${VERSION}-Apple.dmg"
	cp ../sing-box-for-apple/build/SFM-Intel.dmg "dist/SFM/SFM-${VERSION}-Intel.dmg"
	cp ../sing-box-for-apple/build/SFM-Universal.dmg "dist/SFM/SFM-${VERSION}-Universal.dmg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Apple.dmg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Intel.dmg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Universal.dmg"

upload_macos_pkg:
	mkdir -p dist/SFM
	cp ../sing-box-for-apple/build/SFM-Apple.pkg "dist/SFM/SFM-${VERSION}-Apple.pkg"
	cp ../sing-box-for-apple/build/SFM-Intel.pkg "dist/SFM/SFM-${VERSION}-Intel.pkg"
	cp ../sing-box-for-apple/build/SFM-Universal.pkg "dist/SFM/SFM-${VERSION}-Universal.pkg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Apple.pkg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Intel.pkg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Universal.pkg"

replace_macos_pkg:
	mkdir -p dist/SFM
	cp ../sing-box-for-apple/build/SFM-Apple.pkg "dist/SFM/SFM-${VERSION}-Apple.pkg"
	cp ../sing-box-for-apple/build/SFM-Intel.pkg "dist/SFM/SFM-${VERSION}-Intel.pkg"
	cp ../sing-box-for-apple/build/SFM-Universal.pkg "dist/SFM/SFM-${VERSION}-Universal.pkg"
	ghr --replace "v${VERSION}" "dist/SFM/SFM-${VERSION}-Apple.pkg"
	ghr --replace "v${VERSION}" "dist/SFM/SFM-${VERSION}-Intel.pkg"
	ghr --replace "v${VERSION}" "dist/SFM/SFM-${VERSION}-Universal.pkg"

upload_macos_dsyms:
	mkdir -p dist/SFM
	cd ../sing-box-for-apple/build/SFM.System-universal.xcarchive && zip -r SFM.dSYMs.zip dSYMs
	cp ../sing-box-for-apple/build/SFM.System-universal.xcarchive/SFM.dSYMs.zip "dist/SFM/SFM-${VERSION}.dSYMs.zip"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}.dSYMs.zip"

replace_macos_dsyms:
	mkdir -p dist/SFM
	cd ../sing-box-for-apple/build/SFM.System-universal.xcarchive && zip -r SFM.dSYMs.zip dSYMs
	cp ../sing-box-for-apple/build/SFM.System-universal.xcarchive/SFM.dSYMs.zip "dist/SFM/SFM-${VERSION}.dSYMs.zip"
	ghr --replace "v${VERSION}" "dist/SFM/SFM-${VERSION}.dSYMs.zip"

release_macos_standalone: build_macos_pkg notarize_macos_pkg upload_macos_pkg upload_macos_dsyms

replace_macos_standalone: build_macos_pkg notarize_macos_pkg upload_macos_pkg upload_macos_dsyms

build_tvos:
	cd ../sing-box-for-apple && \
	rm -rf build/SFT.xcarchive && \
	xcodebuild archive -scheme SFT -configuration Release -archivePath build/SFT.xcarchive -derivedDataPath build/SFT.dd -allowProvisioningUpdates | xcbeautify | grep -A 10 -e "Archive Succeeded" -e "ARCHIVE FAILED" -e "❌"

upload_tvos_app_store:
	cd ../sing-box-for-apple && \
	xcodebuild -exportArchive -archivePath "build/SFT.xcarchive" -exportOptionsPlist SFI/Upload.plist -allowProvisioningUpdates

export_tvos_ipa:
	cd ../sing-box-for-apple && \
	xcodebuild -exportArchive -archivePath "build/SFT.xcarchive" -exportOptionsPlist SFI/Export.plist -allowProvisioningUpdates -exportPath build/SFT && \
	cp build/SFT/sing-box.ipa dist/SFT.ipa

upload_tvos_ipa:
	cd dist && \
	cp SFT.ipa "SFT-${VERSION}.ipa" && \
	ghr --replace --draft --prerelease "v${VERSION}" "SFT-${VERSION}.ipa"

release_tvos: build_tvos upload_tvos_app_store

update_apple_version:
	go run ./cmd/internal/update_apple_version

update_macos_version:
	MACOS_PROJECT_VERSION=$(shell go run ./cmd/internal/app_store_connect next_project_version macos) go run ./cmd/internal/update_apple_version

release_apple: lib_apple update_apple_version release_ios release_macos release_tvos release_macos_standalone

release_apple_beta: update_apple_version release_ios release_macos release_tvos

publish_testflight:
	go run -v ./cmd/internal/app_store_connect publish_testflight $(filter-out $@,$(MAKECMDGOALS))

submit_app_store:
	go run -v ./cmd/internal/app_store_connect submit_app_store $(filter-out $@,$(MAKECMDGOALS))

release_app_store: release_ios release_tvos submit_app_store

publish_app_store:
	go run -v ./cmd/internal/app_store_connect publish_app_store $(filter-out $@,$(MAKECMDGOALS))

test:
	@go test -v ./... && \
	cd test && \
	go mod tidy && \
	go test -v -tags "$(TAGS_TEST)" .

test_stdio:
	@go test -v ./... && \
	cd test && \
	go mod tidy && \
	go test -v -tags "$(TAGS_TEST),force_stdio" .

lib_android:
	go run ./cmd/internal/build_libbox -target android

lib_apple:
	go run ./cmd/internal/build_libbox -target apple

lib_windows:
	$(SING_FFI) generate --config $(LIBBOX_FFI_CONFIG) --platform-type csharp

lib_android_new:
	$(SING_FFI) generate --config $(LIBBOX_FFI_CONFIG) --platform-type android

lib_apple_new:
	$(SING_FFI) generate --config $(LIBBOX_FFI_CONFIG) --platform-type apple

lib_install:
	go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
	go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.13

docs:
	venv/bin/mkdocs serve

publish_docs:
	venv/bin/mkdocs gh-deploy -m "Update" --force --ignore-version --no-history

docs_install:
	python3 -m venv venv
	source ./venv/bin/activate && pip install --force-reinstall mkdocs-material=="9.7.2" mkdocs-static-i18n=="1.2.*"

clean:
	rm -rf bin dist sing-box
	rm -f $(shell go env GOPATH)/sing-box

update:
	git fetch
	git reset FETCH_HEAD --hard
	git clean -fdx

%:
	@:
