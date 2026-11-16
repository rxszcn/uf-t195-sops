# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

PROJECT             := github.com/getsops/sops/v3
PROJECT_DIR         := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
BIN_DIR             := $(PROJECT_DIR)/bin

GO                  := GOPROXY=https://proxy.golang.org go
GO_TEST_FLAGS       ?= -race -coverprofile=profile.out -covermode=atomic
# Packages whose tests guard the encryption chain. They are run as a dedicated
# CI gate (see .github/workflows/cli.yml) in addition to the full suite, and are
# the ones held to the "no host key material" rule.
CRYPTO_PACKAGES     := . ./age ./pgp ./aes ./config ./kms ./hcvault ./gcpkms ./hckms ./keyservice ./decrypt ./shamir ./stores/...

GITHUB_REPOSITORY   ?= github.com/getsops/sops

STATICCHECK         := $(BIN_DIR)/staticcheck
STATICCHECK_VERSION := latest

SYFT                := $(BIN_DIR)/syft
SYFT_VERSION        ?= v0.87.0

GORELEASER          := $(BIN_DIR)/goreleaser
GORELEASER_VERSION  ?= v1.20.0

PROTOC_GO           := $(BIN_DIR)/protoc-gen-go
PROTOC_GO_VERSION   ?= v1.35.2

PROTOC_GO_GRPC      := $(BIN_DIR)/protoc-gen-go-grpc
PROTOC_GO_GRPC_VERSION ?= v1.5.1

RSTCHECK            := $(shell command -v rstcheck)
MARKDOWNLINT        := $(shell command -v mdl)

export PATH := $(BIN_DIR):$(PATH)

.PHONY: all
all: test vet generate install functional-tests

.PHONY: origin-build
origin-build: test vet generate install functional-tests-all

.PHONY: install
install:
	$(GO) install github.com/getsops/sops/v3/cmd/sops

.PHONY: staticcheck
staticcheck: install-staticcheck
	$(STATICCHECK) ./...

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor

.PHONY: vet
vet:
	$(GO) vet ./...


.PHONY: checkdocs
checkdocs: checkrst checkmd

.PHONY: checkrst
RST_FILES=$(shell find . -name '*.rst' | grep -v /vendor/ | sort)
checkrst: $(RST_FILES)
	@if [ "$(RSTCHECK)" == "" ]; then echo "Need rstcheck to lint RST files. Install rstcheck from your system package repository or from PyPI (https://pypi.org/project/rstcheck/)."; exit 1; fi
	$(RSTCHECK) --report-level warning $^

.PHONY: checkmd
MD_FILES=$(shell find . -name '*.md' | grep -v /vendor/ | sort)
checkmd: $(MD_FILES)
	@if [ "$(MARKDOWNLINT)" == "" ]; then echo "Need markdownlint to lint RST files. Install markdownlint from your system package repository or from https://github.com/markdownlint/markdownlint."; exit 1; fi
	$(MARKDOWNLINT) $^

.PHONY: test
test: vendor
	gpg --import pgp/sops_functional_tests_key.asc 2>&1 1>/dev/null || exit 0
	unset SOPS_AGE_KEY; unset SOPS_AGE_KEY_FILE; unset SOPS_AGE_KEY_CMD; unset SOPS_AGE_RECIPIENT; unset SOPS_AGE_SSH_PRIVATE_KEY_FILE; unset SOPS_AGE_SSH_PRIVATE_KEY_CMD; LANG=en_US.UTF-8 $(GO) test $(GO_TEST_FLAGS) ./...

# crypto-test runs the packages that guard the encryption chain with an
# environment that cannot see the host's key material or credentials. The
# TestMain of those packages already builds that sandbox (internal/testenv); the
# explicit unset here additionally protects the packages that do not have one,
# and makes the intent of the gate readable in CI logs.
.PHONY: crypto-test
crypto-test:
	unset SOPS_AGE_KEY SOPS_AGE_KEY_FILE SOPS_AGE_KEY_CMD SOPS_AGE_RECIPIENT \
		SOPS_AGE_SSH_PRIVATE_KEY_FILE SOPS_AGE_SSH_PRIVATE_KEY_CMD \
		SOPS_GPG_EXEC GOOGLE_CREDENTIALS GOOGLE_OAUTH_ACCESS_TOKEN \
		GOOGLE_APPLICATION_CREDENTIALS VAULT_TOKEN VAULT_ADDR \
		AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE; \
	GPG_AGENT_INFO= LANG=en_US.UTF-8 $(GO) test $(GO_TEST_FLAGS) $(CRYPTO_PACKAGES)

# crypto-test-poisoned deliberately puts hostile key material and credentials in
# the environment before running the same gate. Every test must either ignore it
# or undo it itself; any red here means a test still trusts the host.
.PHONY: crypto-test-poisoned
crypto-test-poisoned:
	SOPS_AGE_KEY="AGE-SECRET-KEY-1432K5YRNSC44GC4986NXMX6GVZ52WTMT9C79CLUVWYY4DKDHD5JSNDP4MC" \
	SOPS_AGE_KEY_FILE=/nonexistent/sops-age-keys.txt \
	SOPS_AGE_KEY_CMD="echo AGE-SECRET-KEY-1432K5YRNSC44GC4986NXMX6GVZ52WTMT9C79CLUVWYY4DKDHD5JSNDP4MC" \
	SOPS_AGE_SSH_PRIVATE_KEY_FILE=/nonexistent/id_ed25519 \
	SOPS_AGE_SSH_PRIVATE_KEY_CMD="echo bogus" \
	GOOGLE_CREDENTIALS=bogus-credentials \
	GOOGLE_OAUTH_ACCESS_TOKEN=bogus-token \
	VAULT_TOKEN=bogus-token \
	VAULT_ADDR=http://127.0.0.1:1 \
	AWS_ACCESS_KEY_ID=bogus \
	AWS_SECRET_ACCESS_KEY=bogus \
	AWS_SESSION_TOKEN=bogus \
	GPG_AGENT_INFO= \
	LANG=en_US.UTF-8 $(GO) test $(GO_TEST_FLAGS) $(CRYPTO_PACKAGES)

.PHONY: showcoverage
showcoverage: test
	$(GO) tool cover -html=profile.out

.PHONY: generate
generate: install-protoc-go install-protoc-go-grpc keyservice/keyservice.pb.go
	$(GO) generate

%.pb.go: %.proto
	protoc --plugin gen-go=$(PROTOC_GO) --plugin gen-go-grpc=$(PLUGIN_GO_GRPC) --go-grpc_opt=require_unimplemented_servers=false --go-grpc_out=. --go_out=. $<

.PHONY: functional-tests
functional-tests:
	$(GO) build -o functional-tests/sops github.com/getsops/sops/v3/cmd/sops
	cd functional-tests && cargo test

.PHONY: functional-tests-all
functional-tests-all:
	$(GO) build -o functional-tests/sops github.com/getsops/sops/v3/cmd/sops
	# Ignored tests are ones that require external services (e.g. AWS KMS)
	# 	TODO: Once `--include-ignored` lands in rust stable, switch to that.
	cd functional-tests && cargo test && cargo test -- --ignored

.PHONY: release-snapshot
release-snapshot: install-goreleaser install-syft
	GITHUB_REPOSITORY=$(GITHUB_REPOSITORY) $(GORELEASER) release --clean --snapshot --skip=sign

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) profile.out functional-tests/sops

.PHONY: install-staticcheck
install-staticcheck:
	$(call go-install-tool,$(STATICCHECK),honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION),$(STATICCHECK_VERSION))

.PHONY: install-goreleaser
install-goreleaser:
	$(call go-install-tool,$(GORELEASER),github.com/goreleaser/goreleaser@$(GORELEASER_VERSION),$(GORELEASER_VERSION))

.PHONY: install-syft
install-syft:
	$(call go-install-tool,$(SYFT),github.com/anchore/syft/cmd/syft@$(SYFT_VERSION),$(SYFT_VERSION))

.PHONY: install-protoc-go
install-protoc-go:
	$(call go-install-tool,$(PROTOC_GO),google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GO_VERSION),$(PROTOC_GO_VERSION))

.PHONY: install-protoc-go-grpc
install-protoc-go-grpc:
	$(call go-install-tool,$(PROTOC_GO_GRPC),google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GO_GRPC_VERSION),$(PROTOC_GO_GRPC_VERSION))

# go-install-tool will 'go install' any package $2 and install it to $1.
define go-install-tool
@[ -f $(1)-$(3) ] || { \
set -e ;\
GOBIN=$$(dirname $(1)) go install $(2) ;\
touch $(1)-$(3) ;\
}
endef
