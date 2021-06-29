NAME := check-tls-cert

.PHONY: all
all: build

.PHONY: deps
deps:
	go get -v -d

.PHONY: build
build: deps
	go build check-tls-cert.go

.PHONY: install
install: deps
	go install check-tls-cert.go

.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 go build -o dist/linux_amd64/check-tls-cert check-tls-cert.go

.PHONY: clean
clean:
	go clean

.PHONY: tag
tag:
	bash scripts/bumpup.sh

.PHONY: test
test: prepare-test-cert
	go test -v ./...

.PHONY: coverage
coverage: prepare-test-cert
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out -o coverage.html

.PHONY: prepare-test-once
prepare-test-once:
	bash scripts/gen-private-key.sh &>/dev/null
	bash scripts/gen-root-ca-cert.sh &>/dev/null
	bash scripts/gen-expired-cert.sh &>/dev/null
	bash scripts/gen-not-yet-valid-cert.sh &>/dev/null

prepare-test-cert:
	bash scripts/gen-valid-cert.sh &>/dev/null
	bash scripts/gen-chain-cert.sh &>/dev/null
	bash scripts/gen-ocsp-cert.sh &>/dev/null
