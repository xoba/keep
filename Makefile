.PHONY: build vet test scan

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

scan:
	gitleaks git .
	trufflehog git file://. --only-verified --fail
