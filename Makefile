NAMESPACE			= flomation.app/sentinel
DATE				= $(shell date -u +%Y%m%d_%H%M%S)
NAME				?= sentinel

BRANCH 				:= $(shell git rev-parse --abbrev-ref HEAD)
GITHASH 			?= $(shell git rev-parse HEAD)
CI_PIPELINE_ID 		?= dev
VERSION 			?= 1.0.${CI_PIPELINE_ID}
REGISTRY 			?= local

build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -X $(NAMESPACE)/internal/version.Version=$(VERSION) -X $(NAMESPACE)/internal/version.Hash=$(GITHASH) -X $(NAMESPACE)/internal/version.BuiltDate=$(DATE)" -o ./dist/flomation-${NAME}-${VERSION} $(NAMESPACE)/cmd
	cd dist && zip -r ../build.zip .

lint:
	go mod tidy
	goimports -l .
	golangci-lint run --timeout=5m ./...
	go vet ./...
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec -exclude=G117,G704 ./...
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out