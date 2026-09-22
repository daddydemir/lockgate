.PHONY: build test integration run
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/lockgate ./cmd/lockgate
test:
	go test ./...
integration:
	@test -n "$(LOCKGATE_TEST_DATABASE_URL)" || (echo 'Set LOCKGATE_TEST_DATABASE_URL to a disposable PostgreSQL database'; exit 1)
	go test -race -p 1 ./...
run:
	go run ./cmd/lockgate serve
