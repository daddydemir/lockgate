.PHONY: build test integration run sdk-test
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

sdk-test:
	go test ./pkg/client
	cd sdk/javascript && npm test
	PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests
	cmp -s sdk/javascript/index.js web/static/examples/lockgate.mjs
	cmp -s sdk/python/src/lockgate_client/__init__.py web/static/examples/lockgate.py
