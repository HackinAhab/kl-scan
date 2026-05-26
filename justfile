bin_dir := "~/.local/bin"
binary := "kl-scan"
cmd := "./cmd/kl-scan"

build:
    mkdir -p {{bin_dir}}
    go build -trimpath -ldflags "-s -w" -o {{bin_dir}}/{{binary}} {{cmd}}

build-all:
    mkdir -p {{bin_dir}}
    for os in linux darwin windows; do \
      for arch in amd64 arm64; do \
        name="{{binary}}-${os}-${arch}"; \
        if [ "$${os}" = "windows" ]; then name="$${name}.exe"; fi; \
        CGO_ENABLED=0 GOOS="$${os}" GOARCH="$${arch}" \
          go build -trimpath -ldflags "-s -w" -o "{{bin_dir}}/$${name}" {{cmd}}; \
      done; \
    done

test:
    go test ./...

vet:
    go vet ./...

lint:
    golangci-lint run ./...

clean:
    rm -rf {{bin_dir}}/{{binary}}

run *args:
    go run {{cmd}} {{args}}
