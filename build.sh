CGO_LDFLAGS="-static `pkg-config --static --libs yara` -lm"

goreleaser build --skip-validate --rm-dist 

