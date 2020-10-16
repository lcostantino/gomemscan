#Switch to goreleaser in the future :)

VERSION := $(shell git describe --always --long --dirty)
PKG := github.com/lcostantino/gomemscan/memscan
OUT := gomemscan
TAGS := $(shell git describe --tags)
all: compile

compile:
	go build  -i -v -o ${OUT} -ldflags="-X main.version=${TAGS}-${VERSION}"   app/gomemscan.go  

