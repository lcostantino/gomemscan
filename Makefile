VERSION := $(shell git describe --always --long --dirty)
PKG := github.com/lcostantino/gomemscan/memscan
OUT := gomemscan

all: compile

compile:
	go build -i -v -o ${OUT} -ldflags="-X main.version=${VERSION}" 

