ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

.PHONY: test
test:
	cd ${ROOT_DIR} && go test -v ./...
