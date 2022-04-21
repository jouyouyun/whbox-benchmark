PRJ=whbox-benchmark
PROG_UPGRADER=${PRJ}
PWD=$(shell pwd)
GOPATH_DIR=gopath

all: build

prepare:
	@if [ ! -d ${GOPATH_DIR}/src/${PRJ} ]; then \
		mkdir -p ${GOPATH_DIR}/src/${PRJ}; \
		ln -sf ${PWD}/pkg ${GOPATH_DIR}/src/${PRJ}; \
	fi

build: prepare
	@env GOPATH=${PWD}/${GOPATH_DIR}:${GOCODE}:${GOPATH} go build -o ${PWD}/${PRJ} ./cmd/${PRJ}/

clean:
	@rm -rf ${GOPATH_DIR}
	@rm -rf ${PWD}/${PRJ}

rebuild: clean build
