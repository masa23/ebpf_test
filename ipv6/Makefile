all: bpf_build build

bpf_build:
	go generate


build:
	go build -v

clean:
	go clean
	rm tc_*
