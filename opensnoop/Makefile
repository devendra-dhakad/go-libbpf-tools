APP=opensnoop

.PHONY: build
build: gen $(APP)

.PHONY: gen
gen: vmlinux bpf2go gobuild run

run: opensnoop.go opensnoop_bpfel.go
	./$(APP)


gobuild:
	CGO_ENABLED=0 go build -o $(APP) .

bpf2go:
	go generate

vmlinux:
	bpftool btf dump id 1 format c > ../headers/vmlinux.h

