APP=openlsm

.PHONY: build
build: gen $(APP)

.PHONY: gen
gen: vmlinux bpf2go gobuild run

run: openlsm.go openlsm_bpfel.go
	./$(APP) -f happy.txt


gobuild:
	CGO_ENABLED=0 go build -o $(APP) .

bpf2go:
	go generate

vmlinux:
	bpftool btf dump id 1 format c > ../headers/vmlinux.h

