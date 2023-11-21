APP=accept

.PHONY: build
build: gen $(APP)

.PHONY: gen
gen: bpf2go gobuild run

run: accept.go accept_bpfel.go
	./$(APP)


gobuild:
	CGO_ENABLED=0 go build -o $(APP) .

bpf2go:
	go generate


