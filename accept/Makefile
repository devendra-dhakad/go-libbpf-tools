APP=exesnoop

.PHONY: build
build: gen $(APP)

.PHONY: gen
gen: bpf2go gobuild run

run: exesnoop.go exesnoop_bpfel.go
	./$(APP)


gobuild:
	CGO_ENABLED=0 go build -o $(APP) .

bpf2go:
	go generate


