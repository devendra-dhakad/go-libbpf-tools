APP=openlsm

.PHONY: build
build: gen $(APP)

.PHONY: gen
gen: bpf2go gobuild run

run: openlsm.go openlsm_bpfel.go
	./$(APP) -f happy.txt -p /home/devendradhakad/website


gobuild:
	CGO_ENABLED=0 go build -o $(APP) .

bpf2go:
	go generate



