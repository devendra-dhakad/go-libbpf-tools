sudo go generate
sudo CGO_ENABLED=0 go build -o opensnoop  .
sudo ./opensnoop
