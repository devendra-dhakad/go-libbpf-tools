package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror" -type event accept ./bpf/accept.bpf.c -- -I../headers
func main() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	logFile, _ := os.Create("exesnoop.log")
	log.SetFlags(log.LstdFlags)
	log.SetOutput(io.MultiWriter(logFile, os.Stdout))

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := acceptObjects{}

	collectionSpec, _ := ebpf.LoadCollectionSpec("accept_bpfel.o")

	opt := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			//Verbose to catch eBPF verifier issues
			LogLevel: 1,
			LogSize:  655358888,
		},
	}

	if err := collectionSpec.LoadAndAssign(&objs, &opt); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)

		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}
		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}
	defer objs.Close()

	if _, err := link.Tracepoint("syscalls", "sys_enter_accept", objs.acceptPrograms.AcceptSyscall, nil); err != nil {
		log.Fatalf("Not able to attach to  tracepoint %v", err)
	}

	reader, err := ringbuf.NewReader(objs.acceptMaps.Ringbuff)
	if err != nil {
		log.Printf("%v", err)
	}
	go ringbuff(reader)
	<-ch
}

func IntToIPv4(ipaddr uint32) net.IP {
	ip := make(net.IP, net.IPv4len)

	// Proceed conversion
	binary.BigEndian.PutUint32(ip, ipaddr)
	return ip
}

func ringbuff(reader *ringbuf.Reader) {
	var event_data acceptEvent
	for {
		rd_data, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Fatalf("Ring buffer is closed. exiting.. %v", err)
			}
			log.Printf("Ring buffer read error %v", err)
		}
		if err := binary.Read(bytes.NewBuffer(rd_data.RawSample), binary.LittleEndian, &event_data); err != nil {
			log.Printf("error in parsing ringbuff data")
		}

		log.Printf("Process ID: %d, User ID: %d, Group ID: %d, Effective User ID: %d, Effective Group ID: %d, CWD : %s, Syscall arguments: FD %d, Addrlen %d, S_family %d IP %d Port %d\n",
			event_data.Pid,
			event_data.Uid,
			event_data.Gid,
			event_data.Euid,
			event_data.Egid,
			event_data.Cwd[:],
			event_data.Fd,
			event_data.Addrlen,
			event_data.S_family,
			IntToIPv4(event_data.IpAddr),
			event_data.Port,
		)

	}
}
