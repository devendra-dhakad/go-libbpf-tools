package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror" -type event opensnoop ./bpf/opensnoop.bpf.c -- -I../headers
func main() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	logFile, _ := os.Create("opensnoop.log")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(logFile)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := opensnoopObjects{}

	collectionSpec, _ := ebpf.LoadCollectionSpec("opensnoop_bpfel.o")
	if collectionSpec.Types != nil {
		err := collectionSpec.RewriteConstants(map[string]interface{}{
			"happy": uint32(5),
		})
		if err != nil {
			fmt.Println("Can't rewrite constant")
		}
	}

	opt := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			//Verbose to catch eBPF verifier issues
			LogLevel: 1,
			LogSize:  65535,
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

	if _, err := link.Tracepoint("syscalls", "sys_enter_open", objs.opensnoopPrograms.OpenSyscall, nil); err != nil {
		log.Fatalf("Not able to attach to  tracepoint %v", err)
	}

	if _, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.opensnoopPrograms.OpenatSyscall, nil); err != nil {
		log.Fatalf("Not able to attach to  tracepoint %v", err)
	}

	if _, err := link.Tracepoint("syscalls", "sys_enter_openat2", objs.opensnoopPrograms.Openat2Syscall, nil); err != nil {
		log.Fatalf("Not able to attach to  tracepoint %v", err)
	}

	reader, err := ringbuf.NewReader(objs.opensnoopMaps.Ringbuff)
	if err != nil {
		log.Printf("%v", err)
	}
	go ringbuff(reader)
	<-ch
}
func ringbuff(reader *ringbuf.Reader) {
	var event_data opensnoopEvent
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
		fmt.Printf("timestamp %v  uid %v PID %v TID %d filename %s code %d \n",
			time.Unix(int64(event_data.TimeStamp), 0),
			event_data.UserIdentifier,
			event_data.ProcessIdentifier, event_data.ThreadIdentifier,
			event_data.Filename[:], event_data.Code)
		log.Printf("timestamp %v  uid %v PID %v TID %d filename %s code %d \n",
			time.Unix(int64(event_data.TimeStamp), 0),
			event_data.UserIdentifier,
			event_data.ProcessIdentifier,
			event_data.ThreadIdentifier,
			event_data.Filename[:],
			event_data.Code)
	}
}
