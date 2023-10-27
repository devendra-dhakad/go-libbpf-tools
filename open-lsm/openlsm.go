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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type event -cc clang -cflags "-O2 -g -Wall -Werror" openlsm  ./bpf/openlsm.bpf.c -- -I../headers

func main() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	logFile, _ := os.Create("openlsm.log")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(logFile)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := openlsmObjects{}

	opt := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			//Verbose to catch eBPF verifier issues
			LogLevel: 1,
			LogSize:  65535,
		},
	}
	if err := loadOpenlsmObjects(&objs, &opt); err != nil {
		log.Printf("%v", err)
	}
	defer objs.Close()
	if _, err := link.AttachLSM(link.LSMOptions{
		Program: objs.openlsmPrograms.FileOpen,
	}); err != nil {
		log.Printf("%v", err)
	}
	reader, err := ringbuf.NewReader(objs.openlsmMaps.Ringbuff)
	if err != nil {
		log.Printf("%v", err)
	}
	go ringbuff(reader)
	<-ch
}
func ringbuff(reader *ringbuf.Reader) {
	var event_data openlsmEvent
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
		fmt.Printf("timestamp %v  filename %s \n",
			time.Unix(int64(event_data.TimeStamp), 0),
			event_data.Filename[:])
		log.Printf("timestamp %v  filename %s \n",
			time.Unix(int64(event_data.TimeStamp), 0),
			event_data.Filename[:])
	}
}
