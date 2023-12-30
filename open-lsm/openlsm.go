package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type event  -cc clang -cflags "-O2 -g -Wall -Werror" openlsm  ./bpf/openlsm.bpf.c -- -I../headers

func main() {

	logFile, _ := os.Create("openlsm.log")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	multi := io.MultiWriter(logFile, os.Stdout)
	log.SetOutput(multi)

	var file_pointer = flag.String("f", "", "file name")
	var path = flag.String("p", "", "file name")
	flag.Parse()
	if *file_pointer == "" && *path == "" {
		log.Fatalln("Please provide file name ")
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := openlsmObjects{}

	opt := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			//Verbose to catch eBPF verifier issues
			LogLevel: ebpf.LogLevelBranch,
			LogSize:  65535 * 10,
		},
	}

	if err := loadOpenlsmObjects(&objs, &opt); err != nil {
		fmt.Printf("%v", err)

	}

	defer objs.Close()

	var filename_arr [128]byte
	var pathArr [128]byte

	copy(filename_arr[:], []byte(*file_pointer))
	if err := objs.ArgMap.Put(uint32(0), filename_arr); err != nil {
		log.Printf("adding file name in map %v", err)
	}

	copy(pathArr[:], []byte(*path))
	objs.ArgMap.Put(uint32(1), pathArr)

	link, err := link.AttachLSM(link.LSMOptions{
		Program: objs.openlsmPrograms.FileOpen,
	})

	defer link.Close()

	if err != nil {
		log.Printf("could not attach LSM program %v", err)
	}
	reader, err := ringbuf.NewReader(objs.openlsmMaps.Ringbuff)
	if err != nil {
		log.Printf("%v", err)
	}
	go ringbuff(reader)
	<-ch
}

func printChar(arry [128]uint8) string {
	// str [128]string
	var builder strings.Builder
	for _, b := range arry {
		if b == 0 {
			break // Stop appending bytes at null terminator
		}
		builder.WriteByte(b)
	}
	return builder.String()
}
func ringbuff(reader *ringbuf.Reader) {
	var event_data openlsmEvent
	for {
		rd_data, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Fatalf("Ring buffer is closed. exiting.. %v", err)
			}
			log.Printf("\n Ring buffer read error %v", err)
		}
		if err := binary.Read(bytes.NewBuffer(rd_data.RawSample), binary.LittleEndian, &event_data); err != nil {
			log.Printf("error in parsing ringbuff data")
		}
		log.Printf("file opened by system %s, path %s\n",
			event_data.FileName, printChar(event_data.Path))

	}
}
