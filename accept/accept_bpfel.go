// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type acceptEvent struct {
	Uid      uint32
	Pid      int32
	Gid      uint32
	Euid     uint32
	Egid     uint32
	Fd       uint32
	Cwd      [50]uint8
	S_family uint16
	Addrlen  int32
	IpAddr   uint32
	Port     uint16
	_        [2]byte
}

// loadAccept returns the embedded CollectionSpec for accept.
func loadAccept() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_AcceptBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load accept: %w", err)
	}

	return spec, err
}

// loadAcceptObjects loads accept and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*acceptObjects
//	*acceptPrograms
//	*acceptMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadAcceptObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadAccept()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// acceptSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type acceptSpecs struct {
	acceptProgramSpecs
	acceptMapSpecs
}

// acceptSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type acceptProgramSpecs struct {
	AcceptSyscall *ebpf.ProgramSpec `ebpf:"accept_syscall"`
}

// acceptMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type acceptMapSpecs struct {
	Ringbuff *ebpf.MapSpec `ebpf:"ringbuff"`
}

// acceptObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadAcceptObjects or ebpf.CollectionSpec.LoadAndAssign.
type acceptObjects struct {
	acceptPrograms
	acceptMaps
}

func (o *acceptObjects) Close() error {
	return _AcceptClose(
		&o.acceptPrograms,
		&o.acceptMaps,
	)
}

// acceptMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadAcceptObjects or ebpf.CollectionSpec.LoadAndAssign.
type acceptMaps struct {
	Ringbuff *ebpf.Map `ebpf:"ringbuff"`
}

func (m *acceptMaps) Close() error {
	return _AcceptClose(
		m.Ringbuff,
	)
}

// acceptPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadAcceptObjects or ebpf.CollectionSpec.LoadAndAssign.
type acceptPrograms struct {
	AcceptSyscall *ebpf.Program `ebpf:"accept_syscall"`
}

func (p *acceptPrograms) Close() error {
	return _AcceptClose(
		p.AcceptSyscall,
	)
}

func _AcceptClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed accept_bpfel.o
var _AcceptBytes []byte
