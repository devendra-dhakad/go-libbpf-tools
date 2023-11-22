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

type exesnoopEvent struct {
	Uid      uint32
	Pid      int32
	Gid      uint32
	Euid     uint32
	Egid     uint32
	FileName [100]uint8
	Cwd      [100]uint8
	Argv     [10][100]uint8
	Envp     [10][100]uint8
}

// loadExesnoop returns the embedded CollectionSpec for exesnoop.
func loadExesnoop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ExesnoopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load exesnoop: %w", err)
	}

	return spec, err
}

// loadExesnoopObjects loads exesnoop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*exesnoopObjects
//	*exesnoopPrograms
//	*exesnoopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadExesnoopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadExesnoop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// exesnoopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type exesnoopSpecs struct {
	exesnoopProgramSpecs
	exesnoopMapSpecs
}

// exesnoopSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type exesnoopProgramSpecs struct {
	ExecveSyscall *ebpf.ProgramSpec `ebpf:"execve_syscall"`
}

// exesnoopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type exesnoopMapSpecs struct {
	Ringbuff *ebpf.MapSpec `ebpf:"ringbuff"`
}

// exesnoopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadExesnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type exesnoopObjects struct {
	exesnoopPrograms
	exesnoopMaps
}

func (o *exesnoopObjects) Close() error {
	return _ExesnoopClose(
		&o.exesnoopPrograms,
		&o.exesnoopMaps,
	)
}

// exesnoopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadExesnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type exesnoopMaps struct {
	Ringbuff *ebpf.Map `ebpf:"ringbuff"`
}

func (m *exesnoopMaps) Close() error {
	return _ExesnoopClose(
		m.Ringbuff,
	)
}

// exesnoopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadExesnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type exesnoopPrograms struct {
	ExecveSyscall *ebpf.Program `ebpf:"execve_syscall"`
}

func (p *exesnoopPrograms) Close() error {
	return _ExesnoopClose(
		p.ExecveSyscall,
	)
}

func _ExesnoopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed exesnoop_bpfel.o
var _ExesnoopBytes []byte
