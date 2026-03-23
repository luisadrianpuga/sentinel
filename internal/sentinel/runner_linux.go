//go:build linux

package sentinel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	eventCommSize    = 16
	eventSyscallSize = 16
	eventArgSize     = 256
)

type linuxRunner struct {
	cfg   Config
	store *Store
}

type eventRecord struct {
	Timestamp uint64
	PID       uint32
	Comm      [eventCommSize]byte
	Syscall   [eventSyscallSize]byte
	Arg       [eventArgSize]byte
}

func NewRunner(cfg Config, store *Store) (Runner, error) {
	if cfg.PID == 0 && strings.TrimSpace(cfg.AgentCommand) == "" {
		return nil, errors.New("run requires --agent or --pid")
	}
	return &linuxRunner{cfg: cfg, store: store}, nil
}

func (r *linuxRunner) Run(ctx context.Context) error {
	targetPID, waitFn, err := r.resolveTarget(ctx)
	if err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(r.cfg.BPFObjectPath)
	if err != nil {
		return fmt.Errorf("load bpf object %s: %w", r.cfg.BPFObjectPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load bpf collection: %w", err)
	}
	defer coll.Close()

	filterMap, ok := coll.Maps["target_pid"]
	if !ok {
		return errors.New("bpf object missing target_pid map")
	}
	eventsMap, ok := coll.Maps["events"]
	if !ok {
		return errors.New("bpf object missing events map")
	}

	key := uint32(0)
	if err := filterMap.Put(key, uint32(targetPID)); err != nil {
		return fmt.Errorf("configure target pid: %w", err)
	}

	links, err := attachTracepoints(coll)
	if err != nil {
		return err
	}
	defer closeAll(links)

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	defer reader.Close()

	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	waitErrCh := make(chan error, 1)
	if waitFn != nil {
		go func() {
			waitErrCh <- waitFn()
			reader.Close()
		}()
	}

	log.Printf("tracing pid=%d session=%s", targetPID, r.cfg.AgentRun)
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				break
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		event, err := decodeEvent(record.RawSample)
		if err != nil {
			log.Printf("decode event: %v", err)
			continue
		}
		event.AgentRun = r.cfg.AgentRun
		if err := r.store.InsertEvent(ctx, event); err != nil {
			return fmt.Errorf("persist event: %w", err)
		}
		log.Printf("[%s] pid=%d comm=%s syscall=%s arg=%s",
			event.Timestamp.Format("2006-01-02 15:04:05"),
			event.PID,
			event.Comm,
			event.Syscall,
			event.Arg,
		)
	}

	select {
	case waitErr := <-waitErrCh:
		if waitErr != nil && !errors.Is(waitErr, context.Canceled) {
			return waitErr
		}
	default:
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	return ctx.Err()
}

func (r *linuxRunner) resolveTarget(ctx context.Context) (int, func() error, error) {
	if r.cfg.PID != 0 {
		return r.cfg.PID, nil, nil
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", r.cfg.AgentCommand)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return 0, nil, fmt.Errorf("start agent command: %w", err)
	}
	waitFn := func() error {
		err := cmd.Wait()
		if err == nil {
			return nil
		}
		return err
	}
	return cmd.Process.Pid, waitFn, nil
}

func attachTracepoints(coll *ebpf.Collection) ([]link.Link, error) {
	tracepoints := map[string][2]string{
		"trace_openat":  {"syscalls", "sys_enter_openat"},
		"trace_connect": {"syscalls", "sys_enter_connect"},
		"trace_execve":  {"syscalls", "sys_enter_execve"},
		"trace_write":   {"syscalls", "sys_enter_write"},
	}

	var links []link.Link
	for progName, parts := range tracepoints {
		prog, ok := coll.Programs[progName]
		if !ok {
			closeAll(links)
			return nil, fmt.Errorf("bpf object missing program %s", progName)
		}
		l, err := link.Tracepoint(parts[0], parts[1], prog, nil)
		if err != nil {
			closeAll(links)
			return nil, fmt.Errorf("attach %s: %w", progName, err)
		}
		links = append(links, l)
	}
	return links, nil
}

func closeAll(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}

func decodeEvent(sample []byte) (Event, error) {
	var raw eventRecord
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return Event{}, err
	}

	event := Event{
		Timestamp: time.Unix(0, int64(raw.Timestamp)),
		PID:       int(raw.PID),
		Comm:      cString(raw.Comm[:]),
		Syscall:   cString(raw.Syscall[:]),
		Arg:       renderArg(cString(raw.Arg[:])),
	}
	return event, nil
}

func cString(buf []byte) string {
	if idx := bytes.IndexByte(buf, 0); idx >= 0 {
		buf = buf[:idx]
	}
	return string(bytes.TrimSpace(buf))
}

func renderArg(arg string) string {
	host, port, err := net.SplitHostPort(arg)
	if err == nil && host != "" {
		return net.JoinHostPort(host, port)
	}
	return strings.TrimSpace(arg)
}
