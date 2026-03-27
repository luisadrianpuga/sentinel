//go:build !linux

package sentinel

import "fmt"

func NewRunner(cfg Config, store *Store) (Runner, error) {
	return nil, fmt.Errorf("eBPF tracing requires Linux; current platform cannot run sentinel")
}
