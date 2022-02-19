//go:build !windows

package gkpxc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

var lookupPaths = []string{
	os.Getenv("XDG_RUNTIME_DIR"),
	os.Getenv("TMPDIR"),
	"/tmp",
}

func connect(ctx context.Context) (net.Conn, error) {
	var lastErr error
	var socketPath string

lookup:
	for _, dir := range lookupPaths {
		socketPath = filepath.Join(dir, SocketName)
		_, lastErr = os.Stat(socketPath)
		switch {
		case errors.Is(lastErr, nil):
			break lookup
		case errors.Is(lastErr, os.ErrNotExist):
		default:
			return nil, fmt.Errorf("socket lookup: %s", lastErr)
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("socket lookup: %s", lastErr)
	}

	return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
}
