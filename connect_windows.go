package gkpxc

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/Microsoft/go-winio"
)

func connect(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx,
		fmt.Sprintf(`\\.\pipe\%s_%s`, SocketName, os.Getenv("USERNAME")),
	)
}
