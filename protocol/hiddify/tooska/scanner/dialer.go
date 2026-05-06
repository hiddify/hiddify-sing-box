package scanner

import (
	"context"
	"net"
	"strconv"
	"time"
)

func dialFast(ctx context.Context, ep Endpoint, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(ep.IP.String(), strconv.Itoa(ep.Port))
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1,
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetLinger(0)
	}
	return conn, nil
}

func armCancel(ctx context.Context, conn net.Conn) func() {
	if ctx.Done() == nil {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	return func() { close(stop) }
}
