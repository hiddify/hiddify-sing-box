package masque

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type TunnelDevice interface {
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
}

type Tunnel struct {
	ctx          context.Context
	cancel       context.CancelFunc // ends the loops and a connect in progress on close
	logger       logger.ContextLogger
	options      TunnelOptions
	tunDevice    Device
	tunnelDevice TunnelDevice

	udpConn net.PacketConn
	tr      *http3.Transport
	ipConn  *connectip.Conn

	mtx sync.Mutex

	// h_connect.go
	endpointAccess sync.Mutex
	failures       map[bool]int // consecutive failed connects, per HTTP/2
	autoAccess     sync.Mutex
	http2Until     time.Time
	http2Step      int
	activeHTTP2    atomic.Bool // the current connection is HTTP/2
	connected      atomic.Bool // H: a connection to the server is up; read without the lock, which a connect holds
}

// IsConnected reports whether the tunnel has a connection to the server. //H
func (e *Tunnel) IsConnected() bool {
	return e.connected.Load()
}

func NewTunnel(ctx context.Context, logger logger.ContextLogger, options TunnelOptions) (*Tunnel, error) {
	if options.MTU == 0 { //H
		options.MTU = DefaultMTU //H
	} //H
	if options.MTU < DefaultMTU || options.MTU > 9000 { //H
		return nil, E.New("MASQUE mtu must be between ", DefaultMTU, " and 9000") //H
	} //H
	deviceOptions := DeviceOptions{
		Context:    ctx,
		Logger:     logger,
		Handler:    options.Handler,
		UDPTimeout: options.UDPTimeout,
		MTU:        options.MTU, //H
		Address:    options.Address,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "create MASQUE device")
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Tunnel{
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		options:      options,
		tunDevice:    tunDevice,
		tunnelDevice: NewNetstackAdapter(tunDevice),
		failures:     make(map[bool]int),
	}, nil
}

func (e *Tunnel) Start(resolve bool) error {
	if resolve {
		err := e.tunDevice.Start()
		if err != nil {
			return err
		}
		go e.maintainTunnel()
	}
	return nil
}

func (e *Tunnel) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Tunnel) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Tunnel) Close() error {
	// cancel first: a connect in progress holds the lock until the context ends
	e.cancel()
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if e.ipConn != nil {
		e.ipConn.Close()
		if e.udpConn != nil {
			e.udpConn.Close()
		}
		if e.tr != nil {
			e.tr.Close()
		}
		e.ipConn = nil
	}
	return e.tunDevice.Close()
}

func (e *Tunnel) maintainTunnel() {
	go func() {
		buf := make([]byte, e.options.MTU) //H: a packet as large as the MTU, not cut at 1280
		for e.ctx.Err() == nil {
			n, err := e.tunnelDevice.ReadPacket(buf)
			if err != nil {
				if e.ctx.Err() != nil {
					// closed: the device read fails at once, so going on would spin
					return
				}
				e.logger.ErrorContext(e.ctx, fmt.Errorf("failed to read from TUN device: %v", err))
				continue
			}
			ipConn, err := e.getIpConn()
			if err != nil {
				return
			}
			icmp, err := ipConn.WritePacket(buf[:n])
			if err != nil {
				if errors.As(err, new(*connectip.CloseError)) {
					if ok := e.closeIpConn(ipConn); ok {
						e.logger.ErrorContext(e.ctx, fmt.Errorf("connection closed while writing to IP connection: %w", err))
					}
					continue
				}
				e.logger.ErrorContext(e.ctx, fmt.Errorf("Error writing to IP connection: %v, continuing...", err))
				continue
			}
			if len(icmp) > 0 {
				if err := e.tunnelDevice.WritePacket(icmp); err != nil {
					if errors.As(err, new(*connectip.CloseError)) {
						e.logger.ErrorContext(e.ctx, fmt.Errorf("connection closed while writing ICMP to TUN device: %v", err))
						continue
					}
					e.logger.ErrorContext(e.ctx, fmt.Errorf("Error writing ICMP to TUN device: %v, continuing...", err))
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, e.options.MTU) //H: a packet as large as the MTU, not cut at 1280
		for e.ctx.Err() == nil {
			ipConn, err := e.getIpConn()
			if err != nil {
				return
			}
			n, err := ipConn.ReadPacket(buf, true)
			if err != nil {
				if e.activeHTTP2.Load() || errors.As(err, new(*connectip.CloseError)) {
					if ok := e.closeIpConn(ipConn); ok {
						e.logger.ErrorContext(e.ctx, fmt.Errorf("connection closed while reading from IP connection: %v", err))
					}
					continue
				}
				e.logger.ErrorContext(e.ctx, fmt.Errorf("Error reading from IP connection: %v, continuine...", err))
				continue
			}
			if err := e.tunnelDevice.WritePacket(buf[:n]); err != nil {
				continue
			}
		}
	}()
	<-e.ctx.Done()
}

func (e *Tunnel) getIpConn() (*connectip.Conn, error) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if e.ctx.Err() != nil {
		return nil, e.ctx.Err()
	}
	if e.ipConn != nil {
		return e.ipConn, nil
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		conn, err := e.connect()
		if err == nil {
			e.udpConn = conn.udpConn
			e.tr = conn.tr
			e.ipConn = conn.ipConn
			e.activeHTTP2.Store(conn.http2)
			e.connected.Store(true) //H
			e.logger.InfoContext(e.ctx, "connected to MASQUE server over ", map[bool]string{true: "HTTP/2", false: "HTTP/3"}[conn.http2])
			return conn.ipConn, nil
		}
		if e.ctx.Err() != nil {
			return nil, e.ctx.Err()
		}
		e.logger.ErrorContext(e.ctx, E.Cause(err, "connect MASQUE tunnel"))
		timer.Reset(e.options.ReconnectDelay)
		select {
		case <-e.ctx.Done():
			return nil, e.ctx.Err()
		case <-timer.C:
		}
	}
}

func (e *Tunnel) closeIpConn(ipConn *connectip.Conn) bool {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if ipConn == e.ipConn {
		e.connected.Store(false) //H
		e.ipConn.Close()
		if e.udpConn != nil {
			e.udpConn.Close()
		}
		if e.tr != nil {
			e.tr.Close()
		}
		e.ipConn = nil
		return true
	}
	return false
}
