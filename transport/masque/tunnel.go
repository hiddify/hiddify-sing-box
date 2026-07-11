package masque

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
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
	logger       logger.ContextLogger
	options      TunnelOptions
	tunDevice    Device
	tunnelDevice TunnelDevice

	udpConn net.PacketConn
	tr      *http3.Transport
	ipConn  *connectip.Conn

	mtx sync.Mutex
}

func NewTunnel(ctx context.Context, logger logger.ContextLogger, options TunnelOptions) (*Tunnel, error) {
	deviceOptions := DeviceOptions{
		Context:    ctx,
		Logger:     logger,
		Handler:    options.Handler,
		UDPTimeout: options.UDPTimeout,
		MTU:        1280,
		Address:    options.Address,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "create MASQUE device")
	}
	return &Tunnel{
		ctx:          ctx,
		logger:       logger,
		options:      options,
		tunDevice:    tunDevice,
		tunnelDevice: NewNetstackAdapter(tunDevice),
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
		buf := make([]byte, 1280)
		for e.ctx.Err() == nil {
			n, err := e.tunnelDevice.ReadPacket(buf)
			if err != nil {
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
		buf := make([]byte, 1280)
		for e.ctx.Err() == nil {
			ipConn, err := e.getIpConn()
			if err != nil {
				return
			}
			n, err := ipConn.ReadPacket(buf, true)
			if err != nil {
				if e.options.UseHTTP2 || errors.As(err, new(*connectip.CloseError)) {
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
	e.logger.InfoContext(e.ctx, "Establishing MASQUE connection to ", e.options.Endpoint)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		e.logger.InfoContext(e.ctx, fmt.Errorf("Establishing MASQUE connection to %s", e.options.Endpoint))
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			e.ctx,
			e.options.Dialer,
			e.options.TLSConfig,
			DefaultQuicConfig(e.options.UDPKeepalivePeriod, e.options.UDPInitialPacketSize),
			"https://cloudflareaccess.com",
			e.options.Endpoint,
			e.options.UseHTTP2,
		)
		if err != nil {
			e.logger.ErrorContext(e.ctx, fmt.Errorf("Failed to connect tunnel: %v", err))
			timer.Reset(e.options.ReconnectDelay)
			select {
			case <-e.ctx.Done():
				return nil, err
			case <-timer.C:
			}
			continue
		}
		if rsp.StatusCode != 200 {
			e.logger.ErrorContext(e.ctx, fmt.Errorf("Tunnel connection failed: %s", rsp.Status))
			ipConn.Close()
			if udpConn != nil {
				udpConn.Close()
			}
			if tr != nil {
				tr.Close()
			}
			timer.Reset(e.options.ReconnectDelay)
			select {
			case <-e.ctx.Done():
				return nil, err
			case <-timer.C:
			}
			continue
		}
		e.udpConn = udpConn
		e.tr = tr
		e.ipConn = ipConn
		e.logger.InfoContext(e.ctx, "Connected to MASQUE server", e.options.Endpoint)
		return ipConn, nil
	}
}

func (e *Tunnel) closeIpConn(ipConn *connectip.Conn) bool {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if ipConn == e.ipConn {
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
