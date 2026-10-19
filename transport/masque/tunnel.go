package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type Tunnel struct {
	ctx     context.Context
	logger  logger.ContextLogger
	options TunnelOptions
	device  Device

	closer io.Closer
	ipConn IpConn

	mtx sync.Mutex
}

func NewTunnel(ctx context.Context, logger logger.ContextLogger, options TunnelOptions) (*Tunnel, error) {
	deviceOptions := DeviceOptions{
		Context:        ctx,
		Logger:         logger,
		System:         options.System,
		UDPTimeout:     options.UDPTimeout,
		CreateDialer:   options.CreateDialer,
		Name:           options.Name,
		MTU:            1280,
		Address:        options.Address,
		AllowedAddress: options.AllowedAddress,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "create MASQUE device")
	}
	return &Tunnel{
		ctx:     ctx,
		logger:  logger,
		options: options,
		device:  tunDevice,
	}, nil
}

func (e *Tunnel) Start(resolve bool) error {
	if resolve {
		err := e.device.Start()
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
	return e.device.DialContext(ctx, network, destination)
}

func (e *Tunnel) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.device.ListenPacket(ctx, destination)
}

func (e *Tunnel) Close() error {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if e.ipConn != nil {
		e.ipConn.Close()
		if e.closer != nil {
			e.closer.Close()
		}
		e.ipConn = nil
		e.closer = nil
	}
	return e.device.Close()
}

func (e *Tunnel) maintainTunnel() {
	go func() {
		bufs := make([][]byte, 1)
		bufs[0] = make([]byte, 1280)
		sizes := make([]int, 1)
		for e.ctx.Err() == nil {
			_, err := e.device.Read(bufs, sizes, 0)
			if err != nil {
				e.logger.ErrorContext(e.ctx, fmt.Errorf("failed to read from TUN device: %v", err))
				continue
			}
			packet := bufs[0][:sizes[0]]
			if len(packet) > 0 {
				switch packet[0] >> 4 {
				case 4:
					if len(packet) >= 9 && packet[8] <= 1 {
						continue
					}
				case 6:
					if len(packet) >= 8 && packet[7] <= 1 {
						continue
					}
				}
			}
			ipConn, err := e.getIpConn()
			if err != nil {
				return
			}
			icmp, err := ipConn.WritePacket(packet)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					if ok := e.closeIpConn(ipConn); ok {
						e.logger.ErrorContext(e.ctx, fmt.Errorf("connection closed while writing to IP connection: %w", err))
					}
					continue
				}
				e.logger.ErrorContext(e.ctx, fmt.Errorf("Error writing to IP connection: %v, continuing...", err))
				continue
			}
			if len(icmp) > 0 {
				if _, err := e.device.Write([][]byte{icmp}, 0); err != nil {
					if errors.Is(err, net.ErrClosed) {
						e.logger.ErrorContext(e.ctx, fmt.Errorf("connection closed while writing ICMP to TUN device: %v", err))
						continue
					}
					e.logger.ErrorContext(e.ctx, fmt.Errorf("Error writing ICMP to TUN device: %v, continuing...", err))
				}
			}
		}
	}()
	go func() {
		for e.ctx.Err() == nil {
			ipConn, err := e.getIpConn()
			if err != nil {
				return
			}
			packet, err := ipConn.ReadPacket()
			if err != nil {
				if e.options.UseHTTP2 || errors.Is(err, net.ErrClosed) {
					if ok := e.closeIpConn(ipConn); ok {
						e.logger.ErrorContext(e.ctx, fmt.Errorf("connection closed while reading from IP connection: %v", err))
					}
					continue
				}
				e.logger.ErrorContext(e.ctx, fmt.Errorf("Error reading from IP connection: %v, continuine...", err))
				continue
			}
			if _, err := e.device.Write([][]byte{packet}, 0); err != nil {
				continue
			}
		}
	}()
	<-e.ctx.Done()
}

func (e *Tunnel) getIpConn() (IpConn, error) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if e.ctx.Err() != nil {
		return nil, e.ctx.Err()
	}
	if e.ipConn != nil {
		return e.ipConn, nil
	}
	e.logger.NoticeContext(e.ctx, "Establishing MASQUE connection to ", e.options.Endpoint)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		e.logger.NoticeContext(e.ctx, fmt.Errorf("Establishing MASQUE connection to %s", e.options.Endpoint))
		var connectCtx context.Context
		var cancel context.CancelFunc
		if e.options.HandshakeTimeout > 0 {
			connectCtx, cancel = context.WithTimeout(e.ctx, e.options.HandshakeTimeout)
		} else {
			connectCtx, cancel = context.WithCancel(e.ctx)
		}
		closer, ipConn, rsp, err := ConnectTunnel(
			connectCtx,
			e.options.Dialer,
			e.options.TLSConfig,
			DefaultQuicConfig(e.options.UDPKeepalivePeriod, e.options.UDPInitialPacketSize),
			"https://cloudflareaccess.com",
			e.options.Endpoint,
			e.options.UseHTTP2,
			e.options.CongestionControl,
		)
		cancel()
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
			if closer != nil {
				closer.Close()
			}
			timer.Reset(e.options.ReconnectDelay)
			select {
			case <-e.ctx.Done():
				return nil, err
			case <-timer.C:
			}
			continue
		}
		e.closer = closer
		e.ipConn = ipConn
		e.logger.NoticeContext(e.ctx, "Connected to MASQUE server ", e.options.Endpoint)
		return ipConn, nil
	}
}

func (e *Tunnel) closeIpConn(ipConn IpConn) bool {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if ipConn == e.ipConn {
		e.ipConn.Close()
		if e.closer != nil {
			e.closer.Close()
		}
		e.ipConn = nil
		e.closer = nil
		return true
	}
	return false
}
