package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	ac "github.com/metacubex/mihomo/transport/anyconnect"

	wireguard "github.com/metacubex/sing-wireguard"
)

type anyConnectSession struct {
	client        acClient
	device        wireguard.Device
	configuration ac.NetworkConfig
	cancel        context.CancelFunc

	stopOnce sync.Once
	wait     sync.WaitGroup
	done     chan struct{}
	errLock  sync.Mutex
	stopErr  error
}

type acClient interface {
	ReadPacket(ctx context.Context) ([]byte, error)
	WritePacket(packet []byte) error
	Close() error
}

func newAnyConnectSession(runCtx context.Context, handshakeCtx context.Context, config ac.Config, dialer C.Dialer, authProvider ac.AuthProvider, name string) (*anyConnectSession, error) {
	client, err := ac.NewClient(runCtx, config, dialer, authProvider)
	if err != nil {
		return nil, fmt.Errorf("create AnyConnect client: %w", err)
	}
	if err := client.Start(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("start AnyConnect client: %w", err)
	}
	configuration, err := client.WaitReady(handshakeCtx)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect AnyConnect server: %w", err)
	}
	if len(configuration.Addresses) == 0 {
		_ = client.Close()
		return nil, errors.New("AnyConnect server did not assign an IPv4 address")
	}
	mtu := configuration.MTU
	if mtu == 0 {
		mtu = 1400
	}
	device, err := wireguard.NewStackDevice(configuration.Addresses, mtu)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("create AnyConnect stack device: %w", err)
	}
	if err := device.Start(); err != nil {
		_ = device.Close()
		_ = client.Close()
		return nil, fmt.Errorf("start AnyConnect stack device: %w", err)
	}
	sessionCtx, cancel := context.WithCancel(runCtx)
	session := &anyConnectSession{
		client:        client,
		device:        device,
		configuration: configuration,
		cancel:        cancel,
		done:          make(chan struct{}),
	}
	session.wait.Add(2)
	go session.stackToTunnel(sessionCtx, name)
	go session.tunnelToStack(sessionCtx, name)
	go func() {
		session.wait.Wait()
		close(session.done)
	}()
	log.Debugln("[AnyConnect](%s) tunnel ready: addresses=%v mtu=%d transport=%s", name, configuration.Addresses, mtu, client.ActiveTransport())
	return session, nil
}

func (s *anyConnectSession) stackToTunnel(ctx context.Context, name string) {
	defer s.wait.Done()
	buffer := make([]byte, 64*1024)
	buffers := [][]byte{buffer}
	sizes := []int{0}
	for ctx.Err() == nil {
		_, err := s.device.Read(buffers, sizes, 0)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
				log.Warnln("[AnyConnect](%s) stack read failed: %v", name, err)
			}
			s.stop(err)
			return
		}
		if err := s.client.WritePacket(buffer[:sizes[0]]); err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				log.Warnln("[AnyConnect](%s) tunnel write failed: %v", name, err)
			}
			s.stop(err)
			return
		}
	}
}

func (s *anyConnectSession) tunnelToStack(ctx context.Context, name string) {
	defer s.wait.Done()
	for ctx.Err() == nil {
		packet, err := s.client.ReadPacket(ctx)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				log.Warnln("[AnyConnect](%s) tunnel read failed: %v", name, err)
			}
			s.stop(err)
			return
		}
		if _, err := s.device.Write([][]byte{packet}, 0); err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
				log.Warnln("[AnyConnect](%s) stack write failed: %v", name, err)
			}
			s.stop(err)
			return
		}
	}
}

func (s *anyConnectSession) stop(err error) {
	s.stopOnce.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		s.errLock.Lock()
		s.stopErr = err
		s.errLock.Unlock()
		s.cancel()
		_ = s.client.Close()
		_ = s.device.Close()
	})
}

func (s *anyConnectSession) err() error {
	s.errLock.Lock()
	defer s.errLock.Unlock()
	if s.stopErr == nil {
		return net.ErrClosed
	}
	return s.stopErr
}

func (s *anyConnectSession) close() error {
	s.stop(net.ErrClosed)
	<-s.done
	return nil
}
