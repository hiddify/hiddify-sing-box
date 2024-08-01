package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
)

type ClientSessionCache struct {
	cache map[string]*tls.ClientSessionState
	mutex sync.Mutex
}

func NewClientSessionCache() *ClientSessionCache {
	return &ClientSessionCache{
		cache: make(map[string]*tls.ClientSessionState),
	}
}

func (c *ClientSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	_ = sessionKey // To stop linter from complaining
	sessionKey = "unused"
	c.mutex.Lock()
	session, ok := c.cache[sessionKey]
	c.mutex.Unlock()
	return session, ok
}

func (c *ClientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	_ = sessionKey
	sessionKey = "unused"
	c.mutex.Lock()
	if cs == nil {
		delete(c.cache, sessionKey)
	} else {
		c.cache[sessionKey] = cs
	}
	c.mutex.Unlock()
}

type STDClientConfig struct {
	config              *tls.Config
	obSessionTicketOpts *option.OutboundSessionTicketOptions
}

func (s *STDClientConfig) ServerName() string {
	return s.config.ServerName
}

func (s *STDClientConfig) SetServerName(serverName string) {
	s.config.ServerName = serverName
}

func (s *STDClientConfig) NextProtos() []string {
	return s.config.NextProtos
}

func (s *STDClientConfig) SetNextProtos(nextProto []string) {
	s.config.NextProtos = nextProto
}

func (s *STDClientConfig) Config() (*STDConfig, error) {
	return s.config, nil
}

func (s *STDClientConfig) Client(conn net.Conn) (Conn, error) {
	tlsConfig := s.config.Clone()
	if s.obSessionTicketOpts != nil && s.obSessionTicketOpts.Enabled && tlsConfig.ServerName == s.obSessionTicketOpts.RealDomain {
		s.obSessionTicketOpts.Mutex.Lock()
		t := time.Now().Unix()
		if (t - s.obSessionTicketOpts.LastUpdate) >= s.obSessionTicketOpts.TimeoutSecs {
			s.obSessionTicketOpts.SessionState = NewClientSessionCache()
			tlsConfig.ClientSessionCache = s.obSessionTicketOpts.SessionState
			tlsConfig.SessionTicketsDisabled = false
			client := tls.Client(conn, tlsConfig)
			err := client.Handshake()
			if err != nil {
				client.Close()
				s.obSessionTicketOpts.Mutex.Unlock()
				return nil, E.New(fmt.Sprintf("Failed to obtain session ticket: %v", err))
			}
			_, err = client.Write([]byte{1, 2, 3})
			if err != nil {
				client.Close()
				s.obSessionTicketOpts.Mutex.Unlock()
				return nil, E.New(fmt.Sprintf("Failed to obtain session ticket: %v", err))
			}
			_, err = io.ReadAll(client)
			if err != nil {
				client.Close()
				s.obSessionTicketOpts.Mutex.Unlock()
				return nil, E.New(fmt.Sprintf("Failed to obtain session ticket: %v", err))
			}
			client.Close()
			s.obSessionTicketOpts.LastUpdate = t
			s.obSessionTicketOpts.Mutex.Unlock()
			return nil, E.New("Got the session ticket, attempting to connect...")
		}
		s.obSessionTicketOpts.Mutex.Unlock()
		tlsConfig.InsecureSkipVerify = true // We are using custom verification, this is fine
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			verifyOptions := x509.VerifyOptions{
				DNSName:       s.config.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range state.PeerCertificates[1:] {
				verifyOptions.Intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(verifyOptions)
			return err
		}
		tlsConfig.SessionTicketsDisabled = false
		tlsConfig.ClientSessionCache = s.obSessionTicketOpts.SessionState
		tlsConfig.ServerName = s.obSessionTicketOpts.FakeDomain
		//tlsConfig.ServerName = s.obSessionTicketOpts.RealDomain
		//tlsConfig.ServerName = ""
	}
	return tls.Client(conn, tlsConfig), nil
}

func (s *STDClientConfig) Clone() Config {
	return &STDClientConfig{s.config.Clone(), s.obSessionTicketOpts}
}

func NewSTDClient(ctx context.Context, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	var serverName string
	if options.ServerName != "" {
		serverName = options.ServerName
	} else if serverAddress != "" {
		if _, err := netip.ParseAddr(serverName); err != nil {
			serverName = serverAddress
		}
	}
	if serverName == "" && !options.Insecure {
		return nil, E.New("missing server_name or insecure=true")
	}

	var tlsConfig tls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	if options.DisableSNI {
		tlsConfig.ServerName = "127.0.0.1"
	} else {
		if options.TLSTricks != nil && options.TLSTricks.MixedCaseSNI {
			tlsConfig.ServerName = randomizeCase(tlsConfig.ServerName)
		} else {
			tlsConfig.ServerName = serverName
		}
	}
	if options.Insecure {
		tlsConfig.InsecureSkipVerify = options.Insecure
	} else if options.DisableSNI {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			verifyOptions := x509.VerifyOptions{
				DNSName:       serverName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range state.PeerCertificates[1:] {
				verifyOptions.Intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(verifyOptions)
			return err
		}
	}
	if len(options.ALPN) > 0 {
		tlsConfig.NextProtos = options.ALPN
	}
	if options.MinVersion != "" {
		minVersion, err := ParseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		tlsConfig.MinVersion = minVersion
	}
	if options.MaxVersion != "" {
		maxVersion, err := ParseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		tlsConfig.MaxVersion = maxVersion
	}
	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(options.Certificate) > 0 {
		certificate = []byte(strings.Join(options.Certificate, "\n"))
	} else if options.CertificatePath != "" {
		content, err := os.ReadFile(options.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, E.New("failed to parse certificate:\n\n", certificate)
		}
		tlsConfig.RootCAs = certPool
	}
	return &STDClientConfig{&tlsConfig, options.SessionTicket}, nil
}
