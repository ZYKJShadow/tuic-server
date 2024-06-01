package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/ZYKJShadow/tuic-protocol-go/auth"
	"github.com/ZYKJShadow/tuic-protocol-go/fragment"
	"github.com/ZYKJShadow/tuic-protocol-go/options"
	"github.com/ZYKJShadow/tuic-protocol-go/protocol"
	"github.com/ZYKJShadow/tuic-protocol-go/utils"
	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"tuic-server/authenticate"
	"tuic-server/config"
	"tuic-server/socket"
)

type TUICServer struct {
	listener         *quic.Listener
	authenticator    *authenticate.Authenticate
	fragmentCacheMap map[quic.Connection]*fragment.FCache
	socketCacheMap   map[quic.Connection]*socket.UdpSocket
	*config.Config
	sync.RWMutex
}

type Session struct {
	authMap map[string]bool
}

func NewTUICServer(cfg *config.Config) (*TUICServer, error) {
	certs, err := utils.LoadCerts(cfg.CertPath)
	if err != nil {
		logrus.Errorf("load certs failed: %v", err)
		return nil, err
	}

	privateKey, err := utils.LoadPrivateKey(cfg.PrivateKey)
	if err != nil {
		logrus.Errorf("load private key failed: %v", err)
		return nil, err
	}

	tlsConfig := &tls.Config{
		NextProtos:         cfg.ALPN,
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		ClientAuth: tls.NoClientCert,
		MinVersion: tls.VersionTLS13,
		RootCAs:    x509.NewCertPool(),
	}

	if certs != nil && privateKey != nil {
		tlsConfig.Certificates = []tls.Certificate{
			{
				Certificate: certs,
				PrivateKey:  privateKey,
			},
		}

		tlsConfig.InsecureSkipVerify = false
	}

	//goland:noinspection SpellCheckingInspection
	quicConfig := &quic.Config{
		Versions:                       []quic.Version{quic.Version2},
		HandshakeIdleTimeout:           time.Duration(cfg.AuthTimeout) * time.Second,
		MaxIdleTimeout:                 time.Duration(cfg.MaxIdleTime) * time.Second,
		Allow0RTT:                      cfg.ZeroRTTHandshake,
		InitialStreamReceiveWindow:     8 * 1024 * 1024 * 2,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024 * 2,
		KeepAlivePeriod:                time.Second * 3,
		EnableDatagrams:                true,
		TokenStore:                     auth.NewAuthenticated(quic.NewLRUTokenStore(10, 4), make(chan string, 100), make(chan string, 100)),
	}

	conn, err := net.ListenPacket(protocol.NetworkUdp, cfg.Server)
	if err != nil {
		logrus.Errorf("listen udp failed: %v", err)
		return nil, err
	}

	listener, err := quic.Listen(conn, tlsConfig, quicConfig)
	if err != nil {
		logrus.Errorf("quic listen failed: %v", err)
		return nil, err
	}

	logrus.Infof("server listen on %s", cfg.Server)

	return &TUICServer{
		listener:         listener,
		Config:           cfg,
		authenticator:    authenticate.NewAuthenticate(cfg.AuthTimeout),
		fragmentCacheMap: make(map[quic.Connection]*fragment.FCache),
		socketCacheMap:   make(map[quic.Connection]*socket.UdpSocket),
	}, nil
}

func (s *TUICServer) Start() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			logrus.Errorf("accept connection failed: %v", err)
			continue
		}

		logrus.Infof("accept connection from %s", conn.RemoteAddr())

		go s.onConnection(conn)
	}
}

func (s *TUICServer) onConnection(conn quic.Connection) {
	defer func() {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "connection closed")
	}()

	var g errgroup.Group
	g.Go(func() error {
		for {
			stream, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				logrus.Errorf("Failed to accept uni stream: %v", err)
				return err
			}

			g.Go(func() error {
				s.onHandleUniStream(conn, stream)
				return nil
			})
		}
	})

	g.Go(func() error {
		for {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				logrus.Errorf("Failed to accept stream: %v", err)
				return err
			}

			_ = stream.SetDeadline(time.Now().Add(time.Second * time.Duration(s.MaxIdleTime)))

			g.Go(func() error {
				s.onHandleStream(conn, stream)
				return nil
			})
		}
	})

	g.Go(func() error {
		for {
			datagram, err := conn.ReceiveDatagram(context.Background())
			if err != nil {
				logrus.Errorf("Failed to receive datagram: %v", err)
				return err
			}

			g.Go(func() error {
				s.onHandleDatagram(conn, datagram)
				return nil
			})
		}
	})

	err := g.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		logrus.Errorf("Error in onConnection: %v", err)
	}
}

func (s *TUICServer) onHandleDatagram(conn quic.Connection, datagram []byte) {
	reader := bytes.NewReader(datagram)

	var cmd protocol.Command
	err := cmd.Unmarshal(reader)
	if err != nil {
		logrus.Errorf("Failed to read command: %v", err)
		return
	}

	switch cmd.Type {
	case protocol.CmdAuthenticate, protocol.CmdConnect, protocol.CmdDissociate:
		err = errors.New("bad command datagram")
	case protocol.CmdHeartbeat:

	case protocol.CmdPacket:
		err = s.packet(conn, reader, cmd.Options.(*options.PacketOptions), protocol.UdpRelayModeNative)
	default:
		err = errors.New("bad command datagram")
	}

	if err != nil {
		logrus.Errorf("onHandleDatagram err: %v", err)
	}
}

func (s *TUICServer) onHandleUniStream(conn quic.Connection, stream quic.ReceiveStream) {
	var cmd protocol.Command
	err := cmd.Unmarshal(stream)
	if err != nil {
		logrus.Errorf("Failed to read command: %v", err)
		return
	}

	if cmd.Type == protocol.CmdAuthenticate {
		err = s.authenticate(conn, cmd.Options.(*options.AuthenticateOptions))
		if err != nil {
			logrus.Errorf("Failed to handle authenticate: %v", err)
		}

		return
	}

	// 等待认证完成再处理其他数据包
	if !s.authenticator.GetAuth(conn) {
		err = s.authenticator.WaitForAuth(conn)
		if err != nil {
			logrus.Errorf("Failed to wait for auth: %v", err)
			return
		}
	}

	switch cmd.Type {
	case protocol.CmdPacket:
		err = s.packet(conn, stream, cmd.Options.(*options.PacketOptions), protocol.UdpRelayModeQuic)
	case protocol.CmdDissociate:
		err = s.dissociate(conn, stream)
	}

	if err != nil {
		logrus.Errorf("Failed to handle packet: %v", err)
	}
}

func (s *TUICServer) onHandleStream(conn quic.Connection, stream quic.Stream) {
	var cmd protocol.Command
	err := cmd.Unmarshal(stream)
	if err != nil {
		logrus.Errorf("Failed to read command: %v", err)
		return
	}

	// 等待认证完成再处理其他数据包
	if !s.authenticator.GetAuth(conn) {
		err = s.authenticator.WaitForAuth(conn)
		if err != nil {
			s.onCloseStream(stream)
			logrus.Errorf("Failed to wait for auth: %v", err)
			return
		}
	}

	defer s.onCloseStream(stream)

	switch cmd.Type {
	case protocol.CmdAuthenticate:
		err = errors.New("bad command authenticate")
	case protocol.CmdConnect:
		err = s.connect(stream, cmd.Options.(*options.ConnectOptions))
	case protocol.CmdPacket:
		err = errors.New("bad command packet")
	case protocol.CmdDissociate:
		err = errors.New("bad command dissociate")
	case protocol.CmdHeartbeat:
		err = errors.New("bad command heartbeat")
	default:
		err = errors.New("unknown command type")
	}

	if err != nil && err != io.EOF && !strings.Contains(err.Error(), "i/o timeout") {
		var streamErr *quic.StreamError
		if errors.As(err, &streamErr) && streamErr.ErrorCode == protocol.NormalClosed {
			return
		}

		logrus.Errorf("onHandleStream err:%v", err)
	}
}

func (s *TUICServer) authenticate(conn quic.Connection, opts *options.AuthenticateOptions) error {
	// 使用opts.UUID和opts.Token进行身份验证
	tlsConn := conn.ConnectionState().TLS
	label := string(opts.UUID)

	// 从已经建立的TLS连接中获得token
	token, err := tlsConn.ExportKeyingMaterial(label, []byte(s.Password), 32)
	if err != nil {
		logrus.Errorf("Failed to export keying material: %v", err)
		return nil
	}

	if !bytes.Equal(token, opts.Token) {
		return errors.New("invalid token")
	}

	// 身份验证通过，保存UUID
	s.authenticator.SetAuth(conn, true)

	return nil
}

func (s *TUICServer) dissociate(conn quic.Connection, stream io.Reader) error {
	// 反序列化options,关闭对应的UDP会话
	var opts options.DissociateOptions
	b := make([]byte, 2)
	_, err := io.ReadFull(stream, b)
	if err != nil {
		logrus.Errorf("dissociate io.ReadFull err:%v", err)
		return err
	}

	err = opts.Unmarshal(b)
	if err != nil {
		return err
	}

	cache := s.fragmentCacheMap[conn]
	if cache != nil {
		cache.DelFragment(opts.AssocID)
	}

	udpSocket := s.socketCacheMap[conn]
	if udpSocket != nil {
		udpSocket.Del(opts.AssocID)
	}

	return nil
}

func (s *TUICServer) onCloseStream(stream quic.Stream) {
	stream.CancelRead(protocol.NormalClosed)
	stream.CancelWrite(protocol.NormalClosed)
}
