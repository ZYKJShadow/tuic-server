package server

import (
	"errors"
	"github.com/ZYKJShadow/tuic-protocol-go/address"
	"github.com/ZYKJShadow/tuic-protocol-go/options"
	"github.com/ZYKJShadow/tuic-protocol-go/protocol"
	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
	"io"
	"net"
	"time"
)

func (s *TUICServer) connect(stream quic.Stream, opts *options.ConnectOptions) error {
	conn, err := s.tcp(stream, opts.Addr)
	if err != nil {
		return err
	}

	_ = conn.SetDeadline(time.Now().Add(time.Second * time.Duration(s.Config.MaxIdleTime)))

	defer func() {
		_ = conn.Close()
	}()

	go func() {
		_ = s.relay(conn, stream)
	}()

	err = s.relay(stream, conn)
	if err != nil {
		logrus.Errorf("stream, conn error: %v", err)
	}

	return nil
}

func (s *TUICServer) relay(dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)

	for {
		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			var e *quic.StreamError
			if errors.As(err, &e) && e.ErrorCode == protocol.NormalClosed {
				return nil
			}

			return err
		}

		if n > 0 {
			n, err = dst.Write(buf[:n])
			if err != nil {
				return err
			}
		}
	}
}

func (s *TUICServer) tcp(stream quic.Stream, protocolAddr address.Address) (net.Conn, error) {
	rc, err := net.DialTimeout(protocol.NetworkTcp, protocolAddr.String(), time.Second*time.Duration(s.Config.MaxIdleTime))
	if err != nil {
		var p *socks5.Reply
		if protocolAddr.TypeCode() == address.AddrTypeDomain || protocolAddr.TypeCode() == address.AddrTypeIPv4 {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv6, net.IPv6zero, []byte{0x00, 0x00})
		}

		if _, err := p.WriteTo(stream); err != nil {
			return nil, err
		}

		return nil, err
	}

	a, parseAddr, port, err := socks5.ParseAddress(rc.LocalAddr().String())
	if err != nil {
		_ = rc.Close()

		var p *socks5.Reply
		if protocolAddr.TypeCode() == address.AddrTypeDomain || protocolAddr.TypeCode() == address.AddrTypeIPv4 {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv6, net.IPv6zero, []byte{0x00, 0x00})
		}

		if _, err := p.WriteTo(stream); err != nil {
			return nil, err
		}

		return nil, err
	}

	if a == socks5.ATYPDomain {
		parseAddr = parseAddr[1:]
	}

	p := socks5.NewReply(socks5.RepSuccess, a, parseAddr, port)
	if _, err = p.WriteTo(stream); err != nil {
		_ = rc.Close()
		return nil, err
	}

	return rc, nil
}
