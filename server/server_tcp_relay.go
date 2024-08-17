package server

import (
	"github.com/ZYKJShadow/tuic-protocol-go/address"
	"github.com/ZYKJShadow/tuic-protocol-go/options"
	"github.com/ZYKJShadow/tuic-protocol-go/protocol"
	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
	"io"
	"net"
	"sync"
	"time"
)

func (s *TUICServer) connect(stream quic.Stream, opts *options.ConnectOptions) error {
	conn, err := s.tcp(stream, opts.Addr)
	if err != nil {
		return err
	}

	defer func() {
		_ = conn.Close()
		_ = stream.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer stream.CancelRead(protocol.NormalClosed)
		s.relay(conn, stream)
		logrus.Infof("streamID:%v Cancel Read", stream.StreamID())
	}()

	go func() {
		defer wg.Done()
		defer stream.CancelWrite(protocol.NormalClosed)
		s.relay(stream, conn)
		logrus.Infof("streamID:%v Cancel Write", stream.StreamID())
	}()

	wg.Wait()

	return nil
}

func (s *TUICServer) relay(dst io.Writer, src io.Reader) {
	var wg sync.WaitGroup
	buf := make(chan []byte, 32*1024)

	wg.Add(2)

	go func() {
		defer wg.Done()
		defer close(buf)
		for {
			b := make([]byte, 32*1024)
			n, err := src.Read(b)
			if err != nil && err != io.EOF {
				logrus.Errorf("Failed to Read conn err: %v", err)
				return
			}

			if err == io.EOF {
				return
			}

			if n <= 0 {
				return
			}

			buf <- b[:n]
		}
	}()

	go func() {
		defer wg.Done()
		for {
			b, ok := <-buf
			_, err := dst.Write(b)
			if err != nil {
				logrus.Errorf("Failed to write buf to stream: %v", err)
				return
			}

			if !ok {
				return
			}
		}
	}()

	wg.Wait()
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

	_ = rc.SetDeadline(time.Now().Add(time.Second * 5))

	return rc, nil
}
