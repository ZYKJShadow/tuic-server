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
	"sync"
	"time"
)

func (s *TUICServer) connect(stream quic.Stream, opts *options.ConnectOptions) error {
	conn, err := s.tcp(stream, opts.Addr)
	if err != nil {
		return err
	}

	_ = conn.SetDeadline(time.Now().Add(time.Second * time.Duration(s.MaxIdleTime)))

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		// 从stream中读取数据并写入conn
		_, err := io.Copy(conn, stream)
		if err != nil {
			// 发生错误，取消读取并通知客户端
			var e *quic.StreamError
			if errors.As(err, &e) && e.ErrorCode == protocol.NormalClosed {
				stream.CancelRead(protocol.NormalClosed)
				return
			}

			if errors.Is(err, net.ErrClosed) {
				stream.CancelRead(protocol.NormalClosed)
				return
			}

			logrus.Errorf("Failed to copy from stream to conn: %v", err)
			stream.CancelRead(protocol.ServerCanceled)

			return
		}

		// stream数据接受完毕，正常关闭tcp连接
		_ = conn.Close()
	}()

	go func() {
		defer wg.Done()
		// 从conn中读取数据并写入stream
		_, err := io.Copy(stream, conn)
		if err != nil {
			_ = conn.Close()

			if errors.Is(err, net.ErrClosed) {
				return
			}

			logrus.Errorf("Failed to copy from conn to stream: %v", err)

			return
		}

		_ = stream.Close()
	}()

	wg.Wait()

	return nil
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

	_ = rc.SetReadDeadline(time.Now().Add(time.Second * time.Duration(s.Config.MaxIdleTime)))
	_ = rc.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(s.Config.MaxIdleTime)))

	return rc, nil
}
