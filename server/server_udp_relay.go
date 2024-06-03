package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/ZYKJShadow/tuic-protocol-go/address"
	"github.com/ZYKJShadow/tuic-protocol-go/fragment"
	"github.com/ZYKJShadow/tuic-protocol-go/options"
	"github.com/ZYKJShadow/tuic-protocol-go/protocol"
	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"time"
	"tuic-server/socket"
)

func (s *TUICServer) packet(conn quic.Connection, stream io.Reader, opts *options.PacketOptions, mode string) error {
	data := make([]byte, opts.Size)
	_, err := io.ReadFull(stream, data)
	if err != nil {
		logrus.Errorf("Failed to read packet: %v", err)
		return err
	}

	switch mode {
	case protocol.UdpRelayModeQuic:
		return s.onHandleQUICPacket(conn, data, opts)
	case protocol.UdpRelayModeNative:
		return s.onHandleNativePacket(conn, data, opts)
	default:
		return errors.New("unknown udp relay mode")
	}
}

func (s *TUICServer) onHandleQUICPacket(conn quic.Connection, data []byte, opts *options.PacketOptions) error {
	if opts.FragTotal > 1 {
		return s.onHandleFragmentedPacket(conn, data, protocol.UdpRelayModeQuic, opts)
	}

	return s.udp(conn, opts.AssocID, data, protocol.UdpRelayModeQuic, opts.Addr)
}

func (s *TUICServer) onHandleNativePacket(conn quic.Connection, data []byte, opts *options.PacketOptions) error {
	if opts.FragTotal > 1 {
		return s.onHandleFragmentedPacket(conn, data, protocol.UdpRelayModeQuic, opts)
	}

	return s.udp(conn, opts.AssocID, data, protocol.UdpRelayModeQuic, opts.Addr)
}

func (s *TUICServer) onHandleFragmentedPacket(conn quic.Connection, data []byte, mode string, opts *options.PacketOptions) error {
	s.Lock()
	cache, ok := s.fragmentCacheMap[conn]
	if !ok {
		cache = fragment.NewFCache()
		s.fragmentCacheMap[conn] = cache
	}
	s.Unlock()

	data = cache.AddFragment(opts.AssocID, opts.FragID, opts.FragTotal, opts.Size, data)
	if data != nil {
		return s.udp(conn, opts.AssocID, data, mode, opts.Addr)
	}

	return nil
}

func (s *TUICServer) udp(conn quic.Connection, assocID uint16, data []byte, mode string, addr address.Address) error {
	udpSocket, ok := s.socketCacheMap[conn]
	if !ok {
		udpSocket = socket.NewUdpSocket(mode)

		s.Lock()
		s.socketCacheMap[conn] = udpSocket
		s.Unlock()
	}

	udp := udpSocket.Get(assocID)
	if udp == nil {
		remoteAddr, err := net.ResolveUDPAddr(protocol.NetworkUdp, addr.String())
		if err != nil {
			logrus.Errorf("udp resolve err:%v", err)
			return err
		}

		udp, err = net.DialUDP(protocol.NetworkUdp, nil, remoteAddr)
		if err != nil {
			logrus.Errorf("udp dial err:%v", err)
			return err
		}

		udpSocket.Set(assocID, udp)

		go s.onReadUdp(conn, udp, assocID, mode, addr)
	}

	_ = udp.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(s.MaxIdleTime)))
	_, err := udp.Write(data)
	if err != nil {
		logrus.Errorf("udp write err:%v", err)
		return err
	}

	return nil
}

func (s *TUICServer) onReadUdp(conn quic.Connection, udp *net.UDPConn, assocID uint16, mode string, remoteAddr address.Address) {
	data := make([]byte, s.MaxPacketSize)
	for {
		_ = udp.SetReadDeadline(time.Now().Add(time.Second * time.Duration(s.MaxIdleTime)))

		_, err := udp.Read(data)
		if err != nil {
			logrus.Errorf("udp read err:%v", err)
			break
		}

		opts := &options.PacketOptions{
			AssocID:   assocID,
			FragTotal: 1,
			FragID:    0,
			Size:      0,
			Addr:      remoteAddr,
		}

		opts.CalFragTotal(data, s.MaxPacketSize)

		switch {
		case opts.FragTotal > 1:
			s.onRelayFragmentedUdpSend(conn, data, mode, opts)
		default:
			s.onRelayUdpSend(conn, data, mode, opts)
		}
	}
}

func (s *TUICServer) onRelayFragmentedUdpSend(conn quic.Connection, data []byte, mode string, opts *options.PacketOptions) {
	// 确保即使 len(data) 不能被 opts.FragTotal 整除也能正确处理
	fragSize := (len(data) + int(opts.FragTotal) - 1) / int(opts.FragTotal)
	opts.Size = uint16(fragSize)

	for i := 0; i < int(opts.FragTotal); i++ {
		opts.FragID = uint8(i)
		start := i * fragSize
		end := start + fragSize
		if end > len(data) {
			end = len(data)
		}
		s.onRelayUdpSend(conn, data[start:end], mode, opts)
	}
}

func (s *TUICServer) onRelayUdpSend(conn quic.Connection, fragment []byte, mode string, opts *options.PacketOptions) {
	opts.Size = uint16(len(fragment))
	cmd := protocol.Command{
		Version: protocol.VersionMajor,
		Type:    protocol.CmdPacket,
		Options: opts,
	}

	cmdBytes, err := cmd.Marshal()
	if err != nil {
		logrus.Errorf("marshal packet failed: %v", err)
		return
	}

	cmdBytes = append(cmdBytes, fragment...)

	switch mode {
	case protocol.UdpRelayModeQuic:
		err = s.onSendUniStream(conn, cmdBytes)
	case protocol.UdpRelayModeNative:
		err = conn.SendDatagram(cmdBytes)
	default:
		logrus.Errorf("UDP relay mode %s not supported", mode)
		return
	}

	if err != nil {
		logrus.Errorf("send data failed: %v", err)
	}
}

func (s *TUICServer) onSendUniStream(conn quic.Connection, data []byte) error {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second*3))
	defer cancel()

	stream, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream failed: %v", err)
	}

	defer func() {
		_ = stream.Close()
	}()

	_, err = stream.Write(data)
	if err != nil {
		return fmt.Errorf("write data failed: %v", err)
	}

	return nil
}
