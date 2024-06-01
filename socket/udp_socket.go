package socket

import (
	"net"
	"sync"
)

type UdpSocket struct {
	cache map[uint16]*net.UDPConn
	mode  string
	sync.Mutex
}

func NewUdpSocket(mode string) *UdpSocket {
	return &UdpSocket{
		cache: make(map[uint16]*net.UDPConn),
		mode:  mode,
	}
}

func (s *UdpSocket) Get(assocID uint16) *net.UDPConn {
	s.Lock()
	defer s.Unlock()

	return s.cache[assocID]
}

func (s *UdpSocket) Set(assocID uint16, conn *net.UDPConn) {
	s.Lock()
	defer s.Unlock()

	s.cache[assocID] = conn
}

func (s *UdpSocket) Del(assocID uint16) {
	s.Lock()
	defer s.Unlock()

	conn := s.cache[assocID]
	if conn == nil {
		return
	}

	_ = conn.Close()
	delete(s.cache, assocID)
}
