package authenticate

import (
	"errors"
	"github.com/quic-go/quic-go"
	"sync"
	"time"
)

type Authenticate struct {
	authConnMap  map[quic.Connection]bool
	authChannels map[quic.Connection]chan struct{}
	authTimeout  time.Duration
	sync.RWMutex
}

func NewAuthenticate(authTimeout int) *Authenticate {
	return &Authenticate{
		authConnMap:  make(map[quic.Connection]bool, 100),
		authChannels: make(map[quic.Connection]chan struct{}, 100),
		authTimeout:  time.Duration(authTimeout) * time.Second,
	}
}

func (a *Authenticate) SetAuth(conn quic.Connection, auth bool) {
	a.Lock()
	defer a.Unlock()
	a.authConnMap[conn] = auth
}

func (a *Authenticate) GetAuth(conn quic.Connection) bool {
	a.RLock()
	defer a.RUnlock()
	return a.authConnMap[conn]
}

func (a *Authenticate) WaitForAuth(conn quic.Connection) error {
	a.RLock()
	channel, ok := a.authChannels[conn]
	a.RUnlock()

	if !ok {
		a.Lock()
		a.authChannels[conn] = make(chan struct{})
		a.Unlock()
	}

	select {
	case <-channel:
	case <-time.After(a.authTimeout):
		return errors.New("auth timeout")
	case <-conn.Context().Done():
		return errors.New("connection closed")
	}

	a.RLock()
	auth := a.authConnMap[conn]
	a.RUnlock()

	if !auth {
		return errors.New("auth failed")
	}

	return nil
}
