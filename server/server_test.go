package server

import (
	"github.com/sirupsen/logrus"
	"testing"
	"tuic-server/config"
)

func TestTUICServer(t *testing.T) {
	logrus.SetReportCaller(true)
	c := &config.Config{}
	c.SetDefaults()
	server, err := NewTUICServer(c)
	if err != nil {
		t.Errorf("err:%v", err)
		return
	}

	err = server.Start()
	if err != nil {
		t.Errorf("err:%v", err)
		return
	}
}
