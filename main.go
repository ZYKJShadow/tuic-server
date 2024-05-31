package main

import (
	"flag"
	"github.com/sirupsen/logrus"
	"os"
	"tuic-server/config"
	"tuic-server/server"
)

var path string

func init() {
	flag.StringVar(&path, "c", "", "config file path")
	flag.StringVar(&path, "config", "", "config file path")
}

func main() {

	flag.Parse()

	logrus.SetReportCaller(true)

	cfg := &config.Config{}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}

		err = cfg.Unmarshal(b)
		if err != nil {
			panic(err)
		}

	} else {
		cfg.SetDefaults()
	}

	s, err := server.NewTUICServer(cfg)
	if err != nil {
		panic(err)
	}

	err = s.Start()
	if err != nil {
		panic(err)
	}
}
