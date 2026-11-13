package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/dnsd"
)

func main() {
	cfgPath := flag.String("config", "/etc/l2x-dnsd/dnsd.yaml", "config path")
	flag.Parse()

	cfg, err := dnsd.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := dnsd.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, systemdSIGTERM())
	defer cancel()

	log.Printf("l2x-dnsd starting domain=%s listen=%s method=%d", cfg.Domain, cfg.ListenUDP, cfg.EncryptionMethod)
	if err := srv.Run(ctx); err != nil {
		log.Printf("l2x-dnsd: %v", err)
		os.Exit(1)
	}
}

func systemdSIGTERM() os.Signal {
	return syscall.SIGTERM
}
