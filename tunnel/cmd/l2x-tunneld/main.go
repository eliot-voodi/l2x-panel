package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/config"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/crypto"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/engine"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/pool"
)

func main() {
	cfgPath := flag.String("config", "/etc/l2x-tunnel/tunneld.yaml", "config path")
	flag.Parse()

	cfg, err := config.Load(*cfgPath, "portal")
	if err != nil {
		log.Fatal(err)
	}
	ciph, err := crypto.New(cfg.Tunnel.Cipher, cfg.Tunnel.PSK)
	if err != nil {
		log.Fatal(err)
	}
	p, err := pool.Listen(cfg.Tunnel.PathCount, cfg.Tunnel.ListenUDP)
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()
	log.Printf("l2x-tunneld udp paths=%v cipher=%s", p.LocalAddrs(), cfg.Tunnel.Cipher)

	eng := engine.New("portal", ciph, p, cfg.Tunnel.Token, "portal", cfg.DefaultDial, cfg.Tunnel.MaxStreams)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go eng.Run(ctx)

	dialTarget := cfg.DefaultDial
	if dialTarget == "" {
		dialTarget = "1.1.1.1:80"
	}
	go func() {
		if err := eng.ServeProxy(ctx, cfg.ProxyListen, dialTarget); err != nil {
			log.Printf("proxy: %v", err)
			cancel()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		in, out, streams, pin, pout := eng.CopyStats()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "role": "portal", "online": eng.Online(),
			"bytes_in": in, "bytes_out": out, "streams": streams,
			"packets_in": pin, "packets_out": pout,
			"peer": fmt.Sprintf("%v", eng.GetPeer()),
			"paths": p.LocalAddrs(),
		})
	})
	go func() {
		if cfg.Metrics.Listen == "" {
			return
		}
		log.Printf("metrics %s", cfg.Metrics.Listen)
		if err := http.ListenAndServe(cfg.Metrics.Listen, mux); err != nil {
			log.Printf("metrics: %v", err)
		}
	}()

	// optional punch listen announce
	go punchProbe(ctx, eng, cfg.Tunnel.PunchIntervalSec)

	log.Printf("proxy %s -> agent dial %s", cfg.ProxyListen, dialTarget)
	<-ctx.Done()
	log.Printf("shutdown")
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

func punchProbe(ctx context.Context, eng *engine.Engine, every int) {
	if every <= 0 {
		every = 60
	}
	t := time.NewTicker(time.Duration(every) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			peer := eng.GetPeer()
			if peer == nil {
				continue
			}
			_ = peer
			// engine handles TypePUNCH replies; portal-initiated punch uses KA for now
			_, _ = net.ResolveUDPAddr("udp", peer.String())
		}
	}
}
