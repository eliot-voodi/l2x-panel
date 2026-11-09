package main

import (
	"context"
	"encoding/json"
	"flag"
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
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/proto"
)

func main() {
	cfgPath := flag.String("config", "/etc/l2x-tunnel/agent.yaml", "config path")
	flag.Parse()

	cfg, err := config.Load(*cfgPath, "agent")
	if err != nil {
		log.Fatal(err)
	}
	if cfg.Tunnel.PeerUDP == "" {
		log.Fatal("tunnel.peer_udp is required for agent")
	}
	peer, err := net.ResolveUDPAddr("udp", cfg.Tunnel.PeerUDP)
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
	log.Printf("l2x-tunnel-agent paths=%v peer=%s cipher=%s", p.LocalAddrs(), peer, cfg.Tunnel.Cipher)

	nodeID := cfg.Tunnel.NodeID
	if nodeID == "" {
		nodeID, _ = os.Hostname()
	}
	eng := engine.New("agent", ciph, p, cfg.Tunnel.Token, nodeID, cfg.DefaultDial, cfg.Tunnel.MaxStreams)
	eng.SetPeer(peer)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go eng.Run(ctx)

	go func() {
		for i := 0; i < 15; i++ {
			_ = eng.SendCtrl(proto.TypePUNCH, []byte("punch"))
			time.Sleep(200 * time.Millisecond)
		}
		t := time.NewTicker(time.Duration(max(cfg.Tunnel.PunchIntervalSec, 30)) * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = eng.SendCtrl(proto.TypePUNCH, []byte("punch"))
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		in, out, streams, pin, pout := eng.CopyStats()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "role": "agent", "online": eng.Online(),
			"bytes_in": in, "bytes_out": out, "streams": streams,
			"packets_in": pin, "packets_out": pout,
			"peer": peer.String(), "paths": p.LocalAddrs(),
		})
	})
	go func() {
		if cfg.Metrics.Listen == "" {
			return
		}
		log.Printf("metrics %s", cfg.Metrics.Listen)
		_ = http.ListenAndServe(cfg.Metrics.Listen, mux)
	}()

	<-ctx.Done()
	log.Printf("shutdown")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
