package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/config"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/crypto"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/engine"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/netperf"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/pool"
)

func main() {
	cfgPath := flag.String("config", "/etc/l2x-tunnel/agent.yaml", "config path")
	flag.Parse()

	if err := netperf.Apply(); err != nil {
		log.Printf("netperf: %v", err)
	}

	cfg, err := config.Load(*cfgPath, "agent")
	if err != nil {
		log.Fatal(err)
	}
	ciph, err := crypto.New(cfg.Tunnel.Cipher, cfg.Tunnel.PSK)
	if err != nil {
		log.Fatal(err)
	}

	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if transport == "" {
		if cfg.WSURL != "" {
			transport = "wss"
		} else {
			transport = "udp"
		}
	}

	nodeID := cfg.Tunnel.NodeID
	if nodeID == "" {
		nodeID, _ = os.Hostname()
	}

	// Local UDP pool only needed for legacy udp transport.
	p, err := pool.Listen(1, "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()

	eng := engine.New("agent", ciph, p, cfg.Tunnel.Token, nodeID, cfg.DefaultDial, cfg.Tunnel.MaxStreams)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go eng.Run(ctx)

	if transport == "wss" || transport == "both" {
		wsURL := strings.TrimSpace(cfg.WSURL)
		if wsURL == "" {
			log.Fatal("transport=wss requires ws_url (wss://master/ws-…)")
		}
		log.Printf("l2x-tunnel-agent transport=wss url=%s cipher=%s", wsURL, cfg.Tunnel.Cipher)
		go func() {
			if err := eng.DialWS(ctx, wsURL); err != nil {
				log.Printf("wss: %v", err)
				cancel()
			}
		}()
	}
	if transport == "udp" || transport == "both" {
		if cfg.Tunnel.PeerUDP == "" {
			log.Fatal("tunnel.peer_udp is required for udp transport")
		}
		log.Printf("l2x-tunnel-agent transport=udp peer=%s", cfg.Tunnel.PeerUDP)
		// Legacy path kept for lab; production apricot uses wss only.
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		in, out, streams, pin, pout := eng.CopyStats()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "role": "agent", "online": eng.Online(),
			"bytes_in": in, "bytes_out": out, "streams": streams,
			"packets_in": pin, "packets_out": pout,
			"transport": transport, "ws_url": cfg.WSURL,
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
