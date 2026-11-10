package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if transport == "" {
		transport = "wss"
	}

	var p *pool.Pool
	if transport == "udp" || transport == "both" {
		p, err = pool.Listen(cfg.Tunnel.PathCount, cfg.Tunnel.ListenUDP)
		if err != nil {
			log.Fatal(err)
		}
		defer p.Close()
		log.Printf("l2x-tunneld udp paths=%v cipher=%s", p.LocalAddrs(), cfg.Tunnel.Cipher)
	} else {
		// WSS-only: no public UDP (avoids VPN-like fingerprint). Tiny unused pool for API compat.
		p, err = pool.Listen(1, "127.0.0.1:0")
		if err != nil {
			log.Fatal(err)
		}
		defer p.Close()
		log.Printf("l2x-tunneld transport=wss cipher=%s (UDP public listen disabled)", cfg.Tunnel.Cipher)
	}

	eng := engine.New("portal", ciph, p, cfg.Tunnel.Token, "portal", cfg.DefaultDial, cfg.Tunnel.MaxStreams)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go eng.Run(ctx)

	dialTarget := cfg.DefaultDial
	if dialTarget == "" {
		dialTarget = "1.1.1.1:80"
	}
	if cfg.ProxyListen != "" {
		go func() {
			if err := eng.ServeProxy(ctx, cfg.ProxyListen, dialTarget); err != nil {
				log.Printf("proxy: %v", err)
			}
		}()
		log.Printf("proxy %s -> agent dial %s", cfg.ProxyListen, dialTarget)
	}
	if cfg.SocksListen != "" {
		go func() {
			if err := eng.ServeSOCKS5(ctx, cfg.SocksListen); err != nil {
				log.Printf("socks5: %v", err)
				cancel()
			}
		}()
		log.Printf("socks5 %s (Xray node egress)", cfg.SocksListen)
	}
	if transport == "wss" || transport == "both" {
		listen := cfg.WSListen
		if listen == "" {
			listen = "127.0.0.1:11081"
		}
		path := cfg.WSPath
		if path == "" {
			path = "/ws-l2x-tunnel"
		}
		go func() {
			if err := eng.ServeWS(ctx, listen, path); err != nil {
				log.Printf("ws: %v", err)
				cancel()
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		in, out, streams, pin, pout := eng.CopyStats()
		agents := eng.AgentsStatus()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "role": "portal", "online": eng.Online() || len(agents) > 0,
			"bytes_in": in, "bytes_out": out, "streams": streams,
			"packets_in": pin, "packets_out": pout,
			"peer":       fmt.Sprintf("%v", eng.GetPeer()),
			"agents":     agents,
			"transport":  transport,
			"ws_path":    cfg.WSPath,
			"socks":      cfg.SocksListen,
			"proxy":      cfg.ProxyListen,
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

	<-ctx.Done()
	log.Printf("shutdown")
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}
