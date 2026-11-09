package pool

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

type Path struct {
	ID   uint8
	Conn *net.UDPConn
}

type Pool struct {
	paths []*Path
	rr    uint32
	mu    sync.Mutex
}

func Listen(n int, bind string) (*Pool, error) {
	if n < 1 {
		n = 1
	}
	if n > 16 {
		n = 16
	}
	host, portStr, err := net.SplitHostPort(bind)
	if err != nil {
		return nil, err
	}
	basePort := 0
	if portStr != "0" {
		fmt.Sscanf(portStr, "%d", &basePort)
	}
	p := &Pool{}
	for i := 0; i < n; i++ {
		addr := bind
		if basePort > 0 && i > 0 {
			addr = net.JoinHostPort(host, fmt.Sprintf("%d", basePort+i))
		} else if basePort == 0 {
			addr = net.JoinHostPort(host, "0")
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			p.Close()
			return nil, err
		}
		c, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			p.Close()
			return nil, err
		}
		_ = c.SetReadBuffer(4 << 20)
		_ = c.SetWriteBuffer(4 << 20)
		p.paths = append(p.paths, &Path{ID: uint8(i), Conn: c})
	}
	return p, nil
}

func (p *Pool) Paths() []*Path { return p.paths }

func (p *Pool) Next() *Path {
	if len(p.paths) == 0 {
		return nil
	}
	i := atomic.AddUint32(&p.rr, 1)
	return p.paths[int(i)%len(p.paths)]
}

func (p *Pool) ByID(id uint8) *Path {
	if int(id) >= len(p.paths) {
		return p.Next()
	}
	return p.paths[id]
}

func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, path := range p.paths {
		if path.Conn != nil {
			_ = path.Conn.Close()
		}
	}
	p.paths = nil
}

func (p *Pool) LocalAddrs() []string {
	out := make([]string, 0, len(p.paths))
	for _, path := range p.paths {
		out = append(out, path.Conn.LocalAddr().String())
	}
	return out
}
