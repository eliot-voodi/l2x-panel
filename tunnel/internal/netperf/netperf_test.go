package netperf

import (
	"strings"
	"testing"
)

func TestBodySizesByRAM(t *testing.T) {
	low := Body(1024, nil)
	if !strings.Contains(low, "16777216") {
		t.Fatalf("1GB host should keep 16MB buffers:\n%s", low)
	}
	mid := Body(2048, nil)
	if !strings.Contains(mid, "33554432") {
		t.Fatalf("2GB host should use 32MB buffers:\n%s", mid)
	}
	hi := Body(4096, []int{11080, 8000})
	if !strings.Contains(hi, "67108864") {
		t.Fatalf("4GB host should use 64MB buffers:\n%s", hi)
	}
	if !strings.Contains(hi, "net.ipv4.ip_local_reserved_ports = 11080") {
		t.Fatalf("reserved ports missing:\n%s", hi)
	}
	for _, want := range []string{
		"tcp_congestion_control = bbr",
		"netdev_max_backlog = 16384",
		"somaxconn = 65535",
		"tcp_notsent_lowat = 16384",
		"rmem_default = 1048576",
		"-net.netfilter.nf_conntrack_max",
	} {
		if !strings.Contains(hi, want) {
			t.Fatalf("missing %q in:\n%s", want, hi)
		}
	}
}
