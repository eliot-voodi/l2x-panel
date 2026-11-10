// Package netperf applies host sysctl tuning for high-RTT proxy / tunnel hosts.
// Keep the rule set in sync with panel/ops.py PERF_SYSCTL_BODY / perf_sysctl_body().
package netperf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	sysctlPath     = "/etc/sysctl.d/99-l2xpanel-perf.conf"
	modulesPath    = "/etc/modules-load.d/l2x-perf.conf"
	ephemeralLow   = 10240
)

var fixedReserved = []int{11080, 11081, 18080, 19100}

// Apply writes sysctl rules sized by RAM and loads them (idempotent).
func Apply() error {
	mem := memTotalMB()
	body := Body(mem, reservedPorts())
	if err := os.MkdirAll(filepath.Dir(sysctlPath), 0o755); err != nil {
		return err
	}
	cur, _ := os.ReadFile(sysctlPath)
	if strings.TrimSpace(string(cur)) != strings.TrimSpace(body) {
		if err := os.WriteFile(sysctlPath, []byte(body), 0o644); err != nil {
			return err
		}
	}
	_ = os.MkdirAll(filepath.Dir(modulesPath), 0o755)
	_ = os.WriteFile(modulesPath, []byte("tcp_bbr\n"), 0o644)
	_ = exec.Command("modprobe", "tcp_bbr").Run()
	out, err := exec.Command("sysctl", "-e", "-p", sysctlPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Body builds the sysctl file contents for the given RAM size (MB).
func Body(memMB int, reserved []int) string {
	if memMB <= 0 {
		memMB = 1024
	}
	buf, ct := 16777216, 262144
	switch {
	case memMB >= 3500:
		buf, ct = 67108864, 1048576
	case memMB >= 1800:
		buf, ct = 33554432, 524288
	}
	uniq := map[int]struct{}{}
	for _, p := range reserved {
		if p >= ephemeralLow {
			uniq[p] = struct{}{}
		}
	}
	ports := make([]int, 0, len(uniq))
	for p := range uniq {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	var b strings.Builder
	fmt.Fprintf(&b, "# managed by l2x-tunnel — network perf (RAM %d MB)\n", memMB)
	b.WriteString("net.core.default_qdisc = fq\n")
	b.WriteString("net.ipv4.tcp_congestion_control = bbr\n")
	fmt.Fprintf(&b, "net.core.rmem_max = %d\n", buf)
	fmt.Fprintf(&b, "net.core.wmem_max = %d\n", buf)
	b.WriteString("net.core.rmem_default = 1048576\n")
	b.WriteString("net.core.wmem_default = 1048576\n")
	fmt.Fprintf(&b, "net.ipv4.tcp_rmem = 4096 131072 %d\n", buf)
	fmt.Fprintf(&b, "net.ipv4.tcp_wmem = 4096 65536 %d\n", buf)
	b.WriteString("net.ipv4.udp_rmem_min = 16384\n")
	b.WriteString("net.ipv4.udp_wmem_min = 16384\n")
	b.WriteString("net.core.netdev_max_backlog = 16384\n")
	b.WriteString("net.core.somaxconn = 65535\n")
	b.WriteString("net.ipv4.tcp_max_syn_backlog = 65535\n")
	fmt.Fprintf(&b, "net.ipv4.ip_local_port_range = %d 65535\n", ephemeralLow)
	if len(ports) > 0 {
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = strconv.Itoa(p)
		}
		fmt.Fprintf(&b, "net.ipv4.ip_local_reserved_ports = %s\n", strings.Join(parts, ","))
	}
	b.WriteString("net.ipv4.tcp_notsent_lowat = 16384\n")
	b.WriteString("net.ipv4.tcp_fastopen = 3\n")
	b.WriteString("net.ipv4.tcp_slow_start_after_idle = 0\n")
	b.WriteString("net.ipv4.tcp_mtu_probing = 1\n")
	fmt.Fprintf(&b, "-net.netfilter.nf_conntrack_max = %d\n", ct)
	return b.String()
}

func memTotalMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 1024
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.Atoi(fields[1])
				return kb / 1024
			}
		}
	}
	return 1024
}

func reservedPorts() []int {
	out := append([]int{}, fixedReserved...)
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile("/proc/net/" + name)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) < 2 {
			continue
		}
		listen := "0A"
		if strings.HasPrefix(name, "udp") {
			listen = "07"
		}
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != listen {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) < 2 {
				continue
			}
			v, err := strconv.ParseUint(parts[len(parts)-1], 16, 16)
			if err != nil {
				continue
			}
			p := int(v)
			if p >= ephemeralLow {
				out = append(out, p)
			}
		}
	}
	return out
}
