package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"sni-spoofing-go/network"
)

// ConnectFromCLI builds a Config from -listen, -connect, and optional -fake-sni.
// If -connect uses a hostname, the injected SNI defaults to that hostname unless fakeSNIOverride is set.
// If -connect uses an IPv4 address, fakeSNIOverride must be non-empty (no default SNI).
func ConnectFromCLI(listenAddr, connectAddr, fakeSNIOverride string) (*Config, error) {
	listenHost, listenPortStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen address %q: %w", listenAddr, err)
	}
	listenPort, err := strconv.Atoi(listenPortStr)
	if err != nil || listenPort < 1 || listenPort > 65535 {
		return nil, fmt.Errorf("invalid listen port in %q", listenAddr)
	}
	connectHost, connectPortStr, err := net.SplitHostPort(connectAddr)
	if err != nil {
		return nil, fmt.Errorf("connect address %q: %w", connectAddr, err)
	}
	connectPort, err := strconv.Atoi(connectPortStr)
	if err != nil || connectPort < 1 || connectPort > 65535 {
		return nil, fmt.Errorf("invalid connect port in %q", connectAddr)
	}
	if listenHost != "" && !network.IsIPv4(listenHost) {
		return nil, fmt.Errorf("listen host must be IPv4 or empty, got %q", listenHost)
	}

	connectHost = strings.TrimSpace(connectHost)
	fakeSNIOverride = strings.TrimSpace(fakeSNIOverride)

	cfg := &Config{
		ListenHost:  listenHost,
		ListenPort:  listenPort,
		ConnectPort: connectPort,
	}

	if network.IsIPv4(connectHost) {
		cfg.ConnectIP = connectHost
		if fakeSNIOverride != "" {
			cfg.FakeSNI = fakeSNIOverride
		} else {
			return nil, fmt.Errorf("with -connect <IPv4>:port, set -fake-sni (no hostname to derive SNI from)")
		}
		return cfg, nil
	}

	ips, err := net.LookupIP(connectHost)
	if err != nil {
		return nil, fmt.Errorf("resolve connect host %q: %w", connectHost, err)
	}
	var ip4 net.IP
	for _, ip := range ips {
		if v := ip.To4(); v != nil {
			ip4 = v
			break
		}
	}
	if ip4 == nil {
		return nil, fmt.Errorf("no IPv4 address for connect host %q", connectHost)
	}
	cfg.ConnectIP = ip4.String()
	if fakeSNIOverride != "" {
		cfg.FakeSNI = fakeSNIOverride
	} else {
		cfg.FakeSNI = connectHost
	}
	return cfg, nil
}
