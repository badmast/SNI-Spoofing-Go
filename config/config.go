// Package config holds runtime settings built from CLI flags.
package config

// Config is the proxy and injection settings for one run (filled from CLI flags in main).
type Config struct {
	ListenHost      string
	ListenPort      int
	ConnectIP       string
	ConnectPort     int
	FakeSNI         string
	UTLSClientHello string // uTLS preset name; empty means default (HelloChrome_Auto)
}
