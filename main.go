// TLS proxy: fake ClientHello injection (wrong-seq) + optional real CH fragmentation. IPv4 only; needs admin/root.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	"sni-spoofing-go/config"
	"sni-spoofing-go/injection"
	"sni-spoofing-go/network"
	"sni-spoofing-go/packet"
)

func usage() {
	exe := os.Args[0]
	w := os.Stderr
	fmt.Fprintf(w, "SNI-Spoofing — fake TLS ClientHello (SNI) injection proxy. IPv4 only; run as Administrator / root.\n\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s -listen <addr> -connect <addr> [options]\n\n", exe)
	fmt.Fprintf(w, "Required:\n")
	fmt.Fprintf(w, "  -listen <host:port>   proxy listen address (host may be omitted, e.g. :8080)\n")
	fmt.Fprintf(w, "  -connect <host:port>  upstream; hostname (SNI defaults to host) or IPv4 (-fake-sni required)\n\n")
	fmt.Fprintf(w, "Optional:\n")
	fmt.Fprintf(w, "  -fake-sni <hostname>  injected ClientHello SNI (overrides hostname from -connect)\n")
	fmt.Fprintf(w, "  -fake-repeat <n>      how many times to inject fake ClientHello (default 1)\n")
	fmt.Fprintf(w, "  -utls <name>          TLS fingerprint (default: chrome); see list below\n")
	fmt.Fprintf(w, "  -fragment             split real ClientHello: prefix, SNI chunks, suffix (default true)\n")
	fmt.Fprintf(w, "  -fragment-delay       delay between writes (default 500ms)\n")
	fmt.Fprintf(w, "  -sni-chunk            SNI hostname bytes per write after prefix (default 3; 0 = whole hostname in one write)\n\n")
	fmt.Fprintf(w, "Examples:\n")
	fmt.Fprintf(w, "  %s -listen 127.0.0.1:8080 -connect example.com:443\n", exe)
	fmt.Fprintf(w, "  %s -listen 127.0.0.1:8080 -connect 198.51.100.2:443 -fake-sni allowed.example.com\n\n", exe)
	fmt.Fprintf(w, "Valid -utls names:\n\n")
	fmt.Fprintf(w, "%s", packet.UTLSHelpGroupedCSV())
	fmt.Fprintf(w, "\nDefault when -utls is omitted: %s.\n\n", packet.DefaultUTLSSummary())
	fmt.Fprintf(w, "Options:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	var optListen, optConnect, optFakeSNI, optUTLS string
	var fragment bool
	var fragmentDelay time.Duration
	var sniChunk int
	var fakeRepeat int
	flag.StringVar(&optListen, "listen", "", "listen address host:port (required)")
	flag.StringVar(&optConnect, "connect", "", "upstream host:port (required)")
	flag.StringVar(&optFakeSNI, "fake-sni", "", "injected ClientHello SNI (optional if -connect uses a hostname)")
	flag.IntVar(&fakeRepeat, "fake-repeat", 1, "number of wrong-seq fake ClientHello injections before real traffic")
	flag.StringVar(&optUTLS, "utls", "", "TLS fingerprint preset (see usage above; e.g. chrome_120, firefox)")
	flag.BoolVar(&fragment, "fragment", true, "after fake SNI, read real ClientHello: send prefix, then SNI chunks, then suffix")
	flag.DurationVar(&fragmentDelay, "fragment-delay", 500*time.Millisecond, "delay between ClientHello segment writes")
	flag.IntVar(&sniChunk, "sni-chunk", packet.DefaultSNIChunkBytes, "SNI hostname bytes per TCP write (0 = entire hostname in one write)")
	flag.Parse()

	cliListen, cliConnect := false, false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			cliListen = true
		case "connect":
			cliConnect = true
		}
	})

	fakeSNIArg := strings.TrimSpace(optFakeSNI)

	args := flag.Args()
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected arguments: %q\n\n", args)
		usage()
		os.Exit(2)
	}
	if !cliListen || !cliConnect {
		log.Fatal("required flags: -listen and -connect")
	}
	if fakeRepeat < 1 {
		log.Fatal("-fake-repeat must be at least 1")
	}
	if sniChunk < 0 {
		log.Fatal("-sni-chunk must be >= 0 (0 = whole hostname in one write)")
	}

	cfg, err := config.ConnectFromCLI(optListen, optConnect, fakeSNIArg)
	if err != nil {
		log.Fatal("Invalid configuration: ", err)
	}

	if strings.TrimSpace(optUTLS) != "" {
		cfg.UTLSClientHello = optUTLS
	}
	clientHelloID, err := packet.ParseClientHelloID(cfg.UTLSClientHello)
	if err != nil {
		log.Fatal("Invalid -utls: ", err)
	}

	fakeSNI := []byte(cfg.FakeSNI)
	if !network.IsIPv4(cfg.ConnectIP) {
		log.Fatalf("upstream must resolve to IPv4 (IPv6 is not supported): %q", cfg.ConnectIP)
	}
	if cfg.ListenHost != "" && !network.IsIPv4(cfg.ListenHost) {
		log.Fatalf("LISTEN host must be IPv4 or empty (IPv6 is not supported): %q", cfg.ListenHost)
	}
	interfaceIPv4 := network.GetDefaultInterfaceIPv4(cfg.ConnectIP)
	if interfaceIPv4 == "" {
		log.Fatal("Failed to detect local interface IPv4 address")
	}
	fmt.Printf("Local interface: %s\n", interfaceIPv4)

	fakeInjector, err := injection.NewFakeTcpInjector(interfaceIPv4, cfg.ConnectIP, uint16(cfg.ConnectPort))
	if err != nil {
		log.Fatal("Failed to create injector: ", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		fakeInjector.Close()
		os.Exit(0)
	}()

	go fakeInjector.Start()

	listenAddr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort))
	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		log.Fatal("Failed to listen: ", err)
	}
	defer listener.Close()
	fmt.Printf("Listening on %s\n", listenAddr)

	for {
		incomingSock, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		if tc, ok := incomingSock.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(11 * time.Second)
		}

		go handleConnection(incomingSock, cfg, interfaceIPv4, fakeSNI, clientHelloID, fakeInjector, fakeRepeat, fragment, fragmentDelay, sniChunk)
	}
}

func handleConnection(
	incomingSock net.Conn,
	cfg *config.Config,
	interfaceIPv4 string,
	fakeSNI []byte,
	clientHelloID utls.ClientHelloID,
	fakeInjector *injection.FakeTcpInjector,
	fakeRepeat int,
	fragment bool,
	fragmentDelay time.Duration,
	sniChunk int,
) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in handle: %v", r)
		}
	}()

	fakeData, err := packet.BuildClientHelloRecord(string(fakeSNI), clientHelloID)
	if err != nil {
		log.Printf("ClientHello: %v", err)
		incomingSock.Close()
		return
	}

	outgoingSock, conn, srcPort, err := dialOutgoing(
		interfaceIPv4, cfg.ConnectIP, cfg.ConnectPort,
		fakeData, "wrong_seq", fakeRepeat, incomingSock, fakeInjector,
	)
	if err != nil {
		log.Printf("Failed to connect to %s:%d: %v", cfg.ConnectIP, cfg.ConnectPort, err)
		incomingSock.Close()
		return
	}

	conn.Mu.Lock()
	conn.Sock = outgoingSock
	conn.Mu.Unlock()

	if tc, ok := outgoingSock.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(11 * time.Second)
	}

	key := injection.ConnID{
		SrcIP: interfaceIPv4, SrcPort: srcPort,
		DstIP: cfg.ConnectIP, DstPort: uint16(cfg.ConnectPort),
	}

	select {
	case msg := <-conn.T2aChan:
		if msg == "unexpected_close" {
			conn.Mu.Lock()
			conn.Monitor = false
			conn.Mu.Unlock()
			fakeInjector.Connections.Delete(key)
			outgoingSock.Close()
			incomingSock.Close()
			return
		}
		if msg != "fake_data_ack_recv" {
			log.Printf("unexpected t2a msg: %q", msg)
			conn.Mu.Lock()
			conn.Monitor = false
			conn.Mu.Unlock()
			fakeInjector.Connections.Delete(key)
			outgoingSock.Close()
			incomingSock.Close()
			return
		}
	case <-time.After(2 * time.Second):
		conn.Mu.Lock()
		conn.Monitor = false
		conn.Mu.Unlock()
		fakeInjector.Connections.Delete(key)
		outgoingSock.Close()
		incomingSock.Close()
		return
	}

	conn.Mu.Lock()
	conn.Monitor = false
	conn.Mu.Unlock()
	fakeInjector.Connections.Delete(key)

	if fragment {
		if err := forwardFragmentedClientHello(incomingSock, outgoingSock, fragmentDelay, sniChunk); err != nil {
			log.Printf("ClientHello fragment: %v", err)
			outgoingSock.Close()
			incomingSock.Close()
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() { defer func() { done <- struct{}{} }(); relay(outgoingSock, incomingSock) }()
	go func() { defer func() { done <- struct{}{} }(); relay(incomingSock, outgoingSock) }()

	<-done
	outgoingSock.Close()
	incomingSock.Close()
	<-done
}

func forwardFragmentedClientHello(incoming, outgoing net.Conn, delay time.Duration, sniChunkBytes int) error {
	rec, err := packet.ReadFirstTLSRecord(incoming)
	if err != nil {
		return err
	}
	frags := packet.SplitClientHelloRecord(rec, sniChunkBytes)
	var tcpFrag *net.TCPConn
	if tc, ok := outgoing.(*net.TCPConn); ok {
		tcpFrag = tc
	}
	return packet.WriteClientHelloFragments(outgoing, frags, delay, tcpFrag)
}

func relay(dst, src net.Conn) {
	buf := make([]byte, 65575)
	_, _ = io.CopyBuffer(dst, src, buf)
}
