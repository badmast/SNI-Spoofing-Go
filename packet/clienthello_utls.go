package packet

import (
	"fmt"
	"io"
	"net"

	utls "github.com/refraction-networking/utls"
)

// recordHeaderHandshakeTLS13Client prepends the TLS record header that Chrome,
// Firefox, and Safari use for a TLS 1.3 ClientHello: content type handshake and
// legacy_record_version 0x0303 (TLS 1.2), per RFC 8446 section 5.1.
//
// This differs from Go's tls.Conn.writeRecordLocked when Conn.vers==0 (which uses
// 0x0301); browsers align on 0x0303 for DPI / fingerprint parity with real traffic.
func recordHeaderHandshakeTLS13Client(fragmentLen int) [5]byte {
	var h [5]byte
	h[0] = 22 // recordTypeHandshake
	v := utls.VersionTLS12
	h[1] = byte(v >> 8)
	h[2] = byte(v)
	h[3] = byte(fragmentLen >> 8)
	h[4] = byte(fragmentLen)
	return h
}

// BuildClientHelloRecord returns a full TLS record (type handshake) containing a
// uTLS ClientHello for serverName built with the given ClientHelloID (browser parrot, etc.).
func BuildClientHelloRecord(serverName string, id utls.ClientHelloID) ([]byte, error) {
	if serverName == "" {
		return nil, fmt.Errorf("packet: empty server name")
	}

	config := &utls.Config{ServerName: serverName}

	client, server := net.Pipe()
	defer client.Close()

	go func() {
		_, _ = io.Copy(io.Discard, server)
		_ = server.Close()
	}()

	uconn := utls.UClient(client, config, id)
	if err := uconn.BuildHandshakeStateWithoutSession(); err != nil {
		return nil, fmt.Errorf("packet: build ClientHello: %w", err)
	}

	handshake := uconn.HandshakeState.Hello.Raw
	if len(handshake) == 0 {
		return nil, fmt.Errorf("packet: empty ClientHello handshake")
	}

	hdr := recordHeaderHandshakeTLS13Client(len(handshake))
	out := make([]byte, 5+len(handshake))
	copy(out, hdr[:])
	copy(out[5:], handshake)
	return out, nil
}
