package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"time"

	utls "github.com/refraction-networking/utls"
)

const maxTLSPlaintextRecord = 1<<14 + 2048

const DefaultSNIChunkBytes = 3

func ReadFirstTLSRecord(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 22 {
		return nil, fmt.Errorf("packet: want TLS handshake record (22), got type %d", hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n <= 0 || n > maxTLSPlaintextRecord {
		return nil, fmt.Errorf("packet: invalid TLS record length %d", n)
	}
	out := make([]byte, 5+n)
	copy(out, hdr[:])
	if _, err := io.ReadFull(r, out[5:]); err != nil {
		return nil, err
	}
	return out, nil
}

func sniValueRange(record []byte) (start, end int, ok bool) {
	if len(record) < 5 {
		return 0, 0, false
	}
	payload := record[5:]
	ch := utls.UnmarshalClientHello(payload)
	if ch == nil || ch.ServerName == "" {
		return 0, 0, false
	}
	host := ch.ServerName
	idx := bytes.Index(record, []byte(host))
	if idx < 0 {
		return 0, 0, false
	}
	return idx, idx + len(host), true
}

func SplitClientHelloRecord(record []byte, sniChunkBytes int) [][]byte {
	if sniChunkBytes < 0 {
		sniChunkBytes = 0
	}
	if len(record) == 0 {
		return nil
	}
	s, e, ok := sniValueRange(record)
	if !ok || e <= s {
		return [][]byte{record}
	}
	var out [][]byte
	if s > 0 {
		out = append(out, record[:s])
	}
	if sniChunkBytes <= 0 {
		out = append(out, record[s:e])
	} else {
		for i := s; i < e; i += sniChunkBytes {
			j := i + sniChunkBytes
			if j > e {
				j = e
			}
			out = append(out, record[i:j])
		}
	}
	if e < len(record) {
		out = append(out, record[e:])
	}
	if len(out) == 0 {
		return [][]byte{record}
	}
	return out
}

func WriteClientHelloFragments(w io.Writer, frags [][]byte, delay time.Duration, tcp interface{ SetNoDelay(bool) error }) error {
	if tcp != nil {
		_ = tcp.SetNoDelay(true)
		defer func() { _ = tcp.SetNoDelay(false) }()
	}
	nFrag := 0
	for _, p := range frags {
		if len(p) > 0 {
			nFrag++
		}
	}
	sent := 0
	for _, p := range frags {
		if len(p) == 0 {
			continue
		}
		if sent > 0 && delay > 0 {
			time.Sleep(delay)
		}
		sent++
		if _, err := w.Write(p); err != nil {
			return err
		}
		log.Printf("ClientHello fragment %d/%d sent (%d bytes)", sent, nFrag, len(p))
	}
	return nil
}
