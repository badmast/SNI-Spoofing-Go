package packet

// tcp.go — Raw IPv4/TCP header accessors for captured packet byte slices.
//
// Windows uses WinDivert; Linux uses nfqueue. Both paths need TCP flags, sequence
// and ack numbers, and updates to IP length / DF and payload. These helpers read
// and write the raw IPv4 and TCP headers in place.
//
// IPv4 Header layout (20 bytes, no options assumed here):
//   Offset  0: Version(4b) + IHL(4b)
//   Offset  2: Total Length (2B)
//   Offset  4: Identification (2B)
//   Offset  6: Flags(3b) + Fragment Offset(13b)
//   Offset  8: TTL(1B) + Protocol(1B)
//   Offset 10: Header Checksum (2B)
//   Offset 12: Source Address (4B)
//   Offset 16: Destination Address (4B)
//
// TCP Header layout (20 bytes minimum, after IP header):
//   Offset  0: Source Port (2B)
//   Offset  2: Destination Port (2B)
//   Offset  4: Sequence Number (4B)
//   Offset  8: Acknowledgement Number (4B)
//   Offset 12: Data Offset(4b) + Reserved(3b) + Flags(9b)
//   Offset 14: Window Size (2B)
//   Offset 16: Checksum (2B)
//   Offset 18: Urgent Pointer (2B)

import (
	"encoding/binary"
	"fmt"
	"net"
)

// TCPFlags represents the individual TCP flag bits.
type TCPFlags struct {
	SYN bool
	ACK bool
	RST bool
	FIN bool
	PSH bool
	URG bool
}

// IPVersion returns 4 or 6 based on the IP version nibble.
func IPVersion(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	return int(raw[0] >> 4)
}

// IPHeaderLen returns the IP header length in bytes (IPv4 only).
func IPHeaderLen(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	return int(raw[0]&0x0F) * 4
}

// tcpOffset returns the byte offset where the TCP header begins.
func tcpOffset(raw []byte) int {
	return IPHeaderLen(raw)
}

// ------------------------------------------------------------------
// IPv4 Header Accessors
// ------------------------------------------------------------------

// IPv4SrcAddr returns the source IP address from an IPv4 packet.
func IPv4SrcAddr(raw []byte) net.IP {
	if len(raw) < 16 {
		return nil
	}
	return net.IP(raw[12:16])
}

// IPv4DstAddr returns the destination IP address from an IPv4 packet.
func IPv4DstAddr(raw []byte) net.IP {
	if len(raw) < 20 {
		return nil
	}
	return net.IP(raw[16:20])
}

// IPv4TotalLen returns the total length field from the IPv4 header.
func IPv4TotalLen(raw []byte) uint16 {
	if len(raw) < 4 {
		return 0
	}
	return binary.BigEndian.Uint16(raw[2:4])
}

// SetIPv4TotalLen sets the total length field in the IPv4 header.
func SetIPv4TotalLen(raw []byte, length uint16) {
	if len(raw) < 4 {
		return
	}
	binary.BigEndian.PutUint16(raw[2:4], length)
}

// IPv4Ident returns the identification field from the IPv4 header.
func IPv4Ident(raw []byte) uint16 {
	if len(raw) < 6 {
		return 0
	}
	return binary.BigEndian.Uint16(raw[4:6])
}

// SetIPv4Ident sets the identification field in the IPv4 header.
func SetIPv4Ident(raw []byte, ident uint16) {
	if len(raw) < 6 {
		return
	}
	binary.BigEndian.PutUint16(raw[4:6], ident)
}

// ClearIPv4DontFragment clears the IPv4 DF (Don't Fragment) bit so the stack may
// fragment oversized datagrams. Injection uses raw sockets; Linux rejects
// sendto(EMSGSIZE) when a single IP packet exceeds the MTU with DF set.
func ClearIPv4DontFragment(raw []byte) {
	if len(raw) < 7 || IPVersion(raw) != 4 {
		return
	}
	// Flags are the high 3 bits of the 16-bit fragment field; DF is bit 6 of byte 6 (RFC 791).
	raw[6] &^= 0x40
}

// ------------------------------------------------------------------
// TCP Header Accessors
// ------------------------------------------------------------------

// TCPSrcPort returns the source port from the TCP header.
func TCPSrcPort(raw []byte) uint16 {
	off := tcpOffset(raw)
	if len(raw) < off+4 {
		return 0
	}
	return binary.BigEndian.Uint16(raw[off : off+2])
}

// TCPDstPort returns the destination port from the TCP header.
func TCPDstPort(raw []byte) uint16 {
	off := tcpOffset(raw)
	if len(raw) < off+4 {
		return 0
	}
	return binary.BigEndian.Uint16(raw[off+2 : off+4])
}

// TCPSeqNum returns the 32-bit sequence number.
func TCPSeqNum(raw []byte) uint32 {
	off := tcpOffset(raw)
	if len(raw) < off+8 {
		return 0
	}
	return binary.BigEndian.Uint32(raw[off+4 : off+8])
}

// SetTCPSeqNum sets the 32-bit sequence number.
func SetTCPSeqNum(raw []byte, seq uint32) {
	off := tcpOffset(raw)
	if len(raw) < off+8 {
		return
	}
	binary.BigEndian.PutUint32(raw[off+4:off+8], seq)
}

// TCPAckNum returns the 32-bit acknowledgement number.
func TCPAckNum(raw []byte) uint32 {
	off := tcpOffset(raw)
	if len(raw) < off+12 {
		return 0
	}
	return binary.BigEndian.Uint32(raw[off+8 : off+12])
}

// SetTCPAckNum sets the 32-bit acknowledgement number.
func SetTCPAckNum(raw []byte, ack uint32) {
	off := tcpOffset(raw)
	if len(raw) < off+12 {
		return
	}
	binary.BigEndian.PutUint32(raw[off+8:off+12], ack)
}

// TCPDataOffset returns the TCP header length in bytes (data offset field × 4).
func TCPDataOffset(raw []byte) int {
	off := tcpOffset(raw)
	if len(raw) < off+13 {
		return 0
	}
	return int(raw[off+12]>>4) * 4
}

// GetTCPFlags reads the TCP flags from the raw packet.
func GetTCPFlags(raw []byte) TCPFlags {
	off := tcpOffset(raw)
	if len(raw) < off+14 {
		return TCPFlags{}
	}
	// Flags are in bytes 12-13 of the TCP header.
	// Byte 13 contains: CWR ECE URG ACK PSH RST SYN FIN
	flags := raw[off+13]
	return TCPFlags{
		FIN: flags&0x01 != 0,
		SYN: flags&0x02 != 0,
		RST: flags&0x04 != 0,
		PSH: flags&0x08 != 0,
		ACK: flags&0x10 != 0,
		URG: flags&0x20 != 0,
	}
}

// SetTCPFlag sets or clears a specific TCP flag. Accepts flag name: "syn", "ack", "rst", "fin", "psh", "urg".
func SetTCPFlag(raw []byte, flag string, value bool) {
	off := tcpOffset(raw)
	if len(raw) < off+14 {
		return
	}
	var mask byte
	switch flag {
	case "fin":
		mask = 0x01
	case "syn":
		mask = 0x02
	case "rst":
		mask = 0x04
	case "psh":
		mask = 0x08
	case "ack":
		mask = 0x10
	case "urg":
		mask = 0x20
	}
	if value {
		raw[off+13] |= mask
	} else {
		raw[off+13] &^= mask
	}
}

// TCPPayload returns the TCP payload (data after the TCP header).
func TCPPayload(raw []byte) []byte {
	ipHdrLen := IPHeaderLen(raw)
	tcpHdrLen := TCPDataOffset(raw)
	payloadStart := ipHdrLen + tcpHdrLen
	if payloadStart >= len(raw) {
		return nil
	}
	return raw[payloadStart:]
}

// TCPPayloadLen returns the length of the TCP payload.
func TCPPayloadLen(raw []byte) int {
	payload := TCPPayload(raw)
	if payload == nil {
		return 0
	}
	return len(payload)
}

// SetTCPPayload replaces the TCP payload and updates the IP total length field.
// Returns a new raw packet byte slice with the modified payload.
// Returns nil if raw has invalid IPv4/TCP headers or truncated data.
func SetTCPPayload(raw []byte, payload []byte) []byte {
	if len(raw) < 20 {
		return nil
	}
	ipHdrLen := IPHeaderLen(raw)
	if ipHdrLen < 20 || ipHdrLen > 60 || len(raw) < ipHdrLen {
		return nil
	}
	tcpHdrLen := TCPDataOffset(raw)
	if tcpHdrLen < 20 || tcpHdrLen > 60 {
		return nil
	}
	headerTotal := ipHdrLen + tcpHdrLen
	if headerTotal > len(raw) || headerTotal < ipHdrLen+20 {
		return nil
	}

	newRaw := make([]byte, headerTotal+len(payload))
	copy(newRaw, raw[:headerTotal])
	copy(newRaw[headerTotal:], payload)

	// Update IP total length
	SetIPv4TotalLen(newRaw, uint16(len(newRaw)))

	return newRaw
}

// PacketSummary returns a human-readable summary of the packet for debugging.
func PacketSummary(raw []byte) string {
	if len(raw) < 40 {
		return fmt.Sprintf("<packet too short: %d bytes>", len(raw))
	}
	flags := GetTCPFlags(raw)
	flagStr := ""
	if flags.SYN {
		flagStr += "SYN "
	}
	if flags.ACK {
		flagStr += "ACK "
	}
	if flags.RST {
		flagStr += "RST "
	}
	if flags.FIN {
		flagStr += "FIN "
	}
	if flags.PSH {
		flagStr += "PSH "
	}
	return fmt.Sprintf("%s:%d → %s:%d [%s] seq=%d ack=%d payload=%d",
		IPv4SrcAddr(raw), TCPSrcPort(raw),
		IPv4DstAddr(raw), TCPDstPort(raw),
		flagStr, TCPSeqNum(raw), TCPAckNum(raw), TCPPayloadLen(raw))
}
