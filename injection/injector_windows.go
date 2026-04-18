//go:build windows

package injection

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/williamfhe/godivert"

	"sni-spoofing-go/connection"
	"sni-spoofing-go/packet"
)

type FakeTcpInjector struct {
	wd          *godivert.WinDivertHandle
	Connections sync.Map
}

func NewFakeTcpInjector(interfaceIP, connectIP string, connectPort uint16) (*FakeTcpInjector, error) {
	filter := fmt.Sprintf(
		"tcp and ((ip.SrcAddr == %s and ip.DstAddr == %s) or (ip.SrcAddr == %s and ip.DstAddr == %s))",
		interfaceIP, connectIP, connectIP, interfaceIP,
	)
	wd, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		return nil, err
	}
	return &FakeTcpInjector{wd: wd}, nil
}

func (f *FakeTcpInjector) Start() {
	for {
		pkt, err := f.wd.Recv()
		if err != nil {
			log.Printf("WinDivert recv error: %v", err)
			continue
		}
		f.inject(pkt)
	}
}

func (f *FakeTcpInjector) Close() {
	if f.wd != nil {
		f.wd.Close()
	}
}

func (f *FakeTcpInjector) sendPacket(pkt *godivert.Packet, recalc bool) error {
	if recalc {
		pkt.CalcNewChecksum(f.wd)
	}
	_, err := f.wd.Send(pkt)
	if err != nil {
		log.Printf("WinDivert send error: %v", err)
	}
	return err
}

func (f *FakeTcpInjector) fakeSendThread(rawCopy []byte, addr *godivert.WinDivertAddress, conn *FakeInjectiveConnection) {
	conn.Mu.Lock()
	defer conn.Mu.Unlock()

	time.Sleep(1 * time.Millisecond)

	if !conn.Monitor {
		return
	}

	if conn.BypassMethod == "wrong_seq" {
		repeat := conn.FakeRepeat
		if repeat < 1 {
			repeat = 1
		}
		payloadLen := uint32(len(conn.FakeData))
		wrongSeq := (uint32(conn.SynSeq) + 1 - payloadLen) & 0xffffffff
		for i := 0; i < repeat; i++ {
			pktData := append([]byte(nil), rawCopy...)
			packet.SetTCPFlag(pktData, "psh", true)
			one := packet.SetTCPPayload(pktData, conn.FakeData)
			if one == nil {
				log.Printf("SetTCPPayload: invalid or truncated TCP/IP packet")
				conn.AbortUnexpectedCloseLocked()
				return
			}
			packet.SetTCPSeqNum(one, wrongSeq)
			if packet.IPVersion(one) == 4 {
				ident := packet.IPv4Ident(one)
				packet.SetIPv4Ident(one, (ident+1+uint16(i))&0xffff)
			}
			addrCopy := *addr
			fakePkt := &godivert.Packet{
				Raw:       one,
				Addr:      &addrCopy,
				PacketLen: uint(len(one)),
			}
			if err := f.sendPacket(fakePkt, true); err != nil {
				conn.AbortUnexpectedCloseLocked()
				return
			}
			log.Printf("injector: fake TLS ClientHello %d/%d sent (%d bytes, 1 TCP segment)",
				i+1, repeat, len(conn.FakeData))
			if i+1 < repeat {
				time.Sleep(2 * time.Millisecond)
			}
		}
		conn.FakeSent = true
	} else {
		log.Printf("not implemented bypass method: %s", conn.BypassMethod)
		conn.AbortUnexpectedCloseLocked()
	}
}

func (f *FakeTcpInjector) onUnexpectedPacket(pkt *godivert.Packet, conn *FakeInjectiveConnection, info string) {
	fmt.Println(info, packet.PacketSummary(pkt.Raw))
	if conn.Sock != nil {
		conn.Sock.Close()
	}
	if conn.PeerSock != nil {
		conn.PeerSock.Close()
	}
	conn.Monitor = false
	select {
	case conn.T2aChan <- "unexpected_close":
	default:
	}
	f.sendPacket(pkt, false)
}

func (f *FakeTcpInjector) onInboundPacket(pkt *godivert.Packet, conn *FakeInjectiveConnection) {
	raw := pkt.Raw

	if conn.SynSeq == -1 {
		f.onUnexpectedPacket(pkt, conn, "unexpected inbound packet, no syn sent!")
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.ACK && flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		if conn.SynAckSeq != -1 && conn.SynAckSeq != int64(seqNum) {
			f.onUnexpectedPacket(pkt, conn,
				fmt.Sprintf("unexpected inbound syn-ack, seq change! %d %d", seqNum, conn.SynAckSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if ackNum != expectedAck {
			f.onUnexpectedPacket(pkt, conn,
				fmt.Sprintf("unexpected inbound syn-ack, ack not matched! %d %d", ackNum, conn.SynSeq))
			return
		}
		conn.SynAckSeq = int64(seqNum)
		f.sendPacket(pkt, false)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 && conn.FakeSent {
		expectedSeq := uint32((uint32(conn.SynAckSeq) + 1) & 0xffffffff)
		if conn.SynAckSeq == -1 || expectedSeq != seqNum {
			f.onUnexpectedPacket(pkt, conn,
				fmt.Sprintf("unexpected inbound ack, seq not matched! %d %d", seqNum, conn.SynAckSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if ackNum != expectedAck {
			f.onUnexpectedPacket(pkt, conn,
				fmt.Sprintf("unexpected inbound ack, ack not matched! %d %d", ackNum, conn.SynSeq))
			return
		}
		conn.Monitor = false
		f.sendPacket(pkt, false)
		select {
		case conn.T2aChan <- "fake_data_ack_recv":
		default:
		}
		return
	}

	f.onUnexpectedPacket(pkt, conn, "unexpected inbound packet")
}

func (f *FakeTcpInjector) onOutboundPacket(pkt *godivert.Packet, conn *FakeInjectiveConnection) {
	raw := pkt.Raw

	if conn.SchFakeSent {
		f.onUnexpectedPacket(pkt, conn, "unexpected outbound packet after fake sent!")
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.SYN && !flags.ACK && !flags.RST && !flags.FIN && payloadLen == 0 {
		if ackNum != 0 {
			f.onUnexpectedPacket(pkt, conn, "unexpected outbound syn, ack_num is not zero!")
			return
		}
		if conn.SynSeq != -1 && conn.SynSeq != int64(seqNum) {
			f.onUnexpectedPacket(pkt, conn,
				fmt.Sprintf("unexpected outbound syn, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		conn.SynSeq = int64(seqNum)
		f.sendPacket(pkt, false)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		expectedSeq := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if conn.SynSeq == -1 || expectedSeq != seqNum {
			f.onUnexpectedPacket(pkt, conn,
				fmt.Sprintf("unexpected outbound ack, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynAckSeq) + 1) & 0xffffffff)
		if conn.SynAckSeq == -1 || ackNum != expectedAck {
			f.onUnexpectedPacket(pkt, conn,
				fmt.Sprintf("unexpected outbound ack, ack not matched! %d %d", ackNum, conn.SynAckSeq))
			return
		}
		f.sendPacket(pkt, false)
		conn.SchFakeSent = true

		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)
		addrCopy := *pkt.Addr
		go f.fakeSendThread(rawCopy, &addrCopy, conn)
		return
	}

	f.onUnexpectedPacket(pkt, conn, "unexpected outbound packet")
}

func (f *FakeTcpInjector) inject(pkt *godivert.Packet) {
	raw := pkt.Raw
	if len(raw) < 40 {
		f.sendPacket(pkt, false)
		return
	}

	if packet.IPVersion(raw) != 4 {
		f.sendPacket(pkt, false)
		return
	}

	srcIP := packet.IPv4SrcAddr(raw).String()
	dstIP := packet.IPv4DstAddr(raw).String()
	srcPort := packet.TCPSrcPort(raw)
	dstPort := packet.TCPDstPort(raw)

	dir := pkt.Direction()

	if dir == godivert.WinDivertDirectionInbound {
		cID := connection.ConnID{SrcIP: dstIP, SrcPort: dstPort, DstIP: srcIP, DstPort: srcPort}
		val, ok := f.Connections.Load(cID)
		if !ok {
			f.sendPacket(pkt, false)
			return
		}
		conn := val.(*FakeInjectiveConnection)
		conn.Mu.Lock()
		defer conn.Mu.Unlock()
		if !conn.Monitor {
			f.sendPacket(pkt, false)
			return
		}
		f.onInboundPacket(pkt, conn)

	} else if dir == godivert.WinDivertDirectionOutbound {
		cID := connection.ConnID{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}
		val, ok := f.Connections.Load(cID)
		if !ok {
			f.sendPacket(pkt, false)
			return
		}
		conn := val.(*FakeInjectiveConnection)
		conn.Mu.Lock()
		defer conn.Mu.Unlock()
		if !conn.Monitor {
			f.sendPacket(pkt, false)
			return
		}
		f.onOutboundPacket(pkt, conn)

	} else {
		log.Printf("impossible WinDivert packet direction: %v", dir)
		f.sendPacket(pkt, false)
	}
}
