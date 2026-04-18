package injection

import (
	"net"
	"sni-spoofing-go/connection"
)

type ConnID = connection.ConnID

type FakeInjectiveConnection struct {
	*connection.MonitorConnection

	FakeData     []byte
	SchFakeSent  bool
	FakeSent     bool
	T2aChan      chan string
	BypassMethod string
	PeerSock     net.Conn
	FakeRepeat   int
}

func NewFakeInjectiveConnection(
	sock net.Conn, srcIP, dstIP string, srcPort, dstPort uint16,
	fakeData []byte, bypassMethod string, peerSock net.Conn,
	fakeRepeat int,
) *FakeInjectiveConnection {
	if fakeRepeat < 1 {
		fakeRepeat = 1
	}
	return &FakeInjectiveConnection{
		MonitorConnection: connection.NewMonitorConnection(sock, srcIP, dstIP, srcPort, dstPort),
		FakeData:          fakeData,
		SchFakeSent:       false,
		FakeSent:          false,
		T2aChan:           make(chan string, 1),
		BypassMethod:      bypassMethod,
		PeerSock:          peerSock,
		FakeRepeat:        fakeRepeat,
	}
}

func (conn *FakeInjectiveConnection) AbortUnexpectedCloseLocked() {
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
}
