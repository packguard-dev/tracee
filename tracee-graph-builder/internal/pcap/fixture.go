package pcap

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// BuildTestFixture returns a minimal tcpdump-style pcap-ng capture (Ethernet link type).
func BuildTestFixture() ([]byte, error) {
	var buf bytes.Buffer
	writer, err := pcapgo.NewNgWriterInterface(&buf, pcapgo.NgInterface{
		Name:       "eth0",
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: 65535,
	}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		return nil, err
	}

	base := time.Date(2026, 6, 7, 8, 29, 3, 0, time.UTC)
	internal := net.ParseIP("10.68.0.5")
	external := net.ParseIP("185.199.108.133")

	if err := writeEthernetTCPPacket(writer, base, internal, external, 40000, 443); err != nil {
		return nil, err
	}
	if err := writeEthernetDNSPacket(writer, base.Add(100*time.Millisecond), internal, external, "raw.githubusercontent.com."); err != nil {
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeEthernetTCPPacket(w *pcapgo.NgWriter, ts time.Time, srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort) error {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		SYN:     true,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		return err
	}

	payload := buf.Bytes()
	ci := gopacket.CaptureInfo{
		Timestamp:      ts,
		CaptureLength:  len(payload),
		Length:         len(payload),
		InterfaceIndex: 0,
	}
	return w.WritePacket(ci, payload)
}

func writeEthernetDNSPacket(w *pcapgo.NgWriter, ts time.Time, srcIP, dstIP net.IP, query string) error {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	udp := &layers.UDP{
		SrcPort: 54321,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return err
	}
	dns := &layers.DNS{
		ID: 1, QR: false, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{{Name: []byte(query), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		return err
	}

	payload := buf.Bytes()
	ci := gopacket.CaptureInfo{
		Timestamp:      ts,
		CaptureLength:  len(payload),
		Length:         len(payload),
		InterfaceIndex: 0,
	}
	return w.WritePacket(ci, payload)
}

func prependNullHeader(payload []byte) []byte {
	out := make([]byte, nullHeaderLen+len(payload))
	binary.LittleEndian.PutUint32(out[:nullHeaderLen], afINET)
	copy(out[nullHeaderLen:], payload)
	return out
}
