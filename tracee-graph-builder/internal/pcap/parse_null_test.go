package pcap

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestParseFileSupportsNullLinkType(t *testing.T) {
	t.Parallel()

	data, err := buildNullLinkFixture()
	if err != nil {
		t.Fatalf("buildNullLinkFixture: %v", err)
	}
	path := writeTempPcap(t, data)

	exclude, err := DefaultExcludeCIDRs()
	if err != nil {
		t.Fatalf("DefaultExcludeCIDRs: %v", err)
	}

	flows, err := ParseFile(path, exclude)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(flows) == 0 {
		t.Fatal("expected flows from NULL link type pcap")
	}
}

func buildNullLinkFixture() ([]byte, error) {
	var buf bytes.Buffer
	writer, err := pcapgo.NewNgWriterInterface(&buf, pcapgo.NgInterface{
		Name:       "null0",
		LinkType:   layers.LinkTypeNull,
		SnapLength: 65535,
	}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		return nil, err
	}

	base := time.Date(2026, 6, 7, 8, 29, 3, 0, time.UTC)
	internal := net.ParseIP("10.68.0.5")
	external := net.ParseIP("185.199.108.133")
	if err := writeNullTCPPacket(writer, base, internal, external, 40000, 443); err != nil {
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeNullTCPPacket(w *pcapgo.NgWriter, ts time.Time, srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort) error {
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
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		return err
	}

	payload := prependNullHeader(buf.Bytes())
	ci := gopacket.CaptureInfo{
		Timestamp:      ts,
		CaptureLength:  len(payload),
		Length:         len(payload),
		InterfaceIndex: 0,
	}
	return w.WritePacket(ci, payload)
}
