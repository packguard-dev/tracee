package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const (
	nullHeaderLen = 4
	afINET        = 2
	afINET6       = 10
)

// FlowRecord is one external-facing indicator extracted from a packet.
type FlowRecord struct {
	Timestamp time.Time
	IP        string
	Port      int32
	Protocol  string
	Domain    string
}

// ParseFile reads a pcap/pcapng file and returns external flow records.
func ParseFile(path string, exclude []netip.Prefix) ([]FlowRecord, error) {
	reader, err := openPacketReader(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	linkType := reader.LinkType()
	flows := make([]FlowRecord, 0, 256)

	for {
		data, ci, readErr := reader.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read packet: %w", readErr)
		}

		for _, flow := range decodePacket(data, ci.Timestamp, linkType, exclude) {
			flows = append(flows, flow)
		}
	}

	return flows, nil
}

func decodePacket(data []byte, timestamp time.Time, linkType layers.LinkType, exclude []netip.Prefix) []FlowRecord {
	payload, firstLayer := preparePayload(data, linkType)
	if len(payload) == 0 {
		return nil
	}

	packet := decodeIPPacket(payload, firstLayer)
	if packet.Layer(layers.LayerTypeIPv4) == nil && packet.Layer(layers.LayerTypeIPv6) == nil {
		return nil
	}

	var srcIP, dstIP netip.Addr
	switch ipLayer := packet.Layer(layers.LayerTypeIPv4).(type) {
	case *layers.IPv4:
		srcIP, _ = netip.AddrFromSlice(ipLayer.SrcIP)
		dstIP, _ = netip.AddrFromSlice(ipLayer.DstIP)
	case nil:
		if ipLayer6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
			srcIP, _ = netip.AddrFromSlice(ipLayer6.SrcIP)
			dstIP, _ = netip.AddrFromSlice(ipLayer6.DstIP)
		}
	}

	if !srcIP.IsValid() || !dstIP.IsValid() {
		return nil
	}

	srcInternal := IsInternalIP(srcIP, exclude)
	dstInternal := IsInternalIP(dstIP, exclude)

	var externalIP netip.Addr
	var externalPort int32
	var direction string

	switch {
	case srcInternal && !dstInternal:
		externalIP = dstIP
		direction = "dst"
	case !srcInternal && dstInternal:
		externalIP = srcIP
		direction = "src"
	default:
		return nil
	}

	protocol, srcPort, dstPort, domains := transportInfo(packet)
	if direction == "dst" {
		externalPort = dstPort
	} else {
		externalPort = srcPort
	}

	out := make([]FlowRecord, 0, 1+len(domains))
	base := FlowRecord{
		Timestamp: timestamp,
		IP:        externalIP.String(),
		Port:      externalPort,
		Protocol:  protocol,
	}
	out = append(out, base)

	for _, domain := range domains {
		if domain == "" {
			continue
		}
		record := base
		record.Protocol = "DNS"
		record.Domain = domain
		out = append(out, record)
	}

	return out
}

func preparePayload(data []byte, linkType layers.LinkType) ([]byte, gopacket.LayerType) {
	switch linkType {
	case layers.LinkTypeNull:
		stripped := stripNullHeader(data)
		if len(stripped) == 0 {
			return nil, gopacket.LayerTypeZero
		}
		return stripped, layers.LayerTypeIPv4
	default:
		layerType := linkType.LayerType()
		if layerType == gopacket.LayerTypeZero || layerType == gopacket.LayerTypeDecodeFailure {
			layerType = layers.LayerTypeEthernet
		}
		return data, layerType
	}
}

func decodeIPPacket(payload []byte, firstLayer gopacket.LayerType) gopacket.Packet {
	packet := gopacket.NewPacket(payload, firstLayer, gopacket.Default)
	if firstLayer != layers.LayerTypeIPv4 {
		return packet
	}
	if packet.Layer(layers.LayerTypeIPv4) == nil && packet.Layer(layers.LayerTypeIPv6) == nil {
		return gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default)
	}
	return packet
}

func stripNullHeader(data []byte) []byte {
	if len(data) <= nullHeaderLen {
		return nil
	}
	family := binary.LittleEndian.Uint32(data[:nullHeaderLen])
	switch family {
	case afINET, afINET6:
		return data[nullHeaderLen:]
	default:
		return nil
	}
}

func transportInfo(packet gopacket.Packet) (protocol string, srcPort, dstPort int32, domains []string) {
	switch tcp := packet.Layer(layers.LayerTypeTCP).(type) {
	case *layers.TCP:
		protocol = "TCP"
		srcPort = int32(tcp.SrcPort)
		dstPort = int32(tcp.DstPort)
	case nil:
		if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
			protocol = "UDP"
			srcPort = int32(udp.SrcPort)
			dstPort = int32(udp.DstPort)
			if dns, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
				domains = dnsNamesFromLayer(dns)
			} else if udp.DstPort == 53 || udp.SrcPort == 53 {
				protocol = "DNS"
			}
		} else if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
			protocol = "ICMP"
		}
	}
	return protocol, srcPort, dstPort, domains
}
