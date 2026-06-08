package pcap

import (
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
	Close() error
}

type ngPacketReader struct {
	r        *pcapgo.NgReader
	linkType layers.LinkType
}

func (r *ngPacketReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return r.r.ReadPacketData()
}

func (r *ngPacketReader) LinkType() layers.LinkType {
	return r.linkType
}

func (r *ngPacketReader) Close() error {
	return nil
}

type classicPacketReader struct {
	r *pcapgo.Reader
}

func (r *classicPacketReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return r.r.ReadPacketData()
}

func (r *classicPacketReader) LinkType() layers.LinkType {
	return r.r.LinkType()
}

func (r *classicPacketReader) Close() error {
	return nil
}

func openPacketReader(path string) (packetReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	ngReader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
	if err == nil {
		linkType := layers.LinkTypeEthernet
		iface, ifaceErr := ngReader.Interface(0)
		if ifaceErr == nil {
			linkType = iface.LinkType
		}
		return &ngPacketReader{r: ngReader, linkType: linkType}, nil
	}

	if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
		file.Close()
		return nil, fmt.Errorf("rewind pcap file: %w", seekErr)
	}

	classicReader, err := pcapgo.NewReader(file)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	return &classicPacketReader{r: classicReader}, nil
}
