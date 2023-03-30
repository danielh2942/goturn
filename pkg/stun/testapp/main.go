package main

import (
	"encoding/binary"
	"log"
	"net"
	
	"github.com/danielh2942/goturn/pkg/iptools"
)


// NB: Network protocol is BIG-ENDIAN
func main() {
	// listen on port 3478 for STUN protocol
	udpServer, err := net.ListenPacket("udp", ":3478")
	if err != nil {
		log.Fatal(err)
	}
	defer udpServer.Close()

	for {
		buf := make([]byte, 65536) // MAX possible IP packet size + 1 (This will never be full)
		pkt_size, addr, err := udpServer.ReadFrom(buf)
		if err != nil {
			log.Println("Error", err)
			continue
		}

		if pkt_size < 20 {
			log.Println("STUN Packet too small, ignoring")
			continue
		}
		log.Println("Packet Recieved Size:", pkt_size, "From Address", addr)

		messageType := binary.BigEndian.Uint16(buf)
		messageSize := binary.BigEndian.Uint16(buf[2:])
		magicCookie := binary.BigEndian.Uint32(buf[4:])

		if magicCookie != 0x2112A442 {
			log.Println("Invalid cookie passed")
			continue
		}
		switch messageType {
		case 1:
			if messageSize > 0 {
				log.Println("invalid size")
				break
			}
			log.Println("Binding Request")
			log.Println("IP Address", addr)
			addruint := iptools.ParseIpAddrString(addr.String())
			log.Println("Address after parse",addruint)
		case 2:
			log.Println("Shared Secret Request")
		default:
			log.Println("Unknown")
		}
	}
}
