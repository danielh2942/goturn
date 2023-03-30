package iptools

import (
	"fmt"
	"regexp"
	"strconv"
)

const (
	IPV4 uint8 = 0x01
	IPV6 uint8 = 0x02
)

type IpAddr interface {
	IpType() uint8               // Get the IP Address type
	XorAddress([4]uint32) IpAddr // Create the XorMappedAddress
	WriteAsStunAttr() []byte     // Output as a StunAttr
}

/*
 * This is a structure to contain IPV4 addresses and stuff
 */
type Ipv4 struct {
	xor  bool   // Is it an XORed Address
	addr uint32 // the addr stored as a uint32
	port uint16 // the port stored as a uint16
}

// Specifies the IP Type for the address
func (Ipv4) IpType() uint8 {
	return IPV4
}

// This performs the XOR operation defined in rfc5389
func (a Ipv4) XorAddress(val [4]uint32) IpAddr {
	if a.xor {
		return a
	}
	XordAddr := a.addr ^ val[0]
	XordPort := a.port ^ uint16(val[0]>>16)
	return Ipv4{xor: true, addr: XordAddr, port: XordPort}
}

// This outputs it as a stun attribute for the return packet
func (a Ipv4) WriteAsStunAttr() []byte {
	dataFrame := []byte{
		0x00, 0x00, 0x00, 0x08,
		0x00, IPV4, byte(a.port >> 8), byte(a.port & 0x00FF),
		byte(a.addr >> 24), byte((a.addr >> 16) & 0xFF), byte((a.addr >> 8) & 0xFF), byte(a.addr & 0x00FF),
	}
	if a.xor {
		dataFrame[1] = 0x01
	} else {
		dataFrame[1] = 0x20
	}
	return dataFrame
}

func (a Ipv4) String() string {
	var output string = ""
	if (a.xor) {
		output = "Xor Mapped Address: "
	}
	return output + fmt.Sprintf("%d.%d.%d.%d:%d",
		a.addr>>24, (a.addr>>16)&0xFF, (a.addr>>8)&0xFF, a.addr&0xFF, a.port,
	)
}

func ParseIpAddrString(addr string) IpAddr {
	// So far this only has IPV4 Support
	// XOR-MAPPED address, first we get the IP Address
	// Valid IPv4 regex lol
	discrim := regexp.MustCompile(
		`^([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]):([0-9]{1,4}|[0-5][0-9]{1,4}|6[0-4][0-9]{3}|655[0-2][0-9]|6553[0-5])$`,
	)
	matches := discrim.FindStringSubmatch(addr)
	// 1 . 2 . 3 . 4 : 5
	var addruint uint32 = 0
	val, _ := strconv.Atoi(matches[1])
	addruint ^= uint32(val) << 24
	val, _ = strconv.Atoi(matches[2])
	addruint ^= uint32(val) << 16
	val, _ = strconv.Atoi(matches[3])
	addruint ^= uint32(val) << 8
	val, _ = strconv.Atoi(matches[4])
	addruint ^= uint32(val)
	val, _ = strconv.Atoi(matches[5])
	port := uint16(val)
	return Ipv4{xor: false, addr: addruint, port: port}
}
