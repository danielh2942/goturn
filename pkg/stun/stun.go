package stun

type StunAttributeType uint16

const (
	UNKNOWN            StunAttributeType = 0xFFFF
	MAPPED_ADDRESS     StunAttributeType = 0x0001
	USERNAME           StunAttributeType = 0x0006
	MESSAGE_INTEGRITY  StunAttributeType = 0x0008
	ERROR_CODE         StunAttributeType = 0x0009
	UNKNOWN_ATTRIBUTES StunAttributeType = 0x000A
	REALM              StunAttributeType = 0x0014
	NONCE              StunAttributeType = 0x0015
	XOR_MAPPED_ADDRESS StunAttributeType = 0x0020
)

func (s StunAttributeType) String() string {
	switch s {
	case MAPPED_ADDRESS:
		return "MAPPED-ADDRESS"
	case USERNAME:
		return "USERNAME"
	case MESSAGE_INTEGRITY:
		return "MESSAGE_INTEGRITY"
	case ERROR_CODE:
		return "ERROR-CODE"
	case UNKNOWN_ATTRIBUTES:
		return "UNKNOWN-ATTRIBUTES"
	case REALM:
		return "REALM"
	case NONCE:
		return "NONCE"
	case XOR_MAPPED_ADDRESS:
		return "XOR-MAPPED-ADDRESS"
	}
	return "UNKNOWN"
}

func ParseStunAttrType(val uint16) StunAttributeType {
	switch val {
	case 0x0001:
		return MAPPED_ADDRESS
	case 0x0006:
		return USERNAME
	case 0x0008:
		return MESSAGE_INTEGRITY
	case 0x0009:
		return ERROR_CODE
	case 0x000A:
		return UNKNOWN_ATTRIBUTES
	case 0x0014:
		return REALM
	case 0x0015:
		return NONCE
	case 0x0020:
		return XOR_MAPPED_ADDRESS
	default:
		return UNKNOWN
	}
}

// StunAttribute is a generalized form for stun attributes and stuff
// It is done to make it easier to parse and understand STUN attributes
type StunAttribute interface {
	AttributeType() StunAttributeType
	ParseStunAttr([]byte) (StunAttribute, uint16, error) // Read in STUN Attribute
	WriteAsStunAttr() []byte                             // Output as attribute for stun packet
}
