package stun

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Nonce is the Nonce attribute for STUN packets, it adheres to RFC2617 as per
// requirements
type Nonce struct {
	token string // Nonce Token generated as a string
}

// This generates a nonce as a token and stuff
func GenerateNonce() Nonce {
	// gets currTime and peppers it
	currTime := time.Now().String() + "foobar1234barfoo"
	// I picked md5 to make it harder to surpass the MD5 threshold with the messages
	// since it is a college Proof-Of-Concept application I figured I could get away with it :)
	// Especially considering that this is not exactly going to be the most secure implementation
	// in the world
	h := md5.New()
	h.Write([]byte(currTime))
	tempToken := fmt.Sprintf("%x", h.Sum(nil))
	return Nonce{token: tempToken}
}

// String returns the nonce as a string
func (a Nonce) String() string {
	return a.token
}

// AttributeType specifies the STUN attribute type
func (Nonce) AttributeType() StunAttributeType {
	return NONCE
}

// ParseStunAttr reads in a byte array and creates a stun attribute
func (a* Nonce) ParseStunAttr(input []byte) (uint16, error) {
	if len(input) < 4 {
		return 0, errors.New("Stun attribute too short")
	}
	if input[1] != 0x15 {
		return 0, errors.New("Not a nonce")
	}
	nonceLen := binary.BigEndian.Uint16(input[2:])

	if nonceLen == 0 || int(nonceLen+4) > len(input) {
		return 0, errors.New("Invalid nonce length")
	}
	a.token = string(input[4 : nonceLen+4])
	return (nonceLen + 4), nil
}

// WriteAsStunAttr outputs the nonce as a STUN byte array
func (a Nonce) WriteAsStunAttr() []byte {
	output := []byte{
		0x00, 0x15, 0x00, 0x20,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	for i := range a.token {
		output[4+i] = a.token[i]
	}

	return output
}
