package stun

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

type Nonce struct {
	token string // Nonce Token generated as a string
}

// This generates a nonce as a token and stuff
func GenerateNonce() Nonce {
	// gets currTime and peppers it
	currTime := time.Now().String() + "foobar1234barfoo"
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
func (Nonce) ParseStunAttr(input []byte) (StunAttribute, uint16, error) {
	if len(input) < 4 {
		return Nonce{}, 0, errors.New("Stun attribute too short")
	}
	if input[1] != 0x15 {
		return Nonce{}, 0, errors.New("Not a nonce")
	}
	nonceLen := binary.BigEndian.Uint16(input[2:])

	if nonceLen == 0 || int(nonceLen+4) > len(input) {
		return Nonce{}, 0, errors.New("Invalid nonce length")
	}
	tokenStr := string(input[4 : nonceLen+4])
	return Nonce{token: tokenStr}, (nonceLen + 4), nil
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
		0x00, 0x00, 0x00, 0x00,
	}

	for i := range a.token {
		output[4+i] = a.token[i]
	}

	return output
}
