package stun

import (
	"testing"
)

func TestGenerateNonce(t *testing.T) {
	nonce := GenerateNonce()
	if len(nonce.token) == 0 {
		t.Fatal("Failed to generate nonce token")
	}
	t.Log("Nonce Token Value:", nonce.token)
}

func TestAttributeType(t *testing.T) {
	nonce := Nonce{}
	if nonce.AttributeType() != NONCE {
		t.Fatal("Returned incorrect type")
	}
}

func TestParseStunAttr(t *testing.T) {
	// Test passing an empty nonce
	nonce := Nonce{}
	_, err := nonce.ParseStunAttr([]byte{})
	if err == nil {
		t.Fatal("Expected Failure here, got successful parse")
	}

	// Test passing invalid data
	_, err = nonce.ParseStunAttr([]byte{0x00, 0xFF, 0x00, 0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("Expected not a nonce error, got nothing.")
	}

	// Test invalid nonceLen
	_, err = nonce.ParseStunAttr([]byte{
		0x00, 0x15, 0xEF, 0xFF,
		0x00, 0x00, 0x00, 0x00,
	})
	if err == nil {
		t.Fatal("Expected invalid nonce length error, got nothing.")
	}

	// Test valid Nonce
	_, err = nonce.ParseStunAttr([]byte{
		0x00, 0x15, 0x00, 0x04,
		0x74, 0x65, 0x73, 0x74,
	})
	if err != nil {
		t.Fatal("Expected success, got error:", err)
	}

	if nonce.String() != "test" {
		t.Fatal("Incorrectly parsed nonce")
	}
}

func TestWriteAsStunAttr(t *testing.T) {
	nonce := GenerateNonce()
	outp := nonce.WriteAsStunAttr()
	if len(outp) != 36 {
		t.Fatal("Expected length 36, got",len(outp))
	}

	nonce2 := Nonce{}
	nonce2.ParseStunAttr(outp)
	if nonce.String() != nonce2.String() {
		t.Fatal("Round trip parsing failed.")
	}
}
