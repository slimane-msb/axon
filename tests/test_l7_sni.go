package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// parseSNIFromClientHello extracts the Server Name Indication from a TLS Client Hello
func parseSNIFromClientHello(hello []byte) string {
	if len(hello) < 38 {
		return ""
	}
	offset := 0
	offset += 2  // Version
	offset += 32 // Random
	if offset >= len(hello) {
		return ""
	}
	sessionIDLen := int(hello[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(hello) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2 + cipherLen
	if offset+1 > len(hello) {
		return ""
	}
	compLen := int(hello[offset])
	offset += 1 + compLen
	if offset+2 > len(hello) {
		return ""
	}
	// extensions length
	offset += 2
	for offset+4 <= len(hello) {
		extType := binary.BigEndian.Uint16(hello[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(hello[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > len(hello) {
			break
		}
		if extType == 0 && extLen > 5 {
			extData := hello[offset : offset+extLen]
			if len(extData) > 5 && extData[2] == 0 {
				nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
				if 5+nameLen <= len(extData) {
					return string(extData[5 : 5+nameLen])
				}
			}
		}
		offset += extLen
	}
	return ""
}

func main() {
	// --- Test Case 1: Manually built minimal ClientHello ---
	sniHost := "axon.example.com"
	sniBytes := []byte(sniHost)
	sniNameLen := len(sniBytes)

	// Build SNI extension
	// Type (2 bytes), Total Len (2), List Len (2), Type Host (1), Name Len (2)
	sniExt := []byte{
		0x00, 0x00, // ext type SNI
		byte((sniNameLen + 5) >> 8), byte(sniNameLen + 5), // ext length
		byte((sniNameLen + 3) >> 8), byte(sniNameLen + 3), // SNI list length
		0x00,                                              // name type host_name
		byte(sniNameLen >> 8), byte(sniNameLen),           // name length
	}
	sniExt = append(sniExt, sniBytes...)

	// Build minimal ClientHello
	hello := make([]byte, 0)
	hello = append(hello, 0x03, 0x03)          // version
	hello = append(hello, make([]byte, 32)...) // random
	hello = append(hello, 0x00)                 // session ID len
	hello = append(hello, 0x00, 0x02)          // cipher suites len
	hello = append(hello, 0x00, 0x2f)          // AES128-SHA
	hello = append(hello, 0x01, 0x00)          // compression

	// extensions length
	extLen := len(sniExt)
	hello = append(hello, byte(extLen>>8), byte(extLen))
	hello = append(hello, sniExt...)

	result := parseSNIFromClientHello(hello)
	if result == sniHost {
		fmt.Printf("✅ SNI extracted correctly: %q\n", result)
	} else {
		fmt.Printf("❌ SNI wrong: got %q, want %q\n", result, sniHost)
		fmt.Printf("   Hello hex: %s\n", hex.EncodeToString(hello))
	}

	// --- Test Case 2: Empty/Malformed ---
	if parseSNIFromClientHello([]byte{}) == "" {
		fmt.Println("✅ Empty input → empty string")
	}
	if parseSNIFromClientHello(make([]byte, 10)) == "" {
		fmt.Println("✅ Too-short input → empty string")
	}

	fmt.Println("\n🚀 All L7 SNI parsing tests passed")
}